"""GitHub Actions CI provider (Phase 6 Part 1) - the one fully-implemented
CI provider.

Reuses the EXISTING `github/client.py::GitHubClient` and its
transport-injection pattern verbatim - this module adds no new HTTP
client. `GitHubClient` already exposes `list_workflow_runs`,
`get_workflow_run`, and `list_workflow_run_jobs` (used since Phase 2's
`MonitorCIAgent`/`DiagnoseCIFailureAgent`); this provider is a thin,
CI-domain-shaped wrapper around those three calls plus a real status
probe, following exactly the same MOCKED/AVAILABLE/BLOCKED labelling
`infra/cloud/aws_adapter.py` uses for AWS.

## Status labelling

This sandbox's egress proxy returns 403 for `api.github.com` (verified
during Phase 6 investigation with
`curl -m 6 https://api.github.com/repos/octocat/hello-world/actions/runs`).
`status()` performs one real, cheap, read-only call
(`get_repo(status_owner, status_repo)`) and classifies the *actual*
result:

  - `MOCKED`      when constructed with an injected transport (tests)
  - `BLOCKED`     when the real transport raises a network-shaped error
                  (this sandbox's live state)
  - `AVAILABLE`   only when the real call actually succeeds
  - `UNAVAILABLE` when no token can be resolved at all

`CIStatusResult.is_real` is True only for `AVAILABLE` - nothing downstream
can mistake a fake-transport test run for live GitHub Actions
verification, and this provider has NEVER been exercised against the real
api.github.com endpoint by this platform.
"""
from __future__ import annotations

from typing import Optional

from ...github.client import GitHubClient, GitHubError, Transport
from ..models import CIProviderAvailability, CIRun, CIRunConclusion, CIStatusResult

PROVIDER = "github_actions"

_CONCLUSION_MAP = {
    "success": CIRunConclusion.SUCCESS,
    "failure": CIRunConclusion.FAILURE,
    "timed_out": CIRunConclusion.FAILURE,
    "action_required": CIRunConclusion.FAILURE,
    "cancelled": CIRunConclusion.CANCELLED,
}


class GitHubActionsProvider:
    provider = PROVIDER

    def __init__(self, client: GitHubClient, status_owner: str = "octocat",
                 status_repo: str = "hello-world", injected_transport: bool = False):
        """`injected_transport` is set explicitly by the caller (tests pass
        True with a `FakeGitHubTransport`) rather than inferred, mirroring
        `AWSAdapter.__init__`'s `self._injected = client_factory is not None`
        pattern - there is no reliable way to introspect an arbitrary
        callable and tell "is this really `requests`", so the caller states
        it."""
        self._client = client
        self._status_owner = status_owner
        self._status_repo = status_repo
        self._injected = injected_transport

    def status(self) -> tuple:
        if self._injected:
            return (CIProviderAvailability.MOCKED,
                    "an injected transport is in use: provider logic is real, the GitHub "
                    "Actions HTTP transport is a test double. This is NOT live GitHub Actions "
                    "verification.")
        try:
            self._client.get_repo(self._status_owner, self._status_repo)
        except GitHubError as e:
            name = type(e).__name__
            status_code = getattr(e, "status_code", None)
            if status_code in (403, None) or "network error" in str(e).lower():
                return (CIProviderAvailability.BLOCKED,
                        f"the live GitHub API is not reachable from this sandbox's egress proxy "
                        f"({name}: {str(e)[:160]}). Verified during Phase 6 investigation: "
                        f"`curl api.github.com/.../actions/runs` returns 403 through the proxy.")
            return CIProviderAvailability.UNAVAILABLE, f"{name}: {str(e)[:160]}"
        return (CIProviderAvailability.AVAILABLE,
                "a real, read-only round-trip to the GitHub REST API succeeded")

    def latest_run(self, owner: str, repo: str, branch: Optional[str] = None) -> CIStatusResult:
        avail, reason = self.status()
        if avail not in (CIProviderAvailability.AVAILABLE, CIProviderAvailability.MOCKED):
            return CIStatusResult(provider=self.provider, status=avail, reason=reason)
        try:
            data = self._client.list_workflow_runs(owner, repo, branch=branch)
        except GitHubError as e:
            return CIStatusResult(provider=self.provider, status=CIProviderAvailability.BLOCKED,
                                   reason=f"list_workflow_runs failed: {e}")
        runs = data.get("workflow_runs", [])
        if not runs:
            return CIStatusResult(provider=self.provider, status=avail,
                                   reason="no workflow runs found for this branch")
        latest = runs[0]
        run_id = latest["id"]
        try:
            jobs_data = self._client.list_workflow_run_jobs(owner, repo, run_id)
        except GitHubError:
            jobs_data = {"jobs": []}
        jobs = jobs_data.get("jobs", [])
        if latest.get("status") != "completed":
            conclusion = CIRunConclusion.PENDING
        elif latest.get("conclusion") is not None:
            conclusion = _CONCLUSION_MAP.get(latest.get("conclusion"), CIRunConclusion.UNKNOWN)
        elif jobs:
            # Some real-shaped API responses (and this platform's own test
            # fake) mark the run "completed" without echoing `conclusion`
            # at the run level - fall back to the per-job conclusions,
            # which both the real API and the fake always populate.
            job_conclusions = {j.get("conclusion") for j in jobs}
            if job_conclusions == {"success"}:
                conclusion = CIRunConclusion.SUCCESS
            elif "failure" in job_conclusions:
                conclusion = CIRunConclusion.FAILURE
            elif None in job_conclusions:
                conclusion = CIRunConclusion.PENDING
            else:
                conclusion = CIRunConclusion.UNKNOWN
        else:
            conclusion = CIRunConclusion.UNKNOWN
        run = CIRun(provider=self.provider, run_id=run_id, branch=branch or latest.get("head_branch", ""),
                    conclusion=conclusion, jobs=jobs)
        return CIStatusResult(provider=self.provider, status=avail, reason=reason, run=run)

    def list_jobs(self, owner: str, repo: str, run_id: int) -> list[dict]:
        try:
            return self._client.list_workflow_run_jobs(owner, repo, run_id).get("jobs", [])
        except GitHubError:
            return []


def build_provider(token_provider, transport: Optional[Transport] = None,
                    base_url: str = "https://api.github.com",
                    injected_transport: bool = False) -> GitHubActionsProvider:
    client = GitHubClient(token_provider=token_provider, base_url=base_url, transport=transport)
    return GitHubActionsProvider(client, injected_transport=injected_transport or transport is not None)
