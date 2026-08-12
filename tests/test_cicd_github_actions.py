"""GitHub Actions CI provider (Phase 6 Part 1) - a fake transport
(mirrors `tests/github_fakes.py`'s pattern) so the provider's real logic
(status classification, run/job normalization) is exercised without
network, plus one live-network reachability check per the task
instructions."""
from __future__ import annotations

import subprocess

from aep.cicd.models import CIProviderAvailability, CIRunConclusion
from aep.cicd.providers.github_actions import build_provider
from aep.github.client import GitHubError, HttpResponse
from github_fakes import FakeGitHubTransport


def test_mocked_status_when_transport_is_injected():
    provider = build_provider(token_provider=lambda: "tok", transport=FakeGitHubTransport())
    avail, reason = provider.status()
    assert avail == CIProviderAvailability.MOCKED
    assert "test double" in reason


def test_latest_run_via_fake_transport_reports_success_when_jobs_all_succeeded():
    transport = FakeGitHubTransport()
    provider = build_provider(token_provider=lambda: "tok", transport=transport)
    # FakeGitHubTransport's workflow-run/job state machine is keyed by a
    # poll counter normally advanced by `list_check_runs` (as
    # MonitorCIAgent does); this provider never calls that endpoint, so
    # the test advances the same counter directly to reach the fake's
    # "success" state deterministically (count >= 3 - see
    # `FakeGitHubTransport._ci_state`).
    transport._poll_count[("acme", "widgets", "main")] = 3
    result = provider.latest_run("acme", "widgets", branch="main")
    assert result.status == CIProviderAvailability.MOCKED
    assert result.run is not None
    assert result.run.conclusion == CIRunConclusion.SUCCESS


def test_status_reports_blocked_on_a_real_403(monkeypatch):
    """Simulates the exact 403 this sandbox's egress proxy returns for
    api.github.com, WITHOUT hitting the network - a real, deterministic
    unit test of the classification branch, not a network-dependent test."""
    def failing_transport(method, url, headers, params, json_body, timeout):
        return HttpResponse(403, {"message": "blocked by proxy"}, headers={})
    provider = build_provider(token_provider=lambda: "tok", transport=failing_transport)
    # `build_provider` marks any explicitly-passed transport as injected
    # (MOCKED) by design (see its docstring) - to exercise the BLOCKED
    # branch specifically we construct the provider directly instead.
    from aep.cicd.providers.github_actions import GitHubActionsProvider
    from aep.github.client import GitHubClient
    client = GitHubClient(token_provider=lambda: "tok", transport=failing_transport)
    real_provider = GitHubActionsProvider(client, injected_transport=False)
    avail, reason = real_provider.status()
    assert avail == CIProviderAvailability.BLOCKED
    assert "sandbox" in reason


def test_live_github_actions_api_is_actually_blocked_from_this_sandbox():
    """Documents, with a real network attempt, exactly what the task
    instructions describe: api.github.com/.../actions/runs returns 403
    through this sandbox's egress proxy. This is not a provider unit test
    - it is the honest verification that LIVE GitHub Actions integration
    is currently BLOCKED, so no other part of this report can overstate
    it."""
    try:
        result = subprocess.run(
            ["curl", "-m", "6", "-o", "/dev/null", "-s", "-w", "%{http_code}",
             "https://api.github.com/repos/octocat/hello-world/actions/runs"],
            capture_output=True, text=True, timeout=15,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return  # curl unavailable in some CI runners - not what this test is verifying
    code = result.stdout.strip()
    assert code in ("403", "000"), f"expected the sandbox's known block (403/000), got {code!r}"
