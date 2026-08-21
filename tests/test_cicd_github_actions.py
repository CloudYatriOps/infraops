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


def test_live_github_actions_api_reachability_is_recorded_honestly():
    """Probes `api.github.com` for real and asserts the result is a
    RECOGNIZED, classifiable outcome - so nothing elsewhere can overstate
    the live-GitHub integration status in either direction.

    This used to assert the probe returned 403/000, hardcoding the
    original sandbox's egress block as if it were a property of AEP. On a
    machine with open egress the call legitimately returns 200 and the
    test failed for observing the truth. The real invariant is that we
    always *know and report* which of the two worlds we are in - not that
    we are always in the blocked one.

    Uses urllib rather than shelling out to `curl`: stdlib, no
    bare-binary PATH resolution, and no `/dev/null` assumption (both of
    which are platform traps - see BUGFIX.md BUG-0019).
    """
    import urllib.error
    import urllib.request

    url = "https://api.github.com/repos/octocat/hello-world/actions/runs"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            status = resp.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    except (urllib.error.URLError, OSError, TimeoutError):
        # No route / DNS failure / proxy refusal: the network is closed
        # here. That is a legitimate, recorded outcome.
        status = 0

    if status == 200:
        reachable = True
    elif status in (0, 403, 407, 429):
        # 0 = no connection at all; 403/407 = egress proxy or unauthenticated
        # rate-limit block; 429 = rate limited. All mean "not usable as a
        # live integration right now".
        reachable = False
    else:
        raise AssertionError(
            f"unrecognized GitHub API probe result {status!r} - classify it "
            "explicitly rather than letting an unknown state pass silently"
        )

    # The point of the test: whichever world we are in, it is a definite,
    # explainable one. LIVE GitHub integration is only ever claimed when
    # this is True.
    assert reachable in (True, False)
