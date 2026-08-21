"""GitHub-integration path for dependency remediation.

MOCKED EXTERNAL GITHUB TRANSPORT (per Part I: this must be labeled
explicitly, never presented as live GitHub verification) - identical
pattern to Phase 2's tests/test_github_ci_loop.py: a real local git repo +
a real bare "remote" repo + the real GitHubClient/GitHubTool/orchestrator,
with only the GitHub REST API's HTTP responses faked
(tests/github_fakes.py). The dependency scan/remediate/rescan steps
themselves stay real (see test_dependency_e2e_real.py for that path in
isolation); this file's job is to prove the *hand-off* into the existing
push -> PR -> CI-loop machinery, unmodified from Phase 2, plus the
CI-failure-after-dependency-upgrade and crash/resume scenarios Part H
calls for.

FakeGitHubTransport's check-runs state machine (see github_fakes.py
`_ci_state`) is deterministic by poll count per branch: pending, then
FAILING, then success - exactly the sequence Phase 2's own CI-loop test
relies on. Every dependency-remediation PR here therefore goes through one
real automatic CI failure before succeeding, which is what lets this file
exercise the "CI failure after dependency upgrade" scenario without
hand-rolling any extra fake-transport state.
"""
from __future__ import annotations

import shutil
import subprocess

import pytest

from aep.bootstrap import build_orchestrator
from aep.dependency.planner import plan_dependency_scan
from aep.dependency.scanners import pip_audit_scanner
from aep.models import ProjectConfig, TaskStatus
from aep.secrets import StaticSecretManager

from github_fakes import FakeGitHubTransport


def _probe(args, cwd=None, timeout=10):
    # Resolve the binary the SAME way the real scan path does. A bare name
    # handed to subprocess.run is resolved by the OS against the whole
    # PATH, which on this kind of machine can pick a DIFFERENT (working)
    # pip-audit than the one the scan itself ends up using - so the skip
    # guard below said "available" while the actual scan returned zero
    # findings, turning an honest skip into a confusing failure.
    resolved = shutil.which(args[0]) or args[0]
    try:
        proc = subprocess.run([resolved] + args[1:], cwd=cwd, capture_output=True,
                               text=True, timeout=timeout)
    except OSError:
        return {"ok": False}
    return {"ok": proc.returncode == 0}


pytestmark = pytest.mark.skipif(
    not pip_audit_scanner.is_available(_probe),
    reason="pip-audit not installed in this environment",
)


def _init_repo(path) -> None:
    subprocess.run(["git", "init", "-q", "-b", "main", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "aep@example.com"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "AEP Bot"], check=True)


def _setup(tmp_path, policy_path, project_id="depgh"):
    demo_repo = tmp_path / "dep_demo_project"
    demo_repo.mkdir()
    _init_repo(demo_repo)
    subprocess.run(["python3", "-m", "pip", "install", "--break-system-packages", "--quiet",
                     "urllib3==1.26.4"], check=True)
    (demo_repo / "requirements.txt").write_text("urllib3==1.26.4\n")
    # `app.py`/`test_app.py` deliberately don't import urllib3: this
    # sandbox's `pytest` binary is an isolated tool install separate from
    # `python3`'s own site-packages (confirmed during Phase 3 development -
    # `python3 -m pip install X` doesn't make X importable under bare
    # `pytest`), so the *generic*, Phase-2-unmodified diagnose/fix loop's
    # own run_tests step (which uses bare `pytest`, not
    # `python3 -m pytest`) would otherwise fail on an environment quirk
    # unrelated to what this test is verifying. requirements.txt still
    # pins the real, real-CVE-affected urllib3==1.26.4 - exactly like a
    # real repo where a scanned/remediated dependency isn't necessarily
    # imported by every fast unit test.
    (demo_repo / "app.py").write_text("def add(a, b):\n    return a + b\n")
    (demo_repo / "test_app.py").write_text(
        "from app import add\n\ndef test_add():\n    assert add(2, 3) == 5\n")
    (demo_repo / ".gitignore").write_text("__pycache__/\n*.pyc\n")
    subprocess.run(["git", "-C", str(demo_repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(demo_repo), "commit", "-q", "-m", "initial commit"], check=True)

    bare_remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(bare_remote)], check=True)
    subprocess.run(["git", "-C", str(demo_repo), "push", str(bare_remote), "main"],
                    check=True, capture_output=True)

    transport = FakeGitHubTransport()
    project = ProjectConfig(id=project_id, name=project_id, repo_path=str(demo_repo),
                             policy_path=policy_path)
    return demo_repo, bare_remote, transport, project


def _generic_fix_responder(request) -> str:
    """Used only by the *existing, generic* CI diagnose/fix loop
    (github/planner.py's build_fix_verify_push_chain, unmodified since
    Phase 2) when it kicks in after the fake transport's scripted CI
    failure. Echoes the current file content back with one appended
    comment line, so there's always a real, non-corrupting diff to commit
    regardless of which file the generic loop points at."""
    prompt = request.user_prompt
    marker = "Current content of "
    idx = prompt.find(marker)
    if idx == -1:
        return "# aep: no-op fix\n"
    content_idx = prompt.find(":\n", idx)
    current_content = prompt[content_idx + 2:]
    return current_content.rstrip("\n") + "\n# aep: addressed CI diagnosis\n"


def _orch(tmp_path, project, transport, db_name="state.db"):
    return build_orchestrator(
        db_path=str(tmp_path / db_name), project=project,
        mock_canned={
            "diagnose_ci_failure": "add a module docstring to satisfy the lint check",
            "code_fix": _generic_fix_responder,
        },
        enable_github=True,
        github_secret_manager=StaticSecretManager({"github_token": "TEST-TOKEN-MUST-NOT-LEAK"}),
        github_transport=transport,
        sleep_fn=lambda seconds: None,
     db_backend="sqlite",)


def test_dependency_remediation_opens_a_real_pr_via_existing_workflow(tmp_path, policy_path):
    demo_repo, bare_remote, transport, project = _setup(tmp_path, policy_path, "depgh")
    orch = _orch(tmp_path, project, transport)

    plan_dependency_scan(orch, project_id="depgh", project_root=str(demo_repo),
                          owner="acme", repo="widgets", remote_url=str(bare_remote),
                          branch_name="aep/dep-fix-demo")
    orch.run_to_completion("depgh", max_iterations=400)

    all_tasks = orch.store.list_tasks("depgh")
    by_type: dict[str, list] = {}
    for t in all_tasks:
        by_type.setdefault(t.type, []).append(t)

    for expected in ("dependency_scan", "dependency_remediate", "run_tests", "dependency_rescan",
                      "push_branch", "create_pull_request", "monitor_ci"):
        assert expected in by_type, f"missing task type {expected}"
    for t in all_tasks:
        assert t.status == TaskStatus.SUCCEEDED, f"{t.type} ({t.id}) ended {t.status}: {t.evidence}"

    prs = transport._prs[("acme", "widgets")]
    assert len(prs) == 1  # never duplicated even after the diagnose/fix/push loop reruns
    assert "dependency security remediation" in prs[0]["title"]

    branch_log = subprocess.run(
        ["git", "--git-dir", str(bare_remote), "log", "--oneline", "aep/dep-fix-demo"],
        capture_output=True, text=True, check=True,
    ).stdout
    assert "security fix" in branch_log
    main_log = subprocess.run(
        ["git", "--git-dir", str(bare_remote), "log", "--oneline", "main"],
        capture_output=True, text=True, check=True,
    ).stdout
    assert "security fix" not in main_log  # never landed on the protected branch directly

    events = orch.store.query_events(project_id="depgh")
    serialized = "\n".join(e.to_json() for e in events)
    assert "TEST-TOKEN-MUST-NOT-LEAK" not in serialized


def test_ci_failure_after_dependency_upgrade_uses_existing_diagnose_fix_loop(tmp_path, policy_path):
    """FakeGitHubTransport's CI state machine always fails once before
    succeeding (see module docstring), so every dependency-remediation PR
    exercises this path - this test asserts on it explicitly rather than
    incidentally, per Part H's 'CI failure after dependency upgrade'
    requirement: the *existing* MonitorCIAgent -> DiagnoseCIFailureAgent ->
    generic code_fix chain (unmodified since Phase 2) must be what
    recovers, not a dependency-specific reimplementation."""
    demo_repo, bare_remote, transport, project = _setup(tmp_path, policy_path, "depgh2")
    orch = _orch(tmp_path, project, transport)

    plan_dependency_scan(orch, project_id="depgh2", project_root=str(demo_repo),
                          owner="acme", repo="widgets", remote_url=str(bare_remote),
                          branch_name="aep/dep-fix-demo2")
    orch.run_to_completion("depgh2", max_iterations=400)

    all_tasks = orch.store.list_tasks("depgh2")
    by_type: dict[str, list] = {}
    for t in all_tasks:
        by_type.setdefault(t.type, []).append(t)

    assert "diagnose_ci_failure" in by_type, "the fake transport's scripted CI failure should have fired"
    assert len(by_type["code_fix"]) == 1, (
        "the generic diagnose/fix loop should produce exactly one additional code_fix task - "
        "dependency remediation itself never creates a code_fix task")
    for t in all_tasks:
        assert t.status == TaskStatus.SUCCEEDED, f"{t.type} ({t.id}) ended {t.status}: {t.evidence}"

    pr_number = transport._prs[("acme", "widgets")][0]["number"]
    comments = transport._comments[("acme", "widgets", pr_number)]
    assert any("lint" in c["body"] for c in comments), "the diagnosis should have been posted to the PR"

    # The dependency upgrade itself is still intact after the generic loop
    # touched a different concern (CI lint failure) - the two mechanisms
    # didn't clobber each other.
    assert (demo_repo / "requirements.txt").read_text().strip() != "urllib3==1.26.4"


def test_dependency_remediation_survives_a_crash_mid_loop(tmp_path, policy_path):
    demo_repo, bare_remote, transport, project = _setup(tmp_path, policy_path, "depgh3")
    db_name = "shared_state.db"
    orch_a = _orch(tmp_path, project, transport, db_name=db_name)

    plan_dependency_scan(orch_a, project_id="depgh3", project_root=str(demo_repo),
                          owner="acme", repo="widgets", remote_url=str(bare_remote),
                          branch_name="aep/dep-fix-demo3")
    # Only enough iterations to get through remediate/test/rescan/push, not
    # all the way through PR/CI/diagnose.
    orch_a.run_to_completion("depgh3", max_iterations=6)
    mid_tasks = orch_a.store.list_tasks("depgh3")
    assert not all(t.status == TaskStatus.SUCCEEDED for t in mid_tasks), (
        "test setup assumption violated: graph should not be finished yet")
    del orch_a  # simulate the process dying without clean shutdown

    orch_b = _orch(tmp_path, project, transport, db_name=db_name)
    orch_b.resume("depgh3")

    final_tasks = orch_b.store.list_tasks("depgh3")
    assert all(t.status == TaskStatus.SUCCEEDED for t in final_tasks), (
        [(t.type, t.status) for t in final_tasks])
    assert (demo_repo / "requirements.txt").read_text().strip() != "urllib3==1.26.4"
