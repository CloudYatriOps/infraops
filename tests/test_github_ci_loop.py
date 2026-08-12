"""End-to-end local integration test for the Phase 2 GitHub PR/CI loop.

Real components exercised here: local git (init/commit/branch/push to a
real bare repo standing in for GitHub's git storage), the real
GitHubClient/GitHubTool routing every capability, the real orchestrator
task graph + durable SQLite state, the real policy engine, and the real
MockProvider (no network, no LLM key needed). The only thing that's
"fake" is the GitHub REST API's HTTP responses (FakeGitHubTransport,
tests/github_fakes.py) - which is exactly what requirement #10 asks for
("tests with mocked GitHub API responses"), since this sandbox has no
live GitHub token/repo to test against (see ARCHITECTURE.md Phase 2
addendum, "what is and isn't real").

Scenario: a real functional bug is fixed and pushed; the fake CI reports
one pending poll, then a failing lint check, then (after a second,
diagnosed fix is pushed) success - exercising the full discovery -> branch
-> implement -> verify -> commit -> push -> PR -> CI-inspect -> diagnose ->
fix -> push -> CI-recheck loop end to end.
"""
import subprocess
import textwrap
from pathlib import Path

from aep.bootstrap import build_orchestrator
from aep.github.planner import plan_github_fix_and_pr
from aep.models import ProjectConfig, TaskStatus
from aep.secrets import StaticSecretManager

from github_fakes import FakeGitHubTransport

FIRST_FIX = "def add(a, b):\n    return a + b\n"
SECOND_FIX = '"""Arithmetic helpers."""\n\n\ndef add(a, b):\n    return a + b\n'


def _init_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q", "-b", "main", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "aep@example.com"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "AEP Bot"], check=True)


def _setup(tmp_path: Path, policy_path: str):
    demo_repo = tmp_path / "demo_project"
    demo_repo.mkdir()
    _init_repo(demo_repo)
    (demo_repo / "app.py").write_text("def add(a, b):\n    return a - b  # BUG\n")
    (demo_repo / "test_app.py").write_text(textwrap.dedent("""\
        from app import add

        def test_add():
            assert add(2, 3) == 5
        """))
    # Without this, a bare `git add -A` (which every commit in this loop
    # does) would sweep up pytest's __pycache__ artifacts once run_tests has
    # executed once - caught by inspecting the manual demo's commit diff,
    # where the second commit showed "3 files changed" instead of 1.
    (demo_repo / ".gitignore").write_text("__pycache__/\n*.pyc\n")
    subprocess.run(["git", "-C", str(demo_repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(demo_repo), "commit", "-q", "-m", "initial commit"], check=True)

    bare_remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(bare_remote)], check=True)
    # Simulate "the repo already exists on GitHub with a main branch",
    # exactly like plan_github_fix_and_pr expects to find when it opens a
    # PR against base=main.
    subprocess.run(["git", "-C", str(demo_repo), "push", str(bare_remote), "main"],
                    check=True, capture_output=True)

    transport = FakeGitHubTransport()
    project = ProjectConfig(id="ghdemo", name="ghdemo", repo_path=str(demo_repo), policy_path=policy_path)
    return demo_repo, bare_remote, transport, project


def _code_fix_responder(request) -> str:
    """Deterministic given only the (durable, resumable) prompt content -
    NOT call order - so a fresh MockProvider instance after a simulated
    crash/resume produces the same answer a real, stateless LLM provider
    would for the same prompt. This is what makes
    test_github_ci_loop_survives_a_crash_mid_loop valid: it must not depend
    on in-memory provider state surviving the 'crash'."""
    if "docstring" in request.user_prompt.lower():
        return SECOND_FIX
    return FIRST_FIX


def _build_orch(tmp_path, project, transport, db_name="state.db"):
    return build_orchestrator(
        db_path=str(tmp_path / db_name), project=project,
        mock_canned={
            "code_fix": _code_fix_responder,
            "diagnose_ci_failure": "add a module docstring to satisfy the lint check",
        },
        enable_github=True,
        github_secret_manager=StaticSecretManager({"github_token": "TEST-TOKEN-MUST-NOT-LEAK"}),
        github_transport=transport,
        sleep_fn=lambda seconds: None,  # don't actually sleep through backoff in tests
    )


def test_github_pr_ci_loop_end_to_end(tmp_path, policy_path):
    demo_repo, bare_remote, transport, project = _setup(tmp_path, policy_path)
    orch = _build_orch(tmp_path, project, transport)

    task_ids = plan_github_fix_and_pr(
        orch, project_id="ghdemo", project_root=str(demo_repo),
        target_file="app.py", bug_description="add() subtracts instead of adding",
        owner="acme", repo="widgets", remote_url=str(bare_remote),
        branch_name="aep/fix-demo",
    )
    orch.run_to_completion("ghdemo", max_iterations=500)

    tasks_by_type: dict[str, list] = {}
    for tid in task_ids:
        t = orch.store.get_task(tid)
        tasks_by_type.setdefault(t.type, []).append(t)
    # every task the diagnose loop scheduled is reachable from the store by
    # project, not just the original task_ids list (follow_up_tasks get new
    # ids) - so also pull the full project task list for final-state checks.
    all_tasks = orch.store.list_tasks("ghdemo")
    by_type_all: dict[str, list] = {}
    for t in all_tasks:
        by_type_all.setdefault(t.type, []).append(t)

    # The initial chain plus one full diagnose/fix/push/monitor loop.
    assert len(by_type_all["code_fix"]) == 2
    assert len(by_type_all["security_scan"]) == 2
    assert len(by_type_all["run_tests"]) == 2
    assert len(by_type_all["push_branch"]) == 2
    assert len(by_type_all["monitor_ci"]) == 2
    assert len(by_type_all["diagnose_ci_failure"]) == 1
    assert len(by_type_all["create_pull_request"]) == 1  # never duplicated

    for t in all_tasks:
        assert t.status == TaskStatus.SUCCEEDED, f"{t.type} ({t.id}) ended {t.status}, evidence={t.evidence}"

    # Real git state on the "remote": both commits landed on the feature
    # branch, never on main.
    branch_log = subprocess.run(
        ["git", "--git-dir", str(bare_remote), "log", "--oneline", "aep/fix-demo"],
        capture_output=True, text=True, check=True,
    ).stdout
    assert branch_log.count("aep: fix") == 2
    main_log = subprocess.run(
        ["git", "--git-dir", str(bare_remote), "log", "--oneline", "main"],
        capture_output=True, text=True, check=True,
    ).stdout
    assert "aep: fix" not in main_log

    assert (demo_repo / "app.py").read_text() == SECOND_FIX

    # Exactly one PR was created (dedup logic worked) and it received the
    # diagnosis comment.
    prs = transport._prs[("acme", "widgets")]
    assert len(prs) == 1
    comments = transport._comments[("acme", "widgets", prs[0]["number"])]
    assert len(comments) == 1
    assert "lint" in comments[0]["body"]

    # The monitor task that detected the failure recorded real evidence of
    # it (not a model's claim).
    first_monitor = sorted(by_type_all["monitor_ci"], key=lambda t: t.created_at)[0]
    assert any("lint" in e.summary for e in first_monitor.evidence)

    # The credential used for GitHub API calls never appears anywhere in
    # the durable event log.
    events = orch.store.query_events(project_id="ghdemo")
    serialized = "\n".join(e.to_json() for e in events)
    assert "TEST-TOKEN-MUST-NOT-LEAK" not in serialized


def test_github_ci_loop_survives_a_crash_mid_loop(tmp_path, policy_path):
    demo_repo, bare_remote, transport, project = _setup(tmp_path, policy_path)
    db_name = "shared_state.db"
    orch_a = _build_orch(tmp_path, project, transport, db_name=db_name)

    plan_github_fix_and_pr(
        orch_a, project_id="ghdemo", project_root=str(demo_repo),
        target_file="app.py", bug_description="add() subtracts instead of adding",
        owner="acme", repo="widgets", remote_url=str(bare_remote),
        branch_name="aep/fix-demo",
    )
    # Run only enough steps to get through the first PR creation and the
    # first (failing) CI check, then simulate a crash before the diagnose/
    # fix/push loop finishes.
    orch_a.run_to_completion("ghdemo", max_iterations=10)
    mid_run_tasks = orch_a.store.list_tasks("ghdemo")
    assert any(t.type == "diagnose_ci_failure" for t in mid_run_tasks), (
        "test setup assumption violated: diagnosis should have started by iteration 10"
    )
    assert not all(t.status == TaskStatus.SUCCEEDED for t in mid_run_tasks), (
        "test setup assumption violated: graph should already be finished by iteration 10"
    )
    del orch_a  # simulate the process dying - no clean shutdown

    # A fresh orchestrator, same durable DB, same external systems (the bare
    # repo and the fake GitHub transport, exactly as real git/GitHub state
    # would still exist after a real crash) - must resume and finish.
    orch_b = _build_orch(tmp_path, project, transport, db_name=db_name)
    orch_b.resume("ghdemo")

    final_tasks = orch_b.store.list_tasks("ghdemo")
    assert all(t.status == TaskStatus.SUCCEEDED for t in final_tasks)
    assert (demo_repo / "app.py").read_text() == SECOND_FIX
