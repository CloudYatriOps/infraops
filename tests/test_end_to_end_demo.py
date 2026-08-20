import subprocess

from aep.bootstrap import build_orchestrator
from aep.models import ProjectConfig, Task, TaskStatus
from fixtures import FIXED_APP_PY


def _project(demo_repo, policy_path) -> ProjectConfig:
    return ProjectConfig(id="demo", name="Demo", repo_path=str(demo_repo), policy_path=policy_path)


def test_fix_bug_end_to_end_happy_path(tmp_path, demo_repo, policy_path):
    project = _project(demo_repo, policy_path)
    orch = build_orchestrator(
        db_path=str(tmp_path / "state.db"), project=project,
        mock_canned={"code_fix": FIXED_APP_PY},
     db_backend="sqlite",)

    task_ids = orch.plan_fix_bug(
        project_id="demo", project_root=str(demo_repo),
        target_file="app.py", bug_description="add() subtracts instead of adding",
    )
    orch.run_to_completion("demo")

    tasks = {orch.store.get_task(tid).type: orch.store.get_task(tid) for tid in task_ids}
    assert tasks["recon"].status == TaskStatus.SUCCEEDED
    assert tasks["code_fix"].status == TaskStatus.SUCCEEDED
    assert tasks["security_scan"].status == TaskStatus.SUCCEEDED
    assert tasks["run_tests"].status == TaskStatus.SUCCEEDED

    # Real git state: the fix landed on a feature branch, not on main.
    current_branch = subprocess.run(
        ["git", "-C", str(demo_repo), "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert current_branch != "main"
    assert current_branch.startswith("aep/fix-")

    main_log = subprocess.run(
        ["git", "-C", str(demo_repo), "log", "--oneline", "main"],
        capture_output=True, text=True, check=True,
    ).stdout
    assert "aep: fix" not in main_log  # the fix commit never touched main

    # Real file content on disk reflects the model's proposed fix, applied
    # by the (real) filesystem tool.
    assert (demo_repo / "app.py").read_text() == FIXED_APP_PY

    # Real pytest evidence, not a model's claim.
    test_evidence = tasks["run_tests"].evidence[0]
    assert test_evidence.source == "pytest"
    assert test_evidence.exit_code == 0
    assert "1 passed" in test_evidence.summary

    # Event log has real, queryable audit trail of tool calls.
    events = orch.store.query_events(project_id="demo")
    actions = [e.action for e in events]
    assert "task_succeeded" in actions
    tool_calls = [e for e in events if e.action == "tool_call"]
    assert any(e.details["capability"] == "git.commit" for e in tool_calls)
    assert any(e.details["capability"] == "shell.run" for e in tool_calls)


def test_security_scan_blocks_downstream_tasks_on_detected_secret(
        tmp_path, demo_repo_with_secret, policy_path):
    project = _project(demo_repo_with_secret, policy_path)
    orch = build_orchestrator(
        db_path=str(tmp_path / "state.db"), project=project,
        mock_canned={"code_fix": FIXED_APP_PY},
     db_backend="sqlite",)

    task_ids = orch.plan_fix_bug(
        project_id="demo", project_root=str(demo_repo_with_secret),
        target_file="app.py", bug_description="add() subtracts instead of adding",
    )
    orch.run_to_completion("demo")

    tasks = {orch.store.get_task(tid).type: orch.store.get_task(tid) for tid in task_ids}
    assert tasks["code_fix"].status == TaskStatus.SUCCEEDED
    assert tasks["security_scan"].status == TaskStatus.BLOCKED_ON_APPROVAL
    # run_tests depends on security_scan succeeding - it must never execute.
    assert tasks["run_tests"].status == TaskStatus.PENDING
    assert tasks["run_tests"].attempts == 0

    events = orch.store.query_events(project_id="demo")
    assert any(e.action == "human_required" for e in events)
    scan_evidence = tasks["security_scan"].evidence[0]
    assert scan_evidence.exit_code == 1
    assert "AKIAABCD1234EFGH5678" not in scan_evidence.summary  # full secret never persisted, even redacted


def test_direct_push_to_main_is_denied_by_policy_gate(tmp_path, demo_repo, policy_path):
    project = _project(demo_repo, policy_path)
    orch = build_orchestrator(db_path=str(tmp_path / "state.db"), project=project, db_backend="sqlite")

    deny_task = Task(
        id="deny-me", type="risky_push", project_id="demo", owner_agent="recon",
        payload={
            "project_root": str(demo_repo),
            "policy_action": "git.push", "policy_context": {"branch": "main"},
        },
    )
    orch.submit_graph("demo", [deny_task])
    orch.run_to_completion("demo")

    result = orch.store.get_task("deny-me")
    assert result.status == TaskStatus.CANCELLED

    events = orch.store.query_events(project_id="demo", task_id="deny-me")
    assert any(e.decision == "DENY" for e in events)


def test_resume_after_simulated_crash_continues_the_graph(tmp_path, demo_repo, policy_path):
    project = _project(demo_repo, policy_path)
    db_path = str(tmp_path / "state.db")

    orch_a = build_orchestrator(db_path=db_path, project=project, mock_canned={"code_fix": FIXED_APP_PY}, db_backend="sqlite")
    task_ids = orch_a.plan_fix_bug(
        project_id="demo", project_root=str(demo_repo),
        target_file="app.py", bug_description="fix add()",
    )
    # Run only the first task, then simulate a crash by discarding the
    # orchestrator without finishing the graph.
    first = orch_a._next_ready_task("demo")
    orch_a.run_task(first)
    assert orch_a.store.get_task(first.id).status == TaskStatus.SUCCEEDED
    del orch_a

    # A fresh orchestrator instance, same durable DB file, must resume and
    # complete the remaining graph.
    orch_b = build_orchestrator(db_path=db_path, project=project, mock_canned={"code_fix": FIXED_APP_PY}, db_backend="sqlite")
    orch_b.resume("demo")

    statuses = {orch_b.store.get_task(tid).status for tid in task_ids}
    assert statuses == {TaskStatus.SUCCEEDED}
