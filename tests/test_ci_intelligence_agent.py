"""CIIntelligenceAgent (Phase 6 Part 2/3), run through the REAL
Orchestrator - discovery is real (parses real workflow files); the
`classify` mode's routing into `build_fix_verify_push_chain` reuses the
EXISTING Phase 2 code-fix chain, verified here without a GitHub target
(no `owner`/`repo`/`remote_url`), which means the push/PR/monitor tail of
that chain will fail for a mundane reason (no git remote) rather than
proving Phase 6 routing - see tests/test_cicd_e2e.py for the full,
GitHub-target version of this loop against a fake transport."""
from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path

from aep.bootstrap import build_orchestrator
from aep.models import ProjectConfig, Task, TaskStatus


def _init_git_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-b", "main", str(path)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "aep@example.com"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "AEP Bot"], check=True)


def test_inspect_mode_discovers_real_workflow_files(tmp_path: Path, policy_path):
    repo = tmp_path / "proj"
    repo.mkdir()
    _init_git_repo(repo)
    workflows = repo / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(textwrap.dedent("""\
        name: CI
        on: [push]
        jobs:
          test:
            steps:
              - run: pytest -q
    """))
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "init"], check=True, capture_output=True)

    project = ProjectConfig(id="p1", name="p1", repo_path=str(repo), policy_path=policy_path)
    orch = build_orchestrator(str(tmp_path / "s.db"), project)
    task = Task(id="t1", type="ci_inspect", project_id="p1", owner_agent="ci_intelligence_agent",
                payload={"mode": "inspect", "project_root": str(repo)})
    orch.submit_graph("p1", [task])
    orch.run_to_completion("p1")
    result = orch.store.get_task("t1")
    assert result.status == TaskStatus.SUCCEEDED
    assert any("1 CI workflow(s)" in e.summary or "1 workflow" in e.summary
               for e in result.evidence) or "1 CI workflow" in result.message


def test_classify_routes_test_failure_to_the_existing_fix_chain(tmp_path: Path, policy_path):
    project = ProjectConfig(id="p1", name="p1", repo_path=str(tmp_path), policy_path=policy_path)
    orch = build_orchestrator(str(tmp_path / "s.db"), project)
    task = Task(id="t1", type="ci_classify", project_id="p1", owner_agent="ci_intelligence_agent",
                payload={"mode": "classify",
                         "failed_checks": [{"name": "unit-tests", "summary": "AssertionError"}],
                         "jobs": [], "project_root": str(tmp_path), "target_file": "app.py",
                         "branch_name": "aep/fix-1"})
    orch.submit_graph("p1", [task])
    orch.run_to_completion("p1")
    result = orch.store.get_task("t1")
    assert result.status == TaskStatus.SUCCEEDED
    assert any("TEST" in e.summary for e in result.evidence)
    # A code_fix follow-up task was actually created, proving Phase 6
    # reused Phase 2's chain rather than reimplementing it.
    all_tasks = orch.store.list_tasks("p1")
    assert any(t.type == "code_fix" for t in all_tasks)


def test_classify_escalates_security_failure_without_touching_the_fix_chain(tmp_path: Path,
                                                                              policy_path):
    project = ProjectConfig(id="p1", name="p1", repo_path=str(tmp_path), policy_path=policy_path)
    orch = build_orchestrator(str(tmp_path / "s.db"), project)
    task = Task(id="t1", type="ci_classify", project_id="p1", owner_agent="ci_intelligence_agent",
                max_attempts=1,
                payload={"mode": "classify",
                         "failed_checks": [{"name": "security-scan",
                                             "summary": "gitleaks found a secret"}],
                         "jobs": [], "project_root": str(tmp_path), "target_file": "app.py",
                         "branch_name": "aep/fix-1"})
    orch.submit_graph("p1", [task])
    orch.run_to_completion("p1")
    result = orch.store.get_task("t1")
    assert result.status != TaskStatus.SUCCEEDED
    all_tasks = orch.store.list_tasks("p1")
    assert not any(t.type == "code_fix" for t in all_tasks)
