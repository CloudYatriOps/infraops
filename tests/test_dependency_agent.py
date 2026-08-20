"""DependencyCVEAgent mode-level tests (remediate/rescan/escalate/scan
wiring). Uses `monkeypatch` on `dependency.inventory.build_inventory` to
control exactly which findings a "scan" sees, so these stay fast and
offline regardless of network/tool availability - the real scanner ->
real network path is covered separately in test_dependency_scanning.py
(unit) and test_dependency_e2e_real.py (full real chain). Everything else
here - git, filesystem, the policy engine, the orchestrator - is real.
"""
from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path

import pytest

from aep.bootstrap import build_orchestrator
from aep.dependency.inventory import InventoryResult
from aep.dependency.models import Ecosystem, Severity, VulnerabilityFinding
from aep.models import FailureClass, ProjectConfig, TaskStatus


def _init_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q", "-b", "main", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "aep@example.com"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "AEP Bot"], check=True)


@pytest.fixture()
def dep_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "dep_project"
    repo.mkdir()
    _init_repo(repo)
    (repo / "requirements.txt").write_text("urllib3==1.26.4\n")
    (repo / "app.py").write_text("VALUE = 1\n")
    (repo / "test_app.py").write_text(textwrap.dedent("""\
        from app import VALUE

        def test_value():
            assert VALUE == 1
        """))
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "initial"], check=True)
    return repo


def _orch(tmp_path, project):
    return build_orchestrator(db_path=str(tmp_path / "state.db"), project=project,
                               sleep_fn=lambda s: None, db_backend="sqlite")


def _finding(package="urllib3", installed="1.26.4", fixed=None, finding_id="PYSEC-TEST-1",
             manifest_path="requirements.txt") -> VulnerabilityFinding:
    return VulnerabilityFinding(
        id=finding_id, aliases=[], ecosystem=Ecosystem.PYTHON, manifest_path=manifest_path,
        package=package, installed_version=installed, vulnerable_range=f"<{installed}",
        fixed_versions=fixed if fixed is not None else ["1.26.17"], severity=Severity.HIGH,
        summary="test finding", source="test-fixture", scanned_at="2026-01-01T00:00:00+00:00",
    )


def test_remediate_mode_applies_upgrade_and_commits(tmp_path, dep_repo, policy_path):
    project = ProjectConfig(id="depagent", name="depagent", repo_path=str(dep_repo),
                             policy_path=policy_path)
    orch = _orch(tmp_path, project)
    from aep.models import Task
    task = Task(id="t1", type="dependency_remediate", project_id="depagent",
                owner_agent="dependency_cve_agent",
                payload={"mode": "remediate", "project_root": str(dep_repo),
                         "branch_name": "aep/dep-fix-test", "skip_install": True,
                         "plans": [{"package": "urllib3", "ecosystem": "python",
                                    "manifest_path": "requirements.txt", "from_version": "1.26.4",
                                    "to_version": "1.26.17", "finding_ids": ["PYSEC-TEST-1"]}]})
    orch.submit_graph("depagent", [task])
    orch.run_to_completion("depagent")

    result = orch.store.get_task("t1")
    assert result.status == TaskStatus.SUCCEEDED, result.evidence
    assert (dep_repo / "requirements.txt").read_text().strip() == "urllib3==1.26.17"
    log = subprocess.run(["git", "-C", str(dep_repo), "log", "--oneline"],
                          capture_output=True, text=True, check=True).stdout
    assert "security fix" in log


def test_remediate_mode_fails_cleanly_when_pin_not_found(tmp_path, dep_repo, policy_path):
    project = ProjectConfig(id="depagent2", name="depagent2", repo_path=str(dep_repo),
                             policy_path=policy_path)
    orch = _orch(tmp_path, project)
    from aep.models import Task
    task = Task(id="t1", type="dependency_remediate", project_id="depagent2",
                owner_agent="dependency_cve_agent", max_attempts=1,
                payload={"mode": "remediate", "project_root": str(dep_repo),
                         "branch_name": "aep/dep-fix-missing", "skip_install": True,
                         "plans": [{"package": "does-not-exist", "ecosystem": "python",
                                    "manifest_path": "requirements.txt", "from_version": "9.9.9",
                                    "to_version": "10.0.0", "finding_ids": ["PYSEC-X"]}]})
    orch.submit_graph("depagent2", [task])
    orch.run_to_completion("depagent2")

    result = orch.store.get_task("t1")
    assert result.status in (TaskStatus.FAILED, TaskStatus.QUARANTINED)


def test_rescan_confirms_resolved(tmp_path, dep_repo, policy_path, monkeypatch):
    monkeypatch.setattr(
        "aep.agents.dependency_cve_agent.build_inventory",
        lambda project_root, run_shell, manifest_filter=None: InventoryResult(
            manifests=[], scan_records=[], unscanned=[]),
    )
    project = ProjectConfig(id="depagent3", name="depagent3", repo_path=str(dep_repo),
                             policy_path=policy_path)
    orch = _orch(tmp_path, project)
    from aep.models import Task
    task = Task(id="t1", type="dependency_rescan", project_id="depagent3",
                owner_agent="dependency_cve_agent",
                payload={"mode": "rescan", "project_root": str(dep_repo),
                         "plans": [{"package": "urllib3", "manifest_path": "requirements.txt",
                                    "from_version": "1.26.4",
                                    "to_version": "1.26.17", "finding_ids": ["PYSEC-TEST-1"]}]})
    orch.submit_graph("depagent3", [task])
    orch.run_to_completion("depagent3")

    result = orch.store.get_task("t1")
    assert result.status == TaskStatus.SUCCEEDED
    assert any("CONFIRMED resolved" in e.summary for e in result.evidence)


def test_rescan_reports_unresolved_cve_rather_than_claiming_fixed(tmp_path, dep_repo, policy_path,
                                                                     monkeypatch):
    still_vulnerable = _finding()  # same finding id still present after the "fix"

    class _Fake:
        findings = [still_vulnerable]
        scan_records = []
    monkeypatch.setattr(
        "aep.agents.dependency_cve_agent.build_inventory",
        lambda project_root, run_shell, manifest_filter=None: _Fake(),
    )
    project = ProjectConfig(id="depagent4", name="depagent4", repo_path=str(dep_repo),
                             policy_path=policy_path)
    orch = _orch(tmp_path, project)
    from aep.models import Task
    task = Task(id="t1", type="dependency_rescan", project_id="depagent4",
                owner_agent="dependency_cve_agent", max_attempts=1,
                payload={"mode": "rescan", "project_root": str(dep_repo),
                         "plans": [{"package": "urllib3", "manifest_path": "requirements.txt",
                                    "from_version": "1.26.4",
                                    "to_version": "1.26.17", "finding_ids": ["PYSEC-TEST-1"]}]})
    orch.submit_graph("depagent4", [task])
    orch.run_to_completion("depagent4")

    result = orch.store.get_task("t1")
    assert result.status in (TaskStatus.FAILED, TaskStatus.QUARANTINED)
    assert any("NOT resolved" in e.summary for e in result.evidence)
    assert not any("CONFIRMED resolved" in e.summary for e in result.evidence)


def test_escalate_mode_is_human_required_not_silently_dropped(tmp_path, dep_repo, policy_path):
    project = ProjectConfig(id="depagent5", name="depagent5", repo_path=str(dep_repo),
                             policy_path=policy_path)
    orch = _orch(tmp_path, project)
    from aep.models import Task
    task = Task(id="t1", type="dependency_escalate", project_id="depagent5",
                owner_agent="dependency_cve_agent", max_attempts=1,
                payload={"mode": "escalate",
                         "plan": {"package": "no-fix-pkg", "from_version": "1.0.0",
                                  "to_version": None, "finding_ids": ["PYSEC-NOFIX"],
                                  "reason": "no published fixed version"}})
    orch.submit_graph("depagent5", [task])
    orch.run_to_completion("depagent5")

    result = orch.store.get_task("t1")
    assert result.status == TaskStatus.BLOCKED_ON_APPROVAL  # NO_AUTO_RETRY -> human required


def test_scan_mode_splits_safe_and_unsafe_into_separate_follow_ups(tmp_path, dep_repo, policy_path,
                                                                     monkeypatch):
    safe = _finding(package="urllib3", fixed=["1.26.17"])
    unsafe = _finding(package="stuck-pkg", installed="0.1.0", fixed=[], finding_id="PYSEC-STUCK")

    class _Fake:
        findings = [safe, unsafe]
        scan_records = []
        unscanned = []
    monkeypatch.setattr(
        "aep.agents.dependency_cve_agent.build_inventory",
        lambda project_root, run_shell: _Fake(),
    )
    project = ProjectConfig(id="depagent6", name="depagent6", repo_path=str(dep_repo),
                             policy_path=policy_path)
    orch = _orch(tmp_path, project)
    from aep.dependency.planner import plan_dependency_scan
    plan_dependency_scan(orch, project_id="depagent6", project_root=str(dep_repo))
    orch.run_to_completion("depagent6", max_iterations=200)

    all_tasks = orch.store.list_tasks("depagent6")
    types = {t.type for t in all_tasks}
    assert "dependency_remediate" in types  # safe upgrade got a remediation chain
    assert "dependency_escalate" in types  # unsafe finding got escalated, not silently dropped

    escalate_task = next(t for t in all_tasks if t.type == "dependency_escalate")
    assert escalate_task.status == TaskStatus.BLOCKED_ON_APPROVAL
    # No github target was given, so the chain must not include push/PR/monitor tasks.
    assert "push_branch" not in types
    assert "create_pull_request" not in types
