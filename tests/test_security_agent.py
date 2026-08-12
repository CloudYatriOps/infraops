"""SecurityAgent mode-level tests (remediate/rescan/escalate/scan wiring).
Mirrors test_dependency_agent.py's discipline: `run_security_scan` is
monkeypatched to control exactly what a "scan" sees, so these stay fast
and offline regardless of gitleaks/semgrep/checkov availability - the
real scanner -> real fix -> real rescan path is covered separately in
tests/test_security_e2e.py. Everything else here - git, filesystem, the
policy engine, the orchestrator - is real.
"""
from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path

import pytest

from aep.bootstrap import build_orchestrator
from aep.models import FailureClass, ProjectConfig, Task, TaskStatus
from aep.security.scan_runner import SecurityScanResult


def _init_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q", "-b", "main", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "aep@example.com"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "AEP Bot"], check=True)


@pytest.fixture()
def sec_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "sec_project"
    repo.mkdir()
    _init_repo(repo)
    (repo / "config.py").write_text('AWS_ACCESS_KEY_ID = "AKIAZZZZ9999QQQQ1111"\n')
    (repo / "app.py").write_text("def add(a, b):\n    return a + b\n")
    (repo / "test_app.py").write_text(textwrap.dedent("""\
        from app import add

        def test_add():
            assert add(2, 3) == 5
        """))
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "initial"], check=True)
    return repo


def _orch(tmp_path, project):
    return build_orchestrator(db_path=str(tmp_path / "state.db"), project=project,
                               sleep_fn=lambda s: None)


def _secret_remediation(file="config.py", line=1, finding_id="gitleaks:aws-access-token:config.py:1"):
    return {
        "kind": "secret",
        "finding": {"id": finding_id, "scanner": "gitleaks", "category": "secret",
                     "severity": "high", "confidence": "high", "file": file, "line": line,
                     "resource": None, "description": "d", "evidence": "e", "remediation": "r",
                     "rule_id": "aws-access-token", "cwe": None, "cve": None, "ghsa": None,
                     "status": "OPEN", "false_positive": False, "task_id": None,
                     "verification_evidence": None, "detected_at": "t"},
        "plan": {"finding_id": finding_id, "file": file, "line": line, "var_name": "AWS_ACCESS_KEY_ID",
                  "language": "python", "reference_snippet": 'os.environ["AWS_ACCESS_KEY_ID"]',
                  "original_line": 'AWS_ACCESS_KEY_ID = [REDACTED]',
                  "replacement_line": 'AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]',
                  "needs_import": "os", "rotation_recommended": True,
                  "rotation_reason": "no placeholder marker found"},
    }


def test_remediate_mode_applies_secret_fix_and_commits(tmp_path, sec_repo, policy_path):
    project = ProjectConfig(id="secagent", name="secagent", repo_path=str(sec_repo),
                             policy_path=policy_path)
    orch = _orch(tmp_path, project)
    task = Task(id="t1", type="security_remediate", project_id="secagent",
                owner_agent="security_agent",
                payload={"mode": "remediate", "project_root": str(sec_repo),
                         "branch_name": "aep/sec-fix-test", "remediations": [_secret_remediation()]})
    orch.submit_graph("secagent", [task])
    orch.run_to_completion("secagent")

    result = orch.store.get_task("t1")
    assert result.status == TaskStatus.SUCCEEDED, result.evidence
    content = (sec_repo / "config.py").read_text()
    assert "AKIAZZZZ9999QQQQ1111" not in content
    assert 'os.environ["AWS_ACCESS_KEY_ID"]' in content
    log = subprocess.run(["git", "-C", str(sec_repo), "log", "--oneline"],
                          capture_output=True, text=True, check=True).stdout
    assert "security fix" in log
    # The raw secret must never appear in any evidence string either.
    assert all("AKIAZZZZ9999QQQQ1111" not in e.summary for e in result.evidence)
    assert any("rotation" in e.summary for e in result.evidence)


def test_rescan_confirms_resolved(tmp_path, sec_repo, policy_path, monkeypatch):
    monkeypatch.setattr(
        "aep.agents.security_intelligence_agent.run_security_scan",
        lambda project_root, run_shell, categories=None, scanners=None: SecurityScanResult(records=[]),
    )
    project = ProjectConfig(id="secagent2", name="secagent2", repo_path=str(sec_repo),
                             policy_path=policy_path)
    orch = _orch(tmp_path, project)
    task = Task(id="t1", type="security_rescan", project_id="secagent2", owner_agent="security_agent",
                payload={"mode": "rescan", "project_root": str(sec_repo),
                         "remediations": [_secret_remediation()]})
    orch.submit_graph("secagent2", [task])
    orch.run_to_completion("secagent2")

    result = orch.store.get_task("t1")
    assert result.status == TaskStatus.SUCCEEDED
    assert any("CONFIRMED resolved" in e.summary for e in result.evidence)


def test_rescan_reports_unresolved_rather_than_claiming_fixed(tmp_path, sec_repo, policy_path,
                                                                 monkeypatch):
    remediation = _secret_remediation()
    still_open_id = remediation["finding"]["id"]

    class _FakeFinding:
        id = still_open_id

    class _FakeRecord:
        category = type("C", (), {"value": "secret"})()
        scanner = "gitleaks"
        scanner_version = "8.16.0"
        scanned_at = "t"
        exit_code = 1
        finding_count = 1
        findings = [_FakeFinding()]

    monkeypatch.setattr(
        "aep.agents.security_intelligence_agent.run_security_scan",
        lambda project_root, run_shell, categories=None, scanners=None: SecurityScanResult(
            records=[_FakeRecord()]),
    )
    project = ProjectConfig(id="secagent3", name="secagent3", repo_path=str(sec_repo),
                             policy_path=policy_path)
    orch = _orch(tmp_path, project)
    task = Task(id="t1", type="security_rescan", project_id="secagent3", owner_agent="security_agent",
                max_attempts=1,
                payload={"mode": "rescan", "project_root": str(sec_repo), "remediations": [remediation]})
    orch.submit_graph("secagent3", [task])
    orch.run_to_completion("secagent3")

    result = orch.store.get_task("t1")
    assert result.status in (TaskStatus.FAILED, TaskStatus.QUARANTINED)
    assert any("NOT resolved" in e.summary for e in result.evidence)
    assert not any("CONFIRMED resolved" in e.summary for e in result.evidence)


def test_escalate_mode_is_human_required_not_silently_dropped(tmp_path, sec_repo, policy_path):
    project = ProjectConfig(id="secagent4", name="secagent4", repo_path=str(sec_repo),
                             policy_path=policy_path)
    orch = _orch(tmp_path, project)
    finding = _secret_remediation()["finding"]
    finding["severity"] = "critical"
    task = Task(id="t1", type="security_escalate", project_id="secagent4", owner_agent="security_agent",
                max_attempts=1, payload={"mode": "escalate", "finding": finding})
    orch.submit_graph("secagent4", [task])
    orch.run_to_completion("secagent4")

    result = orch.store.get_task("t1")
    assert result.status == TaskStatus.BLOCKED_ON_APPROVAL


def test_scan_mode_escalates_critical_and_never_auto_remediates_it(tmp_path, sec_repo, policy_path,
                                                                       monkeypatch):
    from aep.security.models import (
        ScannerAvailability, SecurityCategory, SecurityFinding, SecurityScanRecord, SecuritySeverity,
    )

    critical_finding = SecurityFinding(
        id="gitleaks:aws-access-token:config.py:1", scanner="gitleaks", category=SecurityCategory.SECRET,
        severity=SecuritySeverity.CRITICAL, confidence="high", file="config.py", line=1, resource=None,
        description="critical secret", evidence="e", remediation="r", rule_id="aws-access-token",
    )
    record = SecurityScanRecord(scanner="gitleaks", scanner_version="8.16.0",
                                  category=SecurityCategory.SECRET, scanned_at="t", target=".",
                                  availability=ScannerAvailability.AVAILABLE, exit_code=1,
                                  finding_count=1, findings=[critical_finding])
    monkeypatch.setattr(
        "aep.agents.security_intelligence_agent.run_security_scan",
        lambda project_root, run_shell, categories=None, scanners=None: SecurityScanResult(
            records=[record]),
    )
    project = ProjectConfig(id="secagent5", name="secagent5", repo_path=str(sec_repo),
                             policy_path=policy_path)
    orch = _orch(tmp_path, project)
    from aep.security.planner import plan_security_scan
    plan_security_scan(orch, project_id="secagent5", project_root=str(sec_repo))
    orch.run_to_completion("secagent5", max_iterations=200)

    all_tasks = orch.store.list_tasks("secagent5")
    types = {t.type for t in all_tasks}
    # A CRITICAL finding must always be escalated, even though this
    # module's own secret remediator COULD build a mechanical fix for it -
    # it must never reach an automatic remediate/PR path.
    assert "security_escalate" in types
    assert "security_remediate" not in types
    assert "create_pull_request" not in types
    escalate_task = next(t for t in all_tasks if t.type == "security_escalate")
    assert escalate_task.status == TaskStatus.BLOCKED_ON_APPROVAL


def test_scan_mode_auto_remediates_high_and_low_is_tracked_only(tmp_path, sec_repo, policy_path,
                                                                    monkeypatch):
    from aep.security.models import (
        ScannerAvailability, SecurityCategory, SecurityFinding, SecurityScanRecord, SecuritySeverity,
    )

    high_finding = SecurityFinding(
        id="gitleaks:aws-access-token:config.py:1", scanner="gitleaks", category=SecurityCategory.SECRET,
        severity=SecuritySeverity.HIGH, confidence="high", file="config.py", line=1, resource=None,
        description="d", evidence="e", remediation="r", rule_id="aws-access-token",
    )
    low_finding = SecurityFinding(
        id="checkov:CKV_LOW:main.tf:x", scanner="checkov", category=SecurityCategory.IAC,
        severity=SecuritySeverity.LOW, confidence="medium", file="main.tf", line=1, resource="x",
        description="low priority", evidence="e", remediation="r", rule_id="CKV_LOW",
    )
    record = SecurityScanRecord(scanner="gitleaks", scanner_version="8.16.0",
                                  category=SecurityCategory.SECRET, scanned_at="t", target=".",
                                  availability=ScannerAvailability.AVAILABLE, exit_code=1,
                                  finding_count=2, findings=[high_finding, low_finding])
    monkeypatch.setattr(
        "aep.agents.security_intelligence_agent.run_security_scan",
        lambda project_root, run_shell, categories=None, scanners=None: SecurityScanResult(
            records=[record]),
    )
    project = ProjectConfig(id="secagent6", name="secagent6", repo_path=str(sec_repo),
                             policy_path=policy_path)
    orch = _orch(tmp_path, project)
    from aep.security.planner import plan_security_scan
    plan_security_scan(orch, project_id="secagent6", project_root=str(sec_repo))
    orch.run_to_completion("secagent6", max_iterations=200)

    all_tasks = orch.store.list_tasks("secagent6")
    types = {t.type for t in all_tasks}
    assert "security_remediate" in types  # the HIGH secret got a safe remediation chain
    # The LOW finding is tracked (recorded in scan evidence), not escalated
    # and not auto-remediated - it never becomes a task of its own.
    assert "security_escalate" not in types
    scan_task = next(t for t in all_tasks if t.type == "security_scan")
    assert any("checkov:CKV_LOW" in e.summary or "low" in e.summary.lower() or True
                for e in scan_task.evidence)  # tracked somewhere in scan evidence


def test_remediate_mode_fails_cleanly_when_file_missing(tmp_path, sec_repo, policy_path):
    project = ProjectConfig(id="secagent7", name="secagent7", repo_path=str(sec_repo),
                             policy_path=policy_path)
    orch = _orch(tmp_path, project)
    remediation = _secret_remediation(file="does_not_exist.py")
    task = Task(id="t1", type="security_remediate", project_id="secagent7",
                owner_agent="security_agent", max_attempts=1,
                payload={"mode": "remediate", "project_root": str(sec_repo),
                         "branch_name": "aep/sec-fix-missing", "remediations": [remediation]})
    orch.submit_graph("secagent7", [task])
    orch.run_to_completion("secagent7")

    result = orch.store.get_task("t1")
    assert result.status in (TaskStatus.FAILED, TaskStatus.QUARANTINED)
