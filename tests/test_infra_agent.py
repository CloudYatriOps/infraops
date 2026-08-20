"""Infrastructure agent mode-level tests (Phase 5 Part 11/16).

Mirrors test_security_agent.py: `run_infrastructure_scan` is monkeypatched
so failure paths and policy routing are exercised fast and offline. The
real scanner -> real fix -> real rescan chain is covered by
tests/test_infra_e2e.py. Everything else here - git, filesystem, the
policy engine, the orchestrator - is real.
"""
from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path

import pytest

from aep.bootstrap import build_orchestrator
from aep.models import ProjectConfig, Task, TaskStatus
from aep.security.models import (
    ScannerAvailability, SecurityCategory, SecurityFinding, SecurityScanRecord, SecuritySeverity,
)
from aep.security.scan_runner import SecurityScanResult

# A schema-VALID Deployment (selector/labels present). This matters: the
# agent validates every remediated file against the real Kubernetes
# schemas and reverts anything that fails, so a fixture missing required
# fields would fail for a reason unrelated to what these tests check -
# caught during Phase 5 development when a minimal fixture without
# `spec.selector` was correctly rejected by kubernetes-validate.
_WORKLOAD = textwrap.dedent("""\
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: app
      namespace: default
    spec:
      selector:
        matchLabels:
          app: app
      template:
        metadata:
          labels:
            app: app
        spec:
          hostNetwork: true
          containers:
            - name: c
              image: nginx:1.25
              securityContext:
                privileged: true
    """)


def _init_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q", "-b", "main", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "aep@example.com"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "AEP Bot"], check=True)


@pytest.fixture()
def infra_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "infra_project"
    (repo / "k8s").mkdir(parents=True)
    _init_repo(repo)
    (repo / "k8s" / "app.yaml").write_text(_WORKLOAD)
    (repo / "app.py").write_text("def add(a, b):\n    return a + b\n")
    (repo / "test_app.py").write_text(
        "from app import add\n\ndef test_add():\n    assert add(2, 3) == 5\n")
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "initial"], check=True)
    return repo


def _orch(tmp_path, project):
    return build_orchestrator(db_path=str(tmp_path / "state.db"), project=project,
                               sleep_fn=lambda s: None, db_backend="sqlite")


def _finding(rule_id="CKV_K8S_16", severity=SecuritySeverity.CRITICAL,
              category=SecurityCategory.KUBERNETES, file="k8s/app.yaml",
              resource="Deployment.default.app") -> SecurityFinding:
    return SecurityFinding(
        id=f"checkov-k8s:{rule_id}:{file}:{resource}", scanner="checkov-kubernetes",
        category=category, severity=severity, confidence="high", file=file, line=1,
        resource=resource, description="d", evidence="e", remediation="r", rule_id=rule_id,
    )


def _record(findings) -> SecurityScanRecord:
    return SecurityScanRecord(
        scanner="checkov-kubernetes", scanner_version="3.3.10",
        category=SecurityCategory.KUBERNETES, scanned_at="2026-01-01T00:00:00+00:00",
        target=".", availability=ScannerAvailability.AVAILABLE, exit_code=1,
        finding_count=len(findings), findings=findings,
    )


def _patch_scan(monkeypatch, findings):
    monkeypatch.setattr(
        "aep.agents.infrastructure_intelligence_agent.run_infrastructure_scan",
        lambda project_root, run_shell, categories=None, include_phase4_scanners=True:
            SecurityScanResult(records=[_record(findings)]),
    )


def _remediation(rule_id="CKV_K8S_19", fix="hostNetwork", file="k8s/app.yaml"):
    return {
        "finding": _finding(rule_id=rule_id, severity=SecuritySeverity.HIGH, file=file).to_dict(),
        "risk": {"finding_id": "x", "base_severity": "high", "priority_severity": "high",
                  "score": 41.2, "environment": "production", "blast_radius": "cluster_wide",
                  "exploitability": "adjacent_network", "rationale": "test"},
        "plan": {"finding_id": "x", "kind": "kubernetes", "fix": fix, "file": file,
                  "resource": "Deployment.default.app", "description": "test", "caveat": "test"},
    }


# ---- discovery agent -------------------------------------------------------

def test_discovery_agent_holds_no_mutating_capability():
    from aep.agents import InfrastructureDiscoveryAgent

    capabilities = InfrastructureDiscoveryAgent.required_capabilities
    assert capabilities == {"filesystem.list", "filesystem.read"}
    # Structurally read-only: it cannot shell out, use git, or call GitHub
    # because the capability-scoped registry will not hand it those tools.
    assert not any(c.startswith(("shell.", "git.", "github.")) for c in capabilities)
    assert not any("write" in c for c in capabilities)


def test_discovery_agent_runs_and_records_an_inventory(tmp_path, infra_repo, policy_path):
    project = ProjectConfig(id="infradisc", name="infradisc", repo_path=str(infra_repo),
                             policy_path=policy_path)
    orch = _orch(tmp_path, project)
    task = Task(id="d1", type="infra_discover", project_id="infradisc",
                owner_agent="infrastructure_discovery_agent",
                payload={"project_root": str(infra_repo)})
    orch.submit_graph("infradisc", [task])
    orch.run_to_completion("infradisc")

    result = orch.store.get_task("d1")
    assert result.status == TaskStatus.SUCCEEDED, result.evidence
    assert any("infrastructure asset" in e.summary or "asset(s)" in e.summary
                for e in result.evidence)
    assert any(e.source == "policy" and "ALLOW" in e.summary for e in result.evidence)


# ---- intelligence agent: scan-mode routing ---------------------------------

def test_critical_finding_is_escalated_never_auto_remediated(tmp_path, infra_repo, policy_path,
                                                                monkeypatch):
    _patch_scan(monkeypatch, [_finding("CKV_K8S_16", SecuritySeverity.CRITICAL)])
    project = ProjectConfig(id="infra1", name="infra1", repo_path=str(infra_repo),
                             policy_path=policy_path)
    orch = _orch(tmp_path, project)
    from aep.infra.planner import plan_infrastructure_scan
    plan_infrastructure_scan(orch, project_id="infra1", project_root=str(infra_repo),
                              with_discovery=False)
    orch.run_to_completion("infra1", max_iterations=200)

    types = {t.type for t in orch.store.list_tasks("infra1")}
    # CKV_K8S_16 IS mechanically fixable, but a CRITICAL priority is
    # DENY-gated, so it must never reach the remediation path.
    assert "infra_escalate" in types
    assert "infra_remediate" not in types
    escalation = next(t for t in orch.store.list_tasks("infra1") if t.type == "infra_escalate")
    assert escalation.status == TaskStatus.BLOCKED_ON_APPROVAL


def test_high_finding_with_a_deterministic_fix_is_remediated(tmp_path, infra_repo, policy_path,
                                                                monkeypatch):
    _patch_scan(monkeypatch, [_finding("CKV_K8S_19", SecuritySeverity.HIGH)])
    project = ProjectConfig(id="infra2", name="infra2", repo_path=str(infra_repo),
                             policy_path=policy_path)
    orch = _orch(tmp_path, project)
    from aep.infra.planner import plan_infrastructure_scan
    plan_infrastructure_scan(orch, project_id="infra2", project_root=str(infra_repo),
                              with_discovery=False)
    orch.run_to_completion("infra2", max_iterations=200)

    types = {t.type for t in orch.store.list_tasks("infra2")}
    assert "infra_remediate" in types
    # No GitHub target was given, so the chain must stop after rescan.
    assert "create_pull_request" not in types


def test_ambiguous_finding_is_escalated_with_a_reason(tmp_path, infra_repo, policy_path,
                                                         monkeypatch):
    _patch_scan(monkeypatch, [_finding("CKV_K8S_49", SecuritySeverity.HIGH,
                                        resource="ClusterRole.default.wildcard")])
    project = ProjectConfig(id="infra3", name="infra3", repo_path=str(infra_repo),
                             policy_path=policy_path)
    orch = _orch(tmp_path, project)
    from aep.infra.planner import plan_infrastructure_scan
    plan_infrastructure_scan(orch, project_id="infra3", project_root=str(infra_repo),
                              with_discovery=False)
    orch.run_to_completion("infra3", max_iterations=200)

    escalation = next(t for t in orch.store.list_tasks("infra3") if t.type == "infra_escalate")
    assert escalation.status == TaskStatus.BLOCKED_ON_APPROVAL
    assert any("human" in e.summary.lower() or "IAM" in e.summary for e in escalation.evidence)


def test_low_severity_findings_are_tracked_not_remediated(tmp_path, infra_repo, policy_path,
                                                             monkeypatch):
    _patch_scan(monkeypatch, [_finding("CKV_K8S_9", SecuritySeverity.LOW)])
    project = ProjectConfig(id="infra4", name="infra4", repo_path=str(infra_repo),
                             policy_path=policy_path)
    orch = _orch(tmp_path, project)
    from aep.infra.planner import plan_infrastructure_scan
    plan_infrastructure_scan(orch, project_id="infra4", project_root=str(infra_repo),
                              with_discovery=False)
    orch.run_to_completion("infra4", max_iterations=200)

    types = {t.type for t in orch.store.list_tasks("infra4")}
    assert "infra_remediate" not in types
    assert "infra_escalate" not in types


# ---- remediate / validate --------------------------------------------------

def test_remediate_applies_validates_and_commits(tmp_path, infra_repo, policy_path):
    project = ProjectConfig(id="infra5", name="infra5", repo_path=str(infra_repo),
                             policy_path=policy_path)
    orch = _orch(tmp_path, project)
    task = Task(id="r1", type="infra_remediate", project_id="infra5",
                owner_agent="infrastructure_intelligence_agent",
                payload={"mode": "remediate", "project_root": str(infra_repo),
                         "branch_name": "aep/infra-test", "remediations": [_remediation()]})
    orch.submit_graph("infra5", [task])
    orch.run_to_completion("infra5")

    result = orch.store.get_task("r1")
    assert result.status == TaskStatus.SUCCEEDED, result.evidence
    assert "hostNetwork" not in (infra_repo / "k8s" / "app.yaml").read_text()
    assert any("kubernetes-validate" in e.source for e in result.evidence)
    log = subprocess.run(["git", "-C", str(infra_repo), "log", "--oneline"],
                          capture_output=True, text=True, check=True).stdout
    assert "infrastructure security fix" in log


def test_an_unvalidatable_change_is_reverted_not_committed(tmp_path, infra_repo, policy_path,
                                                              monkeypatch):
    """Part 10's hard rule. Forcing validation to fail must leave the file
    exactly as it was and fail the task."""
    from aep.infra.models import ValidationResult

    monkeypatch.setattr(
        "aep.agents.infrastructure_intelligence_agent._validate_file",
        lambda project_root, relative_path, run_shell: [
            ValidationResult(validator="forced", ran=True, passed=False,
                             detail="forced failure", target=relative_path)],
    )
    original = (infra_repo / "k8s" / "app.yaml").read_text()
    project = ProjectConfig(id="infra6", name="infra6", repo_path=str(infra_repo),
                             policy_path=policy_path)
    orch = _orch(tmp_path, project)
    task = Task(id="r1", type="infra_remediate", project_id="infra6", max_attempts=1,
                owner_agent="infrastructure_intelligence_agent",
                payload={"mode": "remediate", "project_root": str(infra_repo),
                         "branch_name": "aep/infra-revert", "remediations": [_remediation()]})
    orch.submit_graph("infra6", [task])
    orch.run_to_completion("infra6")

    result = orch.store.get_task("r1")
    assert result.status in (TaskStatus.FAILED, TaskStatus.QUARANTINED)
    assert (infra_repo / "k8s" / "app.yaml").read_text() == original
    assert any("REVERTED" in e.summary for e in result.evidence)


def test_remediation_with_no_runnable_validator_is_refused(tmp_path, infra_repo, policy_path,
                                                              monkeypatch):
    """A file type with no validator must not be silently accepted."""
    monkeypatch.setattr(
        "aep.agents.infrastructure_intelligence_agent._validate_file",
        lambda project_root, relative_path, run_shell: [],
    )
    project = ProjectConfig(id="infra7", name="infra7", repo_path=str(infra_repo),
                             policy_path=policy_path)
    orch = _orch(tmp_path, project)
    task = Task(id="r1", type="infra_remediate", project_id="infra7", max_attempts=1,
                owner_agent="infrastructure_intelligence_agent",
                payload={"mode": "remediate", "project_root": str(infra_repo),
                         "branch_name": "aep/infra-noval", "remediations": [_remediation()]})
    orch.submit_graph("infra7", [task])
    orch.run_to_completion("infra7")

    result = orch.store.get_task("r1")
    assert result.status in (TaskStatus.FAILED, TaskStatus.QUARANTINED)
    assert any("no validator was able to run" in e.summary for e in result.evidence)


# ---- rescan ----------------------------------------------------------------

def test_rescan_confirms_resolution(tmp_path, infra_repo, policy_path, monkeypatch):
    _patch_scan(monkeypatch, [])
    project = ProjectConfig(id="infra8", name="infra8", repo_path=str(infra_repo),
                             policy_path=policy_path)
    orch = _orch(tmp_path, project)
    task = Task(id="rs1", type="infra_rescan", project_id="infra8",
                owner_agent="infrastructure_intelligence_agent",
                payload={"mode": "rescan", "project_root": str(infra_repo),
                         "remediations": [_remediation()]})
    orch.submit_graph("infra8", [task])
    orch.run_to_completion("infra8")

    result = orch.store.get_task("rs1")
    assert result.status == TaskStatus.SUCCEEDED
    assert any("CONFIRMED resolved" in e.summary for e in result.evidence)


def test_rescan_refuses_to_claim_success_when_the_finding_persists(tmp_path, infra_repo,
                                                                      policy_path, monkeypatch):
    remediation = _remediation()
    persistent = SecurityFinding(**{
        **{k: v for k, v in remediation["finding"].items()
           if k not in ("category", "severity", "status")},
        "category": SecurityCategory.KUBERNETES, "severity": SecuritySeverity.HIGH,
    })
    _patch_scan(monkeypatch, [persistent])
    project = ProjectConfig(id="infra9", name="infra9", repo_path=str(infra_repo),
                             policy_path=policy_path)
    orch = _orch(tmp_path, project)
    task = Task(id="rs1", type="infra_rescan", project_id="infra9", max_attempts=1,
                owner_agent="infrastructure_intelligence_agent",
                payload={"mode": "rescan", "project_root": str(infra_repo),
                         "remediations": [remediation]})
    orch.submit_graph("infra9", [task])
    orch.run_to_completion("infra9")

    result = orch.store.get_task("rs1")
    assert result.status in (TaskStatus.FAILED, TaskStatus.QUARANTINED)
    assert any("NOT resolved" in e.summary for e in result.evidence)
    assert not any("CONFIRMED resolved" in e.summary for e in result.evidence)


def test_agents_are_registered_in_the_existing_orchestrator(tmp_path, infra_repo, policy_path):
    project = ProjectConfig(id="infra10", name="infra10", repo_path=str(infra_repo),
                             policy_path=policy_path)
    orch = _orch(tmp_path, project)
    # Part 11: integrated into the EXISTING orchestrator, not a parallel one.
    assert "infrastructure_discovery_agent" in orch.agents
    assert "infrastructure_intelligence_agent" in orch.agents
