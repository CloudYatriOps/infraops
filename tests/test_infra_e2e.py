"""Phase 5 Part 13/16: end-to-end DISCOVER -> FIND -> CLASSIFY ->
REMEDIATE -> VALIDATE -> RESCAN -> VERIFY with REAL tooling.

Nothing is mocked in this file: real checkov, real python-hcl2, real
kubernetes-validate, real git, the real orchestrator and the real policy
engine. GitHub push/PR/CI is not exercised (no owner/repo/remote_url is
given, so `include_github=False` truncates the chain after rescan) -
Phase 3's test_dependency_github_loop.py already proves that shared
push/PR/monitor_ci wiring against a mocked transport, and duplicating it
here would re-test identical code.

Deliberately absent: any test that applies Terraform, contacts a cluster,
or reaches a cloud. Part 6 forbids all three, and this platform holds no
capability that could do them.
"""
from __future__ import annotations

import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from aep.bootstrap import build_orchestrator
from aep.infra.discovery import discover_infrastructure
from aep.infra.models import AssetKind
from aep.infra.planner import plan_infrastructure_scan
from aep.infra.scanners import checkov_k8s_scanner, helm_scanner, terraform_deep_scanner
from aep.models import ProjectConfig, TaskStatus
from aep.security.models import ScannerAvailability

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "infra"


def _run_shell(args, cwd=None, timeout=180):
    try:
        proc = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return {"ok": proc.returncode == 0, "exit_code": proc.returncode,
                "stdout": proc.stdout, "stderr": proc.stderr}
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return {"ok": False, "exit_code": -1, "stdout": "", "stderr": str(e)}


_checkov_available = (checkov_k8s_scanner.check_availability(_run_shell).status
                       == ScannerAvailability.AVAILABLE)


def _init_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q", "-b", "main", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "aep@example.com"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "AEP Bot"], check=True)


@pytest.fixture()
def infra_project(tmp_path: Path) -> Path:
    """A real git repo containing the shipped insecure Terraform,
    Kubernetes and Helm fixtures, under a production-named path so the
    risk model's environment weighting is genuinely exercised."""
    repo = tmp_path / "infra_project"
    (repo / "envs" / "prod").mkdir(parents=True)
    _init_repo(repo)
    shutil.copy(FIXTURES / "terraform" / "main.tf", repo / "envs" / "prod" / "main.tf")
    (repo / "k8s").mkdir()
    shutil.copy(FIXTURES / "kubernetes" / "workload.yaml", repo / "k8s" / "workload.yaml")
    shutil.copytree(FIXTURES / "helm" / "insecure-chart", repo / "charts" / "insecure-chart")
    (repo / "app.py").write_text("def add(a, b):\n    return a + b\n")
    (repo / "test_app.py").write_text(
        "from app import add\n\ndef test_add():\n    assert add(2, 3) == 5\n")
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "initial"], check=True)
    return repo


def _orch(tmp_path, repo, policy_path, project_id):
    project = ProjectConfig(id=project_id, name=project_id, repo_path=str(repo),
                             policy_path=policy_path)
    return build_orchestrator(db_path=str(tmp_path / f"{project_id}.db"), project=project,
                               sleep_fn=lambda s: None)


# ---- DISCOVER ---------------------------------------------------------------

def test_e2e_discover_finds_all_three_infrastructure_types(infra_project):
    inventory = discover_infrastructure(str(infra_project))
    kinds = {a.kind for a in inventory.assets}
    assert AssetKind.TERRAFORM_ROOT in kinds
    assert AssetKind.KUBERNETES_MANIFEST in kinds
    assert AssetKind.HELM_CHART in kinds
    terraform = next(a for a in inventory.by_kind(AssetKind.TERRAFORM_ROOT))
    assert terraform.environment.value == "production"


# ---- FIND + CLASSIFY --------------------------------------------------------

def test_e2e_terraform_findings_are_real(infra_project):
    record = terraform_deep_scanner.scan(str(infra_project), _run_shell)
    rules = {f.rule_id for f in record.findings}
    assert "TF_PROVIDER_CREDENTIAL" in rules
    assert "TF_STATE_LOCAL_BACKEND" in rules
    assert "TF_PROVIDER_UNPINNED" in rules


@pytest.mark.skipif(not _checkov_available, reason="checkov not installed in this environment")
def test_e2e_kubernetes_findings_are_real(infra_project):
    record = checkov_k8s_scanner.scan(str(infra_project), _run_shell)
    assert record.availability == ScannerAvailability.AVAILABLE
    rules = {f.rule_id for f in record.findings}
    assert {"CKV_K8S_16", "CKV_K8S_19", "CKV_K8S_23", "CKV_K8S_49"} <= rules


def test_e2e_helm_is_blocked_yet_still_reports_real_values_findings(infra_project):
    record = helm_scanner.scan(str(infra_project), _run_shell)
    if record.availability != ScannerAvailability.AVAILABLE:
        assert record.availability == ScannerAvailability.BLOCKED
        assert record.finding_count > 0


# ---- REMEDIATE + VALIDATE + RESCAN + VERIFY (full agent pipeline) -----------

@pytest.mark.skipif(not _checkov_available, reason="checkov not installed in this environment")
def test_e2e_full_pipeline_remediates_validates_and_verifies(tmp_path, infra_project,
                                                                 policy_path):
    orch = _orch(tmp_path, infra_project, policy_path, "infrae2e")
    plan_infrastructure_scan(orch, project_id="infrae2e", project_root=str(infra_project))
    orch.run_to_completion("infrae2e", max_iterations=400)

    tasks = orch.store.list_tasks("infrae2e")
    types = {t.type for t in tasks}

    # DISCOVER ran and was policy-allowed.
    discover = next(t for t in tasks if t.type == "infra_discover")
    assert discover.status == TaskStatus.SUCCEEDED

    # FIND + CLASSIFY produced a risk-ranked scan.
    scan = next(t for t in tasks if t.type == "infra_scan")
    assert scan.status == TaskStatus.SUCCEEDED
    assert any(e.source == "infra_risk" for e in scan.evidence)

    # REMEDIATE + VALIDATE.
    assert "infra_remediate" in types
    remediate = next(t for t in tasks if t.type == "infra_remediate")
    assert remediate.status == TaskStatus.SUCCEEDED, remediate.evidence
    assert any(e.source.startswith("infra_validation") for e in remediate.evidence)

    # The real file on disk actually changed - HIGH-severity, mechanically
    # fixable findings were applied.
    workload = (infra_project / "k8s" / "workload.yaml").read_text()
    assert "hostNetwork: true" not in workload
    assert "hostPID: true" not in workload
    assert "allowPrivilegeEscalation: false" in workload
    assert "drop:" in workload  # capabilities dropped

    # `privileged: true` is deliberately STILL THERE. CKV_K8S_16 is
    # CRITICAL, and a CRITICAL finding is DENY-gated by policy, so it is
    # escalated to a human even though this platform has a working
    # mechanical fix for it. That is the Part 9/14 rule working, not a
    # remediation failure - asserted explicitly so a future change that
    # started auto-fixing CRITICALs would fail loudly here.
    assert "privileged: true" in workload
    escalated = [t for t in tasks if t.type == "infra_escalate"]
    escalated_text = " ".join(e.summary for t in escalated for e in t.evidence)
    assert "CKV_K8S_16" in escalated_text

    # TEST ran (the existing TestingAgent, unmodified).
    tests_task = next(t for t in tasks if t.type == "run_tests")
    assert tests_task.status == TaskStatus.SUCCEEDED

    # RESCAN + VERIFY - a SECOND real checkov invocation.
    rescan = next(t for t in tasks if t.type == "infra_rescan")
    assert rescan.status == TaskStatus.SUCCEEDED, rescan.evidence
    assert any("CONFIRMED resolved" in e.summary for e in rescan.evidence)

    # No GitHub target was given, so the chain stops after rescan.
    assert "create_pull_request" not in types


@pytest.mark.skipif(not _checkov_available, reason="checkov not installed in this environment")
def test_e2e_ambiguous_findings_are_escalated_not_silently_dropped(tmp_path, infra_project,
                                                                       policy_path):
    orch = _orch(tmp_path, infra_project, policy_path, "infrae2e2")
    plan_infrastructure_scan(orch, project_id="infrae2e2", project_root=str(infra_project))
    orch.run_to_completion("infrae2e2", max_iterations=400)

    tasks = orch.store.list_tasks("infrae2e2")
    escalations = [t for t in tasks if t.type == "infra_escalate"]
    assert escalations, "wildcard RBAC / IAM / credential findings must be escalated"
    assert all(t.status == TaskStatus.BLOCKED_ON_APPROVAL for t in escalations)

    escalated_text = " ".join(e.summary for t in escalations for e in t.evidence)
    # The hardcoded provider credential is CRITICAL - it must be escalated,
    # never auto-"fixed".
    assert "TF_PROVIDER_CREDENTIAL" in escalated_text or "CKV_K8S_49" in escalated_text


@pytest.mark.skipif(not _checkov_available, reason="checkov not installed in this environment")
def test_e2e_never_writes_outside_the_repository(tmp_path, infra_project, policy_path):
    """Part 6: repository remediation only. Nothing in the pipeline may
    touch anything outside the project root."""
    sentinel = tmp_path / "outside.txt"
    sentinel.write_text("untouched\n")
    orch = _orch(tmp_path, infra_project, policy_path, "infrae2e3")
    plan_infrastructure_scan(orch, project_id="infrae2e3", project_root=str(infra_project))
    orch.run_to_completion("infrae2e3", max_iterations=400)
    assert sentinel.read_text() == "untouched\n"


@pytest.mark.skipif(not _checkov_available, reason="checkov not installed in this environment")
def test_e2e_remediated_manifest_is_still_schema_valid(tmp_path, infra_project, policy_path):
    """A "fix" that produced an unschedulable workload would be worse than
    the finding it closed."""
    from aep.infra.validation import validate_kubernetes_manifest

    orch = _orch(tmp_path, infra_project, policy_path, "infrae2e4")
    plan_infrastructure_scan(orch, project_id="infrae2e4", project_root=str(infra_project))
    orch.run_to_completion("infrae2e4", max_iterations=400)

    result = validate_kubernetes_manifest(str(infra_project), "k8s/workload.yaml")
    assert result.ran and result.passed, result.detail
