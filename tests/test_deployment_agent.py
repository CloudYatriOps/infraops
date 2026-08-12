"""DeploymentAgent + DeploymentVerificationAgent integration (Phase 6
Part 5/7/9/11), run through the REAL Orchestrator/PolicyEngine/StateStore
- only the deployment PROVIDER is the local fixture (never live infra)."""
from __future__ import annotations

from pathlib import Path

from aep.bootstrap import build_orchestrator
from aep.cicd.planner import plan_deployment
from aep.deployment.evidence import list_deployment_evidence
from aep.deployment.models import DeploymentState
from aep.models import ProjectConfig, Task, TaskStatus

_ALL_PASS = dict(
    tests_passed=True, cve_scan_clean=True, secrets_clean=True, sast_clean=True, iac_clean=True,
    ci_pipeline_green=True, artifact_built=True, artifact_provenance_recorded=True,
    required_approvals_met=True, environment_policy_satisfied=True,
)


def _orch(tmp_path: Path, policy_path: str):
    project = ProjectConfig(id="p1", name="p1", repo_path=str(tmp_path),
                             policy_path=policy_path)
    return build_orchestrator(str(tmp_path / "state.db"), project,
                               deployment_state_dir=str(tmp_path / "deployments"))


def test_development_deployment_deploys_and_verifies(tmp_path: Path, policy_path):
    orch = _orch(tmp_path, policy_path)
    task_ids = plan_deployment(orch, "p1", environment="development", commit_sha="a" * 12,
                                artifact_id="artifact-1", gates=_ALL_PASS)
    orch.run_to_completion("p1")
    task = orch.store.get_task(task_ids[0])
    assert task.status == TaskStatus.SUCCEEDED

    evidence = list_deployment_evidence(orch.store, "p1")
    assert len(evidence) == 1
    assert evidence[0].final_state == DeploymentState.VERIFIED
    assert evidence[0].release_gates_passed


def test_production_deployment_requires_approval_and_is_never_deployed(tmp_path: Path, policy_path):
    orch = _orch(tmp_path, policy_path)
    task_ids = plan_deployment(orch, "p1", environment="production", commit_sha="b" * 12,
                                artifact_id="artifact-2", gates=_ALL_PASS)
    orch.run_to_completion("p1")
    task = orch.store.get_task(task_ids[0])
    assert task.status == TaskStatus.BLOCKED_ON_APPROVAL

    evidence = list_deployment_evidence(orch.store, "p1")
    assert evidence[0].final_state == DeploymentState.APPROVAL_PENDING
    assert evidence[0].provider == ""  # never reached the provider at all


def test_deployment_blocked_when_release_gates_fail(tmp_path: Path, policy_path):
    orch = _orch(tmp_path, policy_path)
    bad_gates = dict(_ALL_PASS)
    bad_gates["secrets_clean"] = False
    task_ids = plan_deployment(orch, "p1", environment="development", commit_sha="c" * 12,
                                artifact_id="artifact-3", gates=bad_gates)
    orch.run_to_completion("p1")
    task = orch.store.get_task(task_ids[0])
    assert task.status != TaskStatus.SUCCEEDED

    evidence = list_deployment_evidence(orch.store, "p1")
    assert evidence[0].final_state == DeploymentState.BLOCKED
    assert evidence[0].provider == ""


def test_deployment_verification_agent_reverifies_an_existing_deployment(tmp_path: Path,
                                                                           policy_path):
    orch = _orch(tmp_path, policy_path)
    plan_deployment(orch, "p1", environment="staging", commit_sha="d" * 12,
                     artifact_id="artifact-4", gates=_ALL_PASS)
    orch.run_to_completion("p1")

    reverify = Task(id="reverify-1", type="verify_deployment", project_id="p1",
                     owner_agent="deployment_verification_agent",
                     payload={"deployment_ref": "staging-app"})
    orch.submit_graph("p1", [reverify])
    orch.run_to_completion("p1")
    task = orch.store.get_task("reverify-1")
    assert task.status == TaskStatus.SUCCEEDED
