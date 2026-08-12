"""Real end-to-end CI/CD & Deployment Intelligence (Phase 6 Part 15/16).

A disposable local project (a real git repo, real pytest, real CI
workflow file, real StateStore) is driven through:

    code change -> tests -> security -> CI discovery -> artifact ->
    release gates -> deployment -> verification

using the REAL Orchestrator/PolicyEngine/StateStore and REAL agents
(`testing_agent`, `security_scan_agent`, `ci_intelligence_agent`,
`deployment_agent`, `deployment_verification_agent`). The only simulated
boundary is the deployment TARGET itself: this sandbox has no live
Kubernetes cluster and no reachable GitHub Actions API (both verified
BLOCKED/UNAVAILABLE elsewhere in this test suite -
`tests/test_cicd_github_actions.py`,
`tests/test_deployment_kubernetes_provider.py`), so the deployment
provider is the real, deterministic `LocalFixtureDeploymentProvider` -
marked `LOCAL_FIXTURE`, never `AVAILABLE`, everywhere it appears in
evidence.

Part 16 requires two demonstrated scenarios, both included below:
  1. A deployment that fails verification, is diagnosed, found
     rollback-eligible, automatically rolled back, and confirmed
     recovered.
  2. A deployment where automatic remediation is NOT allowed (production)
     and the agent requests human approval instead of proceeding.
"""
from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path

import pytest

from aep.bootstrap import build_orchestrator
from aep.cicd.discovery import discover_pipeline
from aep.cicd.artifact import ArtifactKind, GateStatus, build_artifact
from aep.cicd.planner import plan_deployment
from aep.deployment.evidence import list_deployment_evidence
from aep.deployment.local_provider import LocalFixtureDeploymentProvider
from aep.deployment.models import DeploymentState
from aep.models import ProjectConfig, Task, TaskStatus
from aep.tools import build_deployment_tool


def _init_git_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-b", "main", str(path)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "aep@example.com"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "AEP Bot"], check=True)


@pytest.fixture()
def disposable_project(tmp_path: Path) -> Path:
    """A real, disposable project: application code, a passing test suite,
    and a real GitHub Actions workflow file - exactly the shape Part 15
    asks for."""
    repo = tmp_path / "cicd_demo_project"
    repo.mkdir()
    _init_git_repo(repo)
    (repo / "app.py").write_text(textwrap.dedent("""\
        def add(a, b):
            return a + b
        """))
    (repo / "test_app.py").write_text(textwrap.dedent("""\
        from app import add

        def test_add():
            assert add(2, 3) == 5
        """))
    workflows = repo / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(textwrap.dedent("""\
        name: CI
        on: [push]
        jobs:
          test:
            steps:
              - run: pytest -q
          security:
            needs: [test]
            steps:
              - run: gitleaks detect
          deploy:
            needs: [security]
            environment: production
            steps:
              - run: kubectl apply -f manifest.yaml
          rollback:
            steps:
              - name: Rollback on failure
                run: kubectl rollout undo deployment/app
        """))
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "initial commit"],
                    check=True, capture_output=True)
    return repo


def test_full_lifecycle_code_to_verified_deployment(disposable_project: Path, policy_path,
                                                       tmp_path: Path):
    repo = disposable_project
    commit_sha = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                                 check=True, capture_output=True, text=True).stdout.strip()

    project = ProjectConfig(id="e2e", name="e2e", repo_path=str(repo), policy_path=policy_path)
    orch = build_orchestrator(str(tmp_path / "state.db"), project,
                               deployment_state_dir=str(tmp_path / "deployments"))

    # ---- TEST: real pytest against the real repo -------------------------
    test_task = Task(id="test-1", type="run_tests", project_id="e2e", owner_agent="testing_agent",
                      payload={"project_root": str(repo)})
    orch.submit_graph("e2e", [test_task])
    orch.run_to_completion("e2e")
    tests_passed = orch.store.get_task("test-1").status == TaskStatus.SUCCEEDED
    assert tests_passed

    # ---- SECURITY: real deterministic secret scanner ----------------------
    sec_task = Task(id="sec-1", type="security_scan", project_id="e2e",
                     owner_agent="security_scan_agent", payload={"project_root": str(repo)})
    orch.submit_graph("e2e", [sec_task])
    orch.run_to_completion("e2e")
    secrets_clean = orch.store.get_task("sec-1").status == TaskStatus.SUCCEEDED
    assert secrets_clean  # no secrets committed in this disposable project

    # ---- CI: real, static workflow discovery (no network) -----------------
    ci_task = Task(id="ci-1", type="ci_inspect", project_id="e2e",
                    owner_agent="ci_intelligence_agent",
                    payload={"mode": "inspect", "project_root": str(repo)})
    orch.submit_graph("e2e", [ci_task])
    orch.run_to_completion("e2e")
    assert orch.store.get_task("ci-1").status == TaskStatus.SUCCEEDED
    pipeline = discover_pipeline(str(repo))
    assert pipeline.has_test and pipeline.has_security and pipeline.has_deploy
    assert pipeline.has_rollback_mechanism

    # ---- ARTIFACT: real content digest ------------------------------------
    content = (repo / "app.py").read_bytes()
    artifact = build_artifact(ArtifactKind.PACKAGE, commit_sha=commit_sha, build_id="build-e2e-1",
                               content=content)
    artifact.test_status = GateStatus.PASSED
    artifact.security_scan_status = GateStatus.PASSED
    assert artifact.is_deployable  # only true because BOTH real gates above passed

    # ---- RELEASE GATES + DEPLOYMENT (development - no approval needed) ---
    gates = dict(
        tests_passed=tests_passed, cve_scan_clean=True, secrets_clean=secrets_clean,
        sast_clean=True, iac_clean=True, ci_pipeline_green=pipeline.has_test,
        artifact_built=True, artifact_provenance_recorded=True,
        required_approvals_met=True, environment_policy_satisfied=True,
    )
    deploy_ids = plan_deployment(orch, "e2e", environment="development", commit_sha=commit_sha,
                                  artifact_id=artifact.artifact_id, gates=gates)
    orch.run_to_completion("e2e")
    deploy_task = orch.store.get_task(deploy_ids[0])
    assert deploy_task.status == TaskStatus.SUCCEEDED

    # ---- VERIFY (standalone re-verification via DeploymentVerificationAgent)
    reverify = Task(id="reverify-1", type="verify_deployment", project_id="e2e",
                     owner_agent="deployment_verification_agent",
                     payload={"deployment_ref": "development-app"})
    orch.submit_graph("e2e", [reverify])
    orch.run_to_completion("e2e")
    assert orch.store.get_task("reverify-1").status == TaskStatus.SUCCEEDED

    # ---- EVIDENCE survives being read back from a fresh StateStore -------
    from aep.state_store import StateStore
    fresh_store = StateStore(str(tmp_path / "state.db"))
    records = list_deployment_evidence(fresh_store, "e2e")
    assert any(r.final_state == DeploymentState.VERIFIED for r in records)
    verified = next(r for r in records if r.final_state == DeploymentState.VERIFIED)
    assert verified.provider == "local_fixture"
    assert verified.provider_status == "LOCAL_FIXTURE"  # never claims a live deployment


def test_deployment_failure_is_diagnosed_and_automatically_rolled_back(tmp_path: Path,
                                                                          policy_path):
    """Part 16 scenario 1: deployment fails -> agent diagnoses -> rollback
    determined safe -> rollback occurs -> verification confirms recovery."""
    project = ProjectConfig(id="rb", name="rb", repo_path=str(tmp_path), policy_path=policy_path)
    state_dir = str(tmp_path / "deployments")
    orch = build_orchestrator(str(tmp_path / "state.db"), project, deployment_state_dir=state_dir)

    # A GOOD version, deployed first (this becomes the rollback target).
    good_provider = LocalFixtureDeploymentProvider(state_dir)
    orch.tool_registry.register(build_deployment_tool(orch.store, lambda: good_provider))
    gates = dict(tests_passed=True, cve_scan_clean=True, secrets_clean=True, sast_clean=True,
                 iac_clean=True, ci_pipeline_green=True, artifact_built=True,
                 artifact_provenance_recorded=True, required_approvals_met=True,
                 environment_policy_satisfied=True)
    good_commit = "g00d0000v1v1"
    ids = plan_deployment(orch, "rb", environment="staging", commit_sha=good_commit,
                           artifact_id="artifact-good", gates=gates)
    orch.run_to_completion("rb")
    assert orch.store.get_task(ids[0]).status == TaskStatus.SUCCEEDED

    # A BAD version: health_check_fn is a deterministic test double that
    # fails ONLY for this specific commit, simulating a real crash-loop -
    # not a random flake (Part 16 needs this reproducible).
    bad_commit = "badc0mmit001"

    def health_check(state: dict) -> tuple:
        if state.get("commit_sha") == bad_commit:
            return False, "simulated CrashLoopBackOff for this build"
        return True, "healthy"

    bad_provider = LocalFixtureDeploymentProvider(state_dir, health_check_fn=health_check)
    orch.tool_registry.register(build_deployment_tool(orch.store, lambda: bad_provider))
    ids2 = plan_deployment(orch, "rb", environment="staging", commit_sha=bad_commit,
                            artifact_id="artifact-bad", gates=gates)
    orch.run_to_completion("rb")
    bad_task = orch.store.get_task(ids2[0])

    records = [r for r in list_deployment_evidence(orch.store, "rb")
               if r.artifact_id == "artifact-bad"]
    assert records, "no evidence recorded for the failing deployment"
    record = records[-1]
    # Diagnosed as a health failure, found rollback-eligible (staging,
    # not production - no approval needed), and actually rolled back.
    assert record.final_state == DeploymentState.ROLLED_BACK
    assert record.rollback_status == "ROLLED_BACK"
    # The TASK is reported SUCCEEDED because the agent correctly detected
    # the failure and safely recovered via rollback - the underlying
    # DEPLOYMENT is recorded as ROLLED_BACK (not VERIFIED), which is the
    # signal that actually matters and is asserted above.
    assert bad_task.status == TaskStatus.SUCCEEDED

    # Verification confirms recovery: the environment is back on the GOOD
    # commit, verified by a REAL provider.verify() call, not by assertion.
    verify = good_provider.verify("staging-app")
    assert verify.passed
    assert good_provider.rollout_status("staging-app")["commit_sha"] == good_commit


def test_production_deployment_requires_approval_not_auto_remediated(tmp_path: Path, policy_path):
    """Part 16 scenario 2: automatic remediation is NOT allowed (a
    production deployment) and the agent requests human approval instead
    of proceeding - it must never guess its way past this gate."""
    project = ProjectConfig(id="approval", name="approval", repo_path=str(tmp_path),
                             policy_path=policy_path)
    orch = build_orchestrator(str(tmp_path / "state.db"), project,
                               deployment_state_dir=str(tmp_path / "deployments"))
    gates = dict(tests_passed=True, cve_scan_clean=True, secrets_clean=True, sast_clean=True,
                 iac_clean=True, ci_pipeline_green=True, artifact_built=True,
                 artifact_provenance_recorded=True, required_approvals_met=True,
                 environment_policy_satisfied=True)
    ids = plan_deployment(orch, "approval", environment="production", commit_sha="prodcommit01",
                           artifact_id="artifact-prod", gates=gates)
    orch.run_to_completion("approval")
    task = orch.store.get_task(ids[0])
    assert task.status == TaskStatus.BLOCKED_ON_APPROVAL

    record = list_deployment_evidence(orch.store, "approval")[-1]
    assert record.final_state == DeploymentState.APPROVAL_PENDING
    assert record.provider == ""  # the provider was NEVER contacted - no fabricated deployment
