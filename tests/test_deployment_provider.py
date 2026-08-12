"""Local fixture deployment provider (Phase 6 Part 7/8) - a REAL,
deterministic, disk-backed provider; no live cluster involved."""
from __future__ import annotations

from pathlib import Path

from aep.deployment.local_provider import LocalFixtureDeploymentProvider
from aep.deployment.provider import DeploymentProviderAvailability


def test_status_reports_local_fixture_never_available(tmp_path: Path):
    provider = LocalFixtureDeploymentProvider(str(tmp_path))
    avail, reason = provider.status()
    assert avail == DeploymentProviderAvailability.LOCAL_FIXTURE
    assert "no live cluster" in reason


def test_deploy_then_verify_reports_healthy(tmp_path: Path):
    provider = LocalFixtureDeploymentProvider(str(tmp_path), desired_replicas=3)
    plan = provider.plan("development", "abc123", "artifact-1")
    outcome = provider.deploy(plan)
    assert outcome.success
    assert outcome.deployment_ref == "development-app"
    verify = provider.verify(outcome.deployment_ref)
    assert verify.passed
    assert all(c.passed for c in verify.checks)


def test_verify_fails_on_a_real_state_mismatch(tmp_path: Path):
    provider = LocalFixtureDeploymentProvider(str(tmp_path), desired_replicas=3)
    plan = provider.plan("staging", "commit1", "artifact-1")
    outcome = provider.deploy(plan)
    provider.simulate_partial_rollout(outcome.deployment_ref, ready_replicas=1)
    verify = provider.verify(outcome.deployment_ref)
    assert not verify.passed
    readiness = next(c for c in verify.checks if c.name == "readiness")
    assert not readiness.passed


def test_rollback_restores_previous_version(tmp_path: Path):
    provider = LocalFixtureDeploymentProvider(str(tmp_path))
    plan1 = provider.plan("development", "commit1", "artifact-1")
    provider.deploy(plan1)
    plan2 = provider.plan("development", "commit2", "artifact-2")
    outcome2 = provider.deploy(plan2)
    assert provider.rollout_status(outcome2.deployment_ref)["commit_sha"] == "commit2"

    rollback = provider.rollback(outcome2.deployment_ref)
    assert rollback.success
    assert provider.rollout_status(outcome2.deployment_ref)["commit_sha"] == "commit1"


def test_rollback_without_history_fails_honestly(tmp_path: Path):
    provider = LocalFixtureDeploymentProvider(str(tmp_path))
    plan = provider.plan("development", "commit1", "artifact-1")
    outcome = provider.deploy(plan)
    rollback = provider.rollback(outcome.deployment_ref)
    assert not rollback.success
    assert "no prior version" in rollback.detail


def test_verify_on_unknown_deployment_ref_fails_honestly(tmp_path: Path):
    provider = LocalFixtureDeploymentProvider(str(tmp_path))
    verify = provider.verify("nonexistent-app")
    assert not verify.passed
    assert not verify.checks[0].passed
