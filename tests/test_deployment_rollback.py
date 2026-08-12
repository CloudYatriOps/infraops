"""Rollback planning (Phase 6 Part 10)."""
from __future__ import annotations

from aep.deployment.rollback import (
    CRITICAL_ROLLOUT_FAILURE, HEALTH_CHECK_FAILURE, SECURITY_GATE_FAILURE, UNKNOWN_FAILURE,
    classify_deployment_failure, plan_rollback,
)
from aep.models import FailureClass


def test_critical_rollout_failure_is_rollback_eligible():
    reason = classify_deployment_failure(FailureClass.DEPLOYMENT, verification_passed=False,
                                          rollout_status="APPLY_FAILED")
    assert reason == CRITICAL_ROLLOUT_FAILURE
    decision = plan_rollback(reason, "development")
    assert decision.eligible
    assert not decision.requires_approval


def test_health_check_failure_is_rollback_eligible():
    reason = classify_deployment_failure(FailureClass.HEALTH, verification_passed=False,
                                          rollout_status="ROLLOUT_COMPLETE")
    assert reason == HEALTH_CHECK_FAILURE
    decision = plan_rollback(reason, "staging")
    assert decision.eligible


def test_security_gate_failure_blocks_deployment_never_auto_rolled_back():
    reason = classify_deployment_failure(FailureClass.SECURITY, verification_passed=False,
                                          rollout_status="ROLLOUT_COMPLETE")
    assert reason == SECURITY_GATE_FAILURE
    decision = plan_rollback(reason, "development")
    assert not decision.eligible
    assert decision.requires_approval


def test_unknown_failure_requires_approval_never_auto_anything():
    decision = plan_rollback(UNKNOWN_FAILURE, "development")
    assert not decision.eligible
    assert decision.requires_approval


def test_production_rollback_of_an_eligible_failure_still_requires_approval():
    decision = plan_rollback(CRITICAL_ROLLOUT_FAILURE, "production")
    assert decision.eligible
    assert decision.requires_approval  # production always needs a human unless emergency policy allows


def test_development_rollback_of_an_eligible_failure_does_not_require_approval():
    decision = plan_rollback(CRITICAL_ROLLOUT_FAILURE, "development")
    assert decision.eligible
    assert not decision.requires_approval
