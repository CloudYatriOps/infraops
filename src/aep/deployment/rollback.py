"""Rollback planning (Phase 6 Part 10/11).

Decides ELIGIBILITY only - it never calls `provider.rollback()` itself,
and it never invents an infrastructure-destroying action. The actual
policy gate (production requires approval unless the narrow
`deployment.emergency_rollback` carve-out matches - see
`src/aep/config/policy.yaml`) is evaluated by the caller (the deployment agent)
through the EXISTING `PolicyEngine`, with a fixed action-string literal;
this module only classifies *why* a deployment failed and returns a
recommendation, so the policy-evaluation call site stays the single place
that can say "REQUIRE_APPROVAL wins."
"""
from __future__ import annotations

from dataclasses import dataclass

from ..models import FailureClass

CRITICAL_ROLLOUT_FAILURE = "critical_rollout_failure"
HEALTH_CHECK_FAILURE = "health_check_failure"
SECURITY_GATE_FAILURE = "security_gate_failure"
UNKNOWN_FAILURE = "unknown_failure"


@dataclass
class RollbackDecision:
    eligible: bool
    reason_code: str
    detail: str
    requires_approval: bool  # even when eligible, may still need a human per environment policy


def classify_deployment_failure(failure_class: FailureClass, verification_passed: bool,
                                  rollout_status: str) -> str:
    """Maps a deployment/verification outcome to one of the Part 10 reason
    codes. `SECURITY_GATE_FAILURE` and `CRITICAL_ROLLOUT_FAILURE` are
    distinguished from a generic `UNKNOWN_FAILURE` because they drive
    OPPOSITE recommendations below (security -> never roll back
    automatically, roll forward with a fix instead; critical rollout ->
    roll back automatically is exactly the safe move)."""
    if failure_class == FailureClass.SECURITY:
        return SECURITY_GATE_FAILURE
    if failure_class in (FailureClass.DEPLOYMENT, FailureClass.INFRASTRUCTURE) or \
            rollout_status in ("APPLY_FAILED", "ROLLOUT_FAILED"):
        return CRITICAL_ROLLOUT_FAILURE
    if failure_class == FailureClass.HEALTH or not verification_passed:
        return HEALTH_CHECK_FAILURE
    return UNKNOWN_FAILURE


def plan_rollback(reason_code: str, environment: str) -> RollbackDecision:
    """Part 10's three examples, applied literally:

      CRITICAL rollout failure -> rollback eligible
      Health check failure     -> rollback eligible
      Security gate failure    -> deployment BLOCKED (never auto-rolled-back
                                   as if that fixes anything - it needs a
                                   human decision on the finding itself)
      Unknown failure          -> REQUIRE_APPROVAL (never auto-anything)

    `requires_approval` layers the Part 11 environment policy on top:
    production always requires approval regardless of eligibility, EXCEPT
    that this function does not itself grant the emergency bypass - it
    only says whether the situation is a *candidate* for the
    `deployment.emergency_rollback` policy action; the caller must still
    evaluate that action through `PolicyEngine` before rolling anything
    back automatically."""
    if reason_code == SECURITY_GATE_FAILURE:
        return RollbackDecision(
            eligible=False, reason_code=reason_code,
            detail="a security gate failure is not remediated by rolling back the deployment - "
                   "the finding itself needs a human decision; deployment stays BLOCKED",
            requires_approval=True,
        )
    if reason_code in (CRITICAL_ROLLOUT_FAILURE, HEALTH_CHECK_FAILURE):
        requires_approval = environment == "production"
        return RollbackDecision(
            eligible=True, reason_code=reason_code,
            detail=f"{reason_code} is an explicit auto-rollback-eligible condition (Part 10)"
                   + (" - production still requires approval unless the emergency policy "
                      "action explicitly allows it" if requires_approval else ""),
            requires_approval=requires_approval,
        )
    return RollbackDecision(
        eligible=False, reason_code=UNKNOWN_FAILURE,
        detail="no recognized rollback-eligible condition matched - refusing to guess; a human "
               "must decide",
        requires_approval=True,
    )
