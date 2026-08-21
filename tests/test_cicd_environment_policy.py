"""Deployment/environment policy gates (Phase 6 Part 11) - the EXISTING
PolicyEngine and src/aep/config/policy.yaml, extended (same pattern as
tests/test_infra_policy.py for Phase 5)."""
from __future__ import annotations

from aep.models import PolicyDecisionType
from aep.policy import PolicyEngine


def test_production_deploy_requires_approval(policy_path):
    engine = PolicyEngine.from_yaml(policy_path)
    assert (engine.evaluate("deployment.deploy", {"environment": "production"}).decision
            == PolicyDecisionType.REQUIRE_APPROVAL)


def test_development_and_staging_deploy_are_allowed(policy_path):
    engine = PolicyEngine.from_yaml(policy_path)
    for env in ("development", "staging"):
        assert (engine.evaluate("deployment.deploy", {"environment": env}).decision
                == PolicyDecisionType.ALLOW)


def test_production_rollback_requires_approval(policy_path):
    engine = PolicyEngine.from_yaml(policy_path)
    assert (engine.evaluate("deployment.rollback", {"environment": "production"}).decision
            == PolicyDecisionType.REQUIRE_APPROVAL)


def test_non_production_rollback_is_allowed(policy_path):
    engine = PolicyEngine.from_yaml(policy_path)
    for env in ("development", "staging"):
        assert (engine.evaluate("deployment.rollback", {"environment": env}).decision
                == PolicyDecisionType.ALLOW)


def test_emergency_rollback_is_a_separate_narrowly_scoped_action(policy_path):
    engine = PolicyEngine.from_yaml(policy_path)
    allowed = engine.evaluate("deployment.emergency_rollback",
                               {"environment": "production", "reason": "critical_rollout_failure"})
    assert allowed.decision == PolicyDecisionType.ALLOW

    # A DIFFERENT reason does NOT inherit the emergency allowance - the
    # carve-out only matches the exact condition it names.
    not_allowed = engine.evaluate("deployment.emergency_rollback",
                                   {"environment": "production", "reason": "unknown_failure"})
    assert not_allowed.decision == PolicyDecisionType.DENY


def test_infra_destroy_actions_remain_denied_untouched_by_phase_6(policy_path):
    """Regression guard: Phase 6 must not have weakened Phase 5's
    destructive-infrastructure DENY rules."""
    engine = PolicyEngine.from_yaml(policy_path)
    for action in ("infra.resource_delete", "infra.terraform_destroy",
                    "infra.cluster_resource_delete"):
        assert engine.evaluate(action, {}).decision == PolicyDecisionType.DENY


def test_credential_rotation_still_requires_approval(policy_path):
    engine = PolicyEngine.from_yaml(policy_path)
    assert (engine.evaluate("infra.credential_rotate", {}).decision
            == PolicyDecisionType.REQUIRE_APPROVAL)
