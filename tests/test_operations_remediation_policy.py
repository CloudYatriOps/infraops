from aep.models import PolicyDecisionType
from aep.operations.remediation import (
    build_action, evaluate_with_policy, is_authorized, restart_action_for, rollback_action_for,
)
from aep.policy import PolicyEngine


def _policy():
    return PolicyEngine.from_yaml("src/aep/config/policy.yaml")


def test_readonly_actions_are_allowed():
    policy = _policy()
    action = build_action("collect_logs")
    decision = evaluate_with_policy(policy, action)
    assert decision.decision == PolicyDecisionType.ALLOW
    assert is_authorized(decision)


def test_rollback_allowed_in_development_denied_by_default_elsewhere():
    policy = _policy()
    action = rollback_action_for("development")
    assert evaluate_with_policy(policy, action, {"environment": "development"}).decision == \
        PolicyDecisionType.ALLOW


def test_restart_in_production_requires_approval():
    policy = _policy()
    action = restart_action_for("production")
    decision = evaluate_with_policy(policy, action, {"environment": "production"})
    assert decision.decision == PolicyDecisionType.REQUIRE_APPROVAL
    assert not is_authorized(decision)


def test_rollback_in_production_requires_approval():
    policy = _policy()
    action = rollback_action_for("production")
    decision = evaluate_with_policy(policy, action, {"environment": "production"})
    assert decision.decision == PolicyDecisionType.REQUIRE_APPROVAL


def test_destructive_actions_are_denied():
    policy = _policy()
    for action_id in ("destructive_action", "delete_production_data", "disable_security_control",
                       "bypass_policy", "force_push_protected_branch"):
        action = build_action(action_id)
        decision = evaluate_with_policy(policy, action)
        assert decision.decision == PolicyDecisionType.DENY, action_id
        assert not is_authorized(decision)


def test_database_and_infra_mutation_require_approval():
    policy = _policy()
    for action_id in ("database_change", "infrastructure_mutation", "secret_rotation",
                       "configuration_change", "scale"):
        action = build_action(action_id)
        decision = evaluate_with_policy(policy, action)
        assert decision.decision == PolicyDecisionType.REQUIRE_APPROVAL, action_id
