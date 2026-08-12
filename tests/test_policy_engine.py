from aep.models import PolicyDecisionType
from aep.policy import PolicyEngine


def test_deny_beats_everything(policy_path):
    engine = PolicyEngine.from_yaml(policy_path)
    decision = engine.evaluate("git.push", {"branch": "main"})
    assert decision.decision == PolicyDecisionType.DENY


def test_require_approval_for_production_deploy(policy_path):
    engine = PolicyEngine.from_yaml(policy_path)
    decision = engine.evaluate("deploy.apply", {"environment": "production"})
    assert decision.decision == PolicyDecisionType.REQUIRE_APPROVAL


def test_warn_allows_but_flags(policy_path):
    engine = PolicyEngine.from_yaml(policy_path)
    decision = engine.evaluate("dependency.upgrade", {"major_version_bump": True})
    assert decision.decision == PolicyDecisionType.WARN


def test_explicit_allow(policy_path):
    engine = PolicyEngine.from_yaml(policy_path)
    decision = engine.evaluate("git.branch", {"branch": "aep/fix-123"})
    assert decision.decision == PolicyDecisionType.ALLOW


def test_default_posture_is_deny_for_unknown_action(policy_path):
    engine = PolicyEngine.from_yaml(policy_path)
    decision = engine.evaluate("some.totally_unknown_action", {})
    assert decision.decision == PolicyDecisionType.DENY


def test_default_posture_can_be_allow():
    engine = PolicyEngine(deny=[], require_approval=[], warn=[], allow=[], default_posture="allow")
    decision = engine.evaluate("anything", {})
    assert decision.decision == PolicyDecisionType.ALLOW
