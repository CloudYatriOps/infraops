"""Policy integration (Phase 4 Part 8/13) - the EXISTING PolicyEngine and
config/policy.yaml, extended with `security.finding` rules; no new policy
mechanism. Also confirms the pre-existing, unconditional `secret.commit`
DENY rule (Phase 1) is exactly what SecurityAgent leans on for "secret
detected -> block commit"."""
from __future__ import annotations

from aep.models import PolicyDecisionType
from aep.policy import PolicyEngine


def test_critical_finding_is_denied(policy_path):
    engine = PolicyEngine.from_yaml(policy_path)
    decision = engine.evaluate("security.finding", {"severity": "critical"})
    assert decision.decision == PolicyDecisionType.DENY


def test_high_finding_requires_approval(policy_path):
    engine = PolicyEngine.from_yaml(policy_path)
    decision = engine.evaluate("security.finding", {"severity": "high"})
    assert decision.decision == PolicyDecisionType.REQUIRE_APPROVAL


def test_medium_finding_is_a_warning(policy_path):
    engine = PolicyEngine.from_yaml(policy_path)
    decision = engine.evaluate("security.finding", {"severity": "medium"})
    assert decision.decision == PolicyDecisionType.WARN


def test_low_and_info_findings_are_allowed_explicitly(policy_path):
    engine = PolicyEngine.from_yaml(policy_path)
    assert engine.evaluate("security.finding", {"severity": "low"}).decision == PolicyDecisionType.ALLOW
    assert engine.evaluate("security.finding", {"severity": "info"}).decision == PolicyDecisionType.ALLOW


def test_low_and_info_are_explicit_allow_not_default_posture_deny(policy_path):
    # This is the actual point of Part 8's explicit LOW/INFO allow rules:
    # without them, `default_posture: deny` would silently route every
    # low-severity finding into the same escalation path as CRITICAL.
    engine = PolicyEngine.from_yaml(policy_path)
    decision = engine.evaluate("security.finding", {"severity": "low"})
    assert decision.matched_rule == "ALLOW:security.finding"
    assert decision.matched_rule is not None  # i.e. not the default-posture fallback


def test_secret_commit_is_still_unconditionally_denied(policy_path):
    # Pre-existing Phase 1 rule, reused (not duplicated) by SecurityAgent's
    # secret remediation path.
    engine = PolicyEngine.from_yaml(policy_path)
    decision = engine.evaluate("secret.commit", {})
    assert decision.decision == PolicyDecisionType.DENY


def test_git_history_inspection_is_explicitly_allowed_not_denied_by_default(policy_path):
    engine = PolicyEngine.from_yaml(policy_path)
    decision = engine.evaluate("security.git_history_inspection", {})
    assert decision.decision == PolicyDecisionType.ALLOW


def test_unmapped_severity_falls_back_to_default_deny_posture(policy_path):
    # Sanity check that the fallback behavior itself still works as
    # documented - an unrecognized severity value has no explicit rule.
    engine = PolicyEngine.from_yaml(policy_path)
    decision = engine.evaluate("security.finding", {"severity": "not-a-real-severity"})
    assert decision.decision == PolicyDecisionType.DENY
    assert decision.matched_rule is None
