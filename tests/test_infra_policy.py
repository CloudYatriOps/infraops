"""Infrastructure policy gates (Phase 5 Part 14/16) - the EXISTING
PolicyEngine and src/aep/config/policy.yaml, extended. No new policy mechanism."""
from __future__ import annotations

from aep.models import PolicyDecisionType
from aep.policy import PolicyEngine


def test_terraform_apply_requires_approval(policy_path):
    engine = PolicyEngine.from_yaml(policy_path)
    assert (engine.evaluate("infra.terraform_apply", {}).decision
            == PolicyDecisionType.REQUIRE_APPROVAL)


def test_production_iam_modification_requires_approval(policy_path):
    engine = PolicyEngine.from_yaml(policy_path)
    assert (engine.evaluate("infra.iam_modify", {"environment": "production"}).decision
            == PolicyDecisionType.REQUIRE_APPROVAL)


def test_production_network_modification_requires_approval(policy_path):
    engine = PolicyEngine.from_yaml(policy_path)
    assert (engine.evaluate("infra.network_modify", {"environment": "production"}).decision
            == PolicyDecisionType.REQUIRE_APPROVAL)


def test_non_production_iam_falls_through_to_deny_which_is_stricter(policy_path):
    """Deliberate asymmetry, documented in src/aep/config/policy.yaml: production
    is called out explicitly because Part 14 names it; every other
    environment matches no rule and hits deny-by-default."""
    engine = PolicyEngine.from_yaml(policy_path)
    decision = engine.evaluate("infra.iam_modify", {"environment": "development"})
    assert decision.decision == PolicyDecisionType.DENY
    assert decision.matched_rule is None  # default posture, not an explicit rule


def test_resource_deletion_is_denied_not_merely_approval_gated(policy_path):
    engine = PolicyEngine.from_yaml(policy_path)
    for action in ("infra.resource_delete", "infra.terraform_destroy",
                    "infra.cluster_resource_delete"):
        assert engine.evaluate(action, {}).decision == PolicyDecisionType.DENY


def test_credential_rotation_requires_approval(policy_path):
    engine = PolicyEngine.from_yaml(policy_path)
    assert (engine.evaluate("infra.credential_rotate", {}).decision
            == PolicyDecisionType.REQUIRE_APPROVAL)


def test_read_only_discovery_is_allowed(policy_path):
    engine = PolicyEngine.from_yaml(policy_path)
    assert (engine.evaluate("infra.discovery", {"read_only": True}).decision
            == PolicyDecisionType.ALLOW)
    assert (engine.evaluate("infra.cloud_discovery",
                             {"provider": "aws", "read_only": True}).decision
            == PolicyDecisionType.ALLOW)


def test_non_read_only_discovery_does_not_inherit_the_allowance(policy_path):
    """The `read_only: true` condition means the allowance cannot silently
    widen if the capability ever changes."""
    engine = PolicyEngine.from_yaml(policy_path)
    assert (engine.evaluate("infra.discovery", {"read_only": False}).decision
            == PolicyDecisionType.DENY)


def test_repository_fixes_are_allowed(policy_path):
    engine = PolicyEngine.from_yaml(policy_path)
    assert engine.evaluate("infra.repository_fix", {}).decision == PolicyDecisionType.ALLOW


def test_infra_finding_severity_maps_to_the_expected_decisions(policy_path):
    engine = PolicyEngine.from_yaml(policy_path)
    expected = {
        "critical": PolicyDecisionType.DENY,
        "high": PolicyDecisionType.REQUIRE_APPROVAL,
        "medium": PolicyDecisionType.WARN,
        "low": PolicyDecisionType.ALLOW,
        "info": PolicyDecisionType.ALLOW,
    }
    for severity, decision in expected.items():
        assert engine.evaluate("infra.finding", {"severity": severity}).decision == decision


def test_phase_1_to_4_policy_decisions_are_unchanged(policy_path):
    """Phase 5 adds rules; it must not alter any existing decision."""
    engine = PolicyEngine.from_yaml(policy_path)
    assert engine.evaluate("git.push", {"branch": "main"}).decision == PolicyDecisionType.DENY
    assert engine.evaluate("secret.commit", {}).decision == PolicyDecisionType.DENY
    assert (engine.evaluate("security.finding", {"severity": "critical"}).decision
            == PolicyDecisionType.DENY)
    assert (engine.evaluate("security.finding", {"severity": "high"}).decision
            == PolicyDecisionType.REQUIRE_APPROVAL)
    assert (engine.evaluate("dependency.upgrade", {"major_version_bump": True}).decision
            == PolicyDecisionType.WARN)
    assert engine.evaluate("git.commit", {}).decision == PolicyDecisionType.ALLOW
