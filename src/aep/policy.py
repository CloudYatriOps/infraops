"""Deny-by-default policy engine.

Loads declarative rules from YAML. Evaluation order is fixed and documented
in ARCHITECTURE.md §8: explicit DENY first (unconditional, cannot be
overridden by anything computed at runtime), then REQUIRE_APPROVAL, then
WARN, then the project's default posture.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

import yaml

from .models import PolicyDecision, PolicyDecisionType


@dataclass
class Rule:
    action: str
    when: dict


def _matches(rule_when: dict, context: dict) -> bool:
    for key, expected in (rule_when or {}).items():
        if context.get(key) != expected:
            return False
    return True


class PolicyEngine:
    def __init__(self, deny: list[Rule], require_approval: list[Rule],
                 warn: list[Rule], allow: list[Rule], default_posture: str = "deny"):
        self.deny = deny
        self.require_approval = require_approval
        self.warn = warn
        self.allow = allow
        self.default_posture = default_posture

    @classmethod
    def from_yaml(cls, path: str) -> "PolicyEngine":
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        def _rules(key: str) -> list[Rule]:
            return [Rule(action=r["action"], when=r.get("when", {})) for r in data.get(key, [])]
        return cls(
            deny=_rules("deny"),
            require_approval=_rules("require_approval"),
            warn=_rules("warn"),
            allow=_rules("allow"),
            default_posture=data.get("default_posture", "deny"),
        )

    def evaluate(self, action: str, context: Optional[dict] = None) -> PolicyDecision:
        context = context or {}
        for bucket, decision_type in (
            (self.deny, PolicyDecisionType.DENY),
            (self.require_approval, PolicyDecisionType.REQUIRE_APPROVAL),
            (self.warn, PolicyDecisionType.WARN),
        ):
            for rule in bucket:
                if rule.action == action and _matches(rule.when, context):
                    return PolicyDecision(
                        action=action,
                        decision=decision_type,
                        matched_rule=f"{decision_type.value}:{rule.action}",
                        reason=f"matched explicit {decision_type.value} rule for '{action}'",
                    )
        for rule in self.allow:
            if rule.action == action and _matches(rule.when, context):
                return PolicyDecision(
                    action=action,
                    decision=PolicyDecisionType.ALLOW,
                    matched_rule=f"ALLOW:{rule.action}",
                    reason=f"matched explicit ALLOW rule for '{action}'",
                )
        # No explicit rule matched: fall back to default posture.
        default = PolicyDecisionType.ALLOW if self.default_posture == "allow" else PolicyDecisionType.DENY
        return PolicyDecision(
            action=action,
            decision=default,
            matched_rule=None,
            reason=f"no explicit rule matched; default posture is '{self.default_posture}'",
        )
