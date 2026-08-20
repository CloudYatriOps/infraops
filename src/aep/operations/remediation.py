"""Part 6: operational remediation decision engine.

Reuses the EXISTING `PolicyEngine` unmodified in mechanism (same
deny > require_approval > warn > allow > default_posture evaluation order
every other phase uses) - this module only decides WHICH fixed
`operations.*` action literal a given remediation candidate maps to, and
never builds that literal from incident/finding/log content (Part 6:
"reuse the existing policy engine; do not create a parallel policy
system").

Candidate action catalog, matching the Part 6 buckets literally:

  READ-ONLY        collect_logs, inspect_metrics, inspect_deployment,
                    inspect_configuration, compare_versions,
                    inspect_dependencies
  SAFE AUTOMATION   restart_workload (non-prod), retry_job, rollback,
                    create_issue, create_diagnostic_task, trigger_cicd
  REQUIRE APPROVAL  restart_workload (prod), rollback (prod), scale,
                    configuration_change, secret_rotation, database_change,
                    infrastructure_mutation
  DENY              destructive_action, delete_production_data,
                    disable_security_control, bypass_policy,
                    force_push_protected_branch
"""
from __future__ import annotations

from ..models import PolicyDecision, PolicyDecisionType
from .models import RemediationAction, RemediationCategory

# Fixed catalog: (action_id -> (category, fixed policy_action literal,
# description, reversible)). Every policy_action string below is passed
# VERBATIM to `ctx.policy.evaluate()` - never interpolated with untrusted
# content - matching the threat-model discipline every prior phase enforces.
_CATALOG: dict[str, tuple[RemediationCategory, str, str, bool]] = {
    "collect_logs": (RemediationCategory.READ_ONLY, "operations.collect_logs",
                      "collect logs for the affected service", True),
    "inspect_metrics": (RemediationCategory.READ_ONLY, "operations.inspect_metrics",
                         "inspect metrics for the affected service", True),
    "inspect_deployment": (RemediationCategory.READ_ONLY, "operations.inspect_deployment",
                            "inspect current deployment/version state", True),
    "inspect_configuration": (RemediationCategory.READ_ONLY, "operations.inspect_configuration",
                               "inspect current configuration", True),
    "compare_versions": (RemediationCategory.READ_ONLY, "operations.compare_versions",
                          "compare current vs previous deployed version", True),
    "inspect_dependencies": (RemediationCategory.READ_ONLY, "operations.inspect_dependencies",
                              "inspect service dependency graph", True),

    "restart_workload_nonprod": (RemediationCategory.SAFE_AUTOMATION, "operations.restart_workload",
                                  "restart a failed non-production workload", True),
    "retry_job": (RemediationCategory.SAFE_AUTOMATION, "operations.retry_job",
                  "retry a failed job", True),
    "rollback_nonprod": (RemediationCategory.SAFE_AUTOMATION, "operations.rollback",
                         "roll back a verified bad deployment (non-production)", True),
    "create_issue": (RemediationCategory.SAFE_AUTOMATION, "operations.create_issue",
                      "create a GitHub issue/PR describing the incident", True),
    "create_diagnostic_task": (RemediationCategory.SAFE_AUTOMATION, "operations.create_diagnostic_task",
                                "create a follow-up diagnostic task", True),
    "trigger_cicd": (RemediationCategory.SAFE_AUTOMATION, "operations.trigger_cicd",
                      "trigger an existing CI/CD workflow", True),

    "restart_workload_prod": (RemediationCategory.REQUIRE_APPROVAL, "operations.restart_workload",
                               "restart a production workload", True),
    "rollback_prod": (RemediationCategory.REQUIRE_APPROVAL, "operations.rollback",
                      "roll back a production deployment", True),
    "scale": (RemediationCategory.REQUIRE_APPROVAL, "operations.scale",
              "change scaling/replica count", True),
    "configuration_change": (RemediationCategory.REQUIRE_APPROVAL, "operations.configuration_change",
                              "change service configuration", True),
    "secret_rotation": (RemediationCategory.REQUIRE_APPROVAL, "operations.secret_rotation",
                         "rotate a secret/credential", True),
    "database_change": (RemediationCategory.REQUIRE_APPROVAL, "operations.database_change",
                         "make a database change", False),
    "infrastructure_mutation": (RemediationCategory.REQUIRE_APPROVAL, "operations.infrastructure_mutation",
                                 "mutate live infrastructure", False),

    "destructive_action": (RemediationCategory.DENY, "operations.destructive_action",
                            "an action without an explicit recovery guarantee", False),
    "delete_production_data": (RemediationCategory.DENY, "operations.delete_production_data",
                                "delete production data", False),
    "disable_security_control": (RemediationCategory.DENY, "operations.disable_security_control",
                                  "disable a security control", False),
    "bypass_policy": (RemediationCategory.DENY, "operations.bypass_policy",
                       "bypass the policy engine", False),
    "force_push_protected_branch": (RemediationCategory.DENY, "operations.force_push_protected_branch",
                                     "force-push a protected branch", False),
}


def build_action(action_id: str) -> RemediationAction:
    if action_id not in _CATALOG:
        raise KeyError(f"unknown operations remediation action_id: {action_id!r}")
    category, policy_action, description, reversible = _CATALOG[action_id]
    return RemediationAction(action_id=action_id, category=category, policy_action=policy_action,
                              description=description, reversible=reversible)


def restart_action_for(environment: str) -> RemediationAction:
    return build_action("restart_workload_prod" if environment == "production"
                         else "restart_workload_nonprod")


def rollback_action_for(environment: str) -> RemediationAction:
    return build_action("rollback_prod" if environment == "production" else "rollback_nonprod")


def evaluate_with_policy(policy, action: RemediationAction, context: dict | None = None) -> PolicyDecision:
    """The single call site that consults the EXISTING PolicyEngine for an
    operations remediation action - `action.policy_action` is always the
    fixed literal from the catalog above, never rebuilt from finding/log
    content."""
    return policy.evaluate(action.policy_action, context or {})


def is_authorized(decision: PolicyDecision) -> bool:
    """A DENY or an unresolved REQUIRE_APPROVAL both mean "do not execute
    now" - only an explicit ALLOW authorizes immediate automated
    execution. WARN is treated as authorized-with-a-recorded-warning,
    matching how Phase 4/5's `security.finding`/`infra.finding` WARN rules
    are treated (tracked, not blocking)."""
    return decision.decision in (PolicyDecisionType.ALLOW, PolicyDecisionType.WARN)
