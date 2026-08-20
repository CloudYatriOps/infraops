"""Introspects the REAL existing AEP surface (tool capabilities, security
scanners, policy actions) so `SkillRegistry` self-validation (Stage B
Part 16) can reject a skill claiming a tool/capability/policy action that
does not actually exist in this platform - never trusting a skill
definition's own say-so.

`REAL_SCANNER_IDS` is imported directly from the scanner modules
themselves (not re-typed as string literals) so it can never silently
drift from the real implementations in `src/aep/security/scanners/`.
`REAL_TOOL_CAPABILITIES` is a fixed enumeration of the capability strings
actually registered by `src/aep/tools/*.py` (via `bootstrap.py`'s
`build_tool_registry`) - kept as a literal set rather than introspecting a
live `ToolRegistry` instance because constructing one requires a
`StateStore`/DB connection, and Stage B's skill self-validation must work
with zero network/DB dependency (e.g. inside `SkillRegistry.publish`,
called from a fast unit test). `tests/test_skills_self_validation.py`
cross-checks this list against a live-wired `ToolRegistry` to keep it
honest.
"""
from __future__ import annotations

from ..policy import PolicyEngine
from ..security.scanners import checkov_scanner, gitleaks_scanner, semgrep_scanner, trivy_scanner

REAL_TOOL_CAPABILITIES: frozenset[str] = frozenset({
    "git.branch", "git.commit", "git.current_branch", "git.diff", "git.log", "git.push_local",
    "filesystem.list", "filesystem.read", "filesystem.write",
    "shell.run",
    "github.comment_on_pr", "github.create_issue", "github.create_pull_request",
    "github.get_branch", "github.get_combined_status", "github.get_commit",
    "github.get_pull_request", "github.get_repo", "github.get_workflow_run",
    "github.list_branches", "github.list_check_runs", "github.list_commits",
    "github.list_issues", "github.list_pr_comments", "github.list_pr_files",
    "github.list_pull_requests", "github.list_workflow_run_jobs", "github.list_workflow_runs",
    "github.push_branch", "github.update_pull_request",
    "deployment.deploy", "deployment.list_evidence", "deployment.plan",
    "deployment.record_evidence", "deployment.rollback", "deployment.rollout_status",
    "deployment.verify",
    "operations.find_similar_incidents", "operations.list_incidents", "operations.record_incident",
})

REAL_SCANNER_IDS: frozenset[str] = frozenset({
    gitleaks_scanner.SCANNER_ID,
    semgrep_scanner.SCANNER_ID,
    checkov_scanner.SCANNER_ID,
    trivy_scanner.SCANNER_ID,
})

# Verification checks a skill's `required_checks`/`verification_rules` may
# reference: real scanner ids, plus a fixed set of other real, already-
# implemented verification mechanisms in the platform (the migration
# runner's apply/drift-report cycle, pytest, the policy engine itself, and
# CI status checks via the real GitHub tool). Nothing invented here that
# doesn't map to actual existing code.
KNOWN_VERIFICATION_CHECKS: frozenset[str] = REAL_SCANNER_IDS | frozenset({
    "pytest",
    "migration_runner.apply_pending",
    "migration_runner.drift_report",
    "policy_engine.evaluate",
    "github.get_combined_status",
    "deployment.verify",
    "git.diff",
})


def real_policy_actions(policy_path: str) -> frozenset[str]:
    """Every action string declared anywhere in the real `policy.yaml`
    (all four buckets), read fresh from disk each call - never cached
    across a process that might reload policy at a different path."""
    engine = PolicyEngine.from_yaml(policy_path)
    actions: set[str] = set()
    for bucket in (engine.deny, engine.require_approval, engine.warn, engine.allow):
        for rule in bucket:
            actions.add(rule.action)
    return frozenset(actions)
