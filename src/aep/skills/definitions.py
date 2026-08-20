"""Canonical AEP skill definitions (Stage B Part 5): real, concise
structured data - not giant prompt blobs - one for each of the 18 initial
skills the spec requires. Every `allowed_tools`/`required_checks`/
`prohibited_actions` entry below is a REAL string that exists in this
platform (`known_capabilities.py`'s introspected sets) - `SkillRegistry.
publish()` self-validates this at publish time, so a typo or an invented
capability here fails loudly at seed time rather than silently shipping.

These are registered through the REAL `SkillRegistry`/repository path by
`seed_canonical_skills()` below - never a hardcoded bypass that lets an
agent read this module directly instead of going through the registry.

Honesty notes baked into the content itself (not just prose elsewhere):
  * `terraform`/`kubernetes`/`helm` skills describe discovery/validation/
    remediation-boundary procedures only - they never claim a live
    cluster/cloud apply capability (see `prohibited_actions` naming the
    exact destructive policy actions from config/policy.yaml that are
    DENY, e.g. "infra.terraform_apply" is NOT here because Phase 5 never
    calls it; "infra.resource_delete"/"infra.terraform_destroy"/
    "infra.cluster_resource_delete" ARE listed as prohibited because they
    are real DENY-bucket actions this skill must never claim to perform).
  * `postgresql`/`database` skills require migration-only schema change
    (matching Stage A/A.5's actual `src/aep/db/migrations.py` discipline),
    never a direct schema-mutating DDL statement outside the runner.
  * `security`/`sast`/`dependency-cve`/`secrets` skills reference the
    REAL scanner ids (`gitleaks`, `semgrep`, `checkov`, `trivy`) - they do
    not duplicate scanner logic, only require that the real scanner run
    and be verified.
"""
from __future__ import annotations

from .models import RiskLevel, Skill, SkillDependency, SkillVersion
from .registry import SkillRegistry


def _skill(skill_id: str, name: str, description: str, purpose: str, scope: str) -> Skill:
    return Skill(skill_id=skill_id, name=name, description=description, purpose=purpose, scope=scope)


def _v(skill_id: str, **kwargs) -> SkillVersion:
    kwargs.setdefault("version", "1.0.0")
    return SkillVersion(skill_id=skill_id, **kwargs)


CANONICAL_SKILLS: list[tuple[Skill, SkillVersion]] = [
    (
        _skill("security", "Security Intelligence", "Coordinates secret/SAST/IaC/dependency-CVE scanning and remediation across a project.",
               "Ensure every relevant scanner category runs, findings are policy-gated by severity, and remediation is verified rather than assumed.",
               "Repository-level static analysis and remediation; never live traffic/runtime interception."),
        _v("security", risk_level=RiskLevel.MEDIUM,
           description="Requires secret/CVE/SAST/IaC scanning per relevance to the changed files; verification-after-remediation is mandatory; no secret value may ever appear in a finding.",
           capabilities=["secret_scanning", "sast_scanning", "iac_scanning", "dependency_cve_scanning", "remediation_verification"],
           allowed_tools=["shell.run", "filesystem.read", "filesystem.write", "git.diff", "git.commit"],
           prohibited_actions=["secret.commit"],
           required_checks=["gitleaks", "semgrep", "checkov", "trivy"],
           verification_rules=["pytest", "git.diff"],
           escalation_rules=["security.finding severity=critical always escalates to a human (policy DENY, never auto-merged)"],
           approval_requirements=["security.finding severity=high requires policy REQUIRE_APPROVAL before merge"],
           input_contract={"project_root": "str", "changed_files": "list[str]"},
           output_contract={"findings": "list[SecurityFinding]", "remediated": "list[str]"}),
    ),
    (
        _skill("sast", "Static Application Security Testing", "Runs semgrep-based static analysis for code-level vulnerability patterns.",
               "Find code-level vulnerability patterns before they reach production.", "Source code in the repository only."),
        _v("sast", risk_level=RiskLevel.LOW,
           description="Runs the real semgrep scanner (security/scanners/semgrep_scanner.py) and reports REAL/MOCKED/UNAVAILABLE/BLOCKED honestly rather than fabricating a clean scan when the tool is unavailable.",
           capabilities=["sast_scanning"],
           allowed_tools=["shell.run", "filesystem.read"],
           required_checks=["semgrep"],
           verification_rules=["pytest"],
           dependencies=[SkillDependency("security", ">=1.0.0")],
           input_contract={"project_root": "str"}, output_contract={"findings": "list[SecurityFinding]"}),
    ),
    (
        _skill("dependency-cve", "Dependency & CVE Intelligence", "Scans manifests for vulnerable dependencies and plans upgrade remediation.",
               "Keep dependencies free of known CVEs without breaking the build.", "Manifest files (requirements.txt, package.json, etc.) and trivy's container/dependency scan."),
        _v("dependency-cve", risk_level=RiskLevel.MEDIUM,
           description="Runs the real trivy scanner for dependency/container CVEs; a major-version upgrade always routes through policy WARN (dependency.upgrade major_version_bump=true) rather than auto-applying silently.",
           capabilities=["dependency_scanning", "cve_remediation_planning"],
           allowed_tools=["shell.run", "filesystem.read", "filesystem.write"],
           required_checks=["trivy"],
           verification_rules=["pytest"],
           dependencies=[SkillDependency("security", ">=1.0.0"), SkillDependency("testing", ">=1.0.0")],
           input_contract={"project_root": "str"}, output_contract={"upgrades_planned": "list[str]"}),
    ),
    (
        _skill("secrets", "Secret Scanning", "Runs gitleaks to detect committed credentials, including git history.",
               "Prevent and detect credential exposure in the repository, including its history.",
               "Working tree and git history read-only inspection; never rewrites history automatically."),
        _v("secrets", risk_level=RiskLevel.HIGH,
           description="Runs the real gitleaks scanner; secret.commit is always DENY (config/policy.yaml); history inspection is read-only and explicitly ALLOWed (security.git_history_inspection) - no automatic history rewrite is ever performed.",
           capabilities=["secret_scanning", "git_history_inspection"],
           allowed_tools=["shell.run", "filesystem.read", "git.log", "git.diff"],
           prohibited_actions=["secret.commit"],
           required_checks=["gitleaks"],
           verification_rules=["pytest"],
           dependencies=[SkillDependency("security", ">=1.0.0")],
           input_contract={"project_root": "str"}, output_contract={"findings": "list[SecurityFinding]"}),
    ),
    (
        _skill("terraform", "Terraform Infrastructure Review", "Discovers and validates Terraform configuration for security/drift issues.",
               "Catch insecure or drifted infrastructure-as-code before it is applied by a human.",
               "Repository-only static analysis via checkov; NEVER live terraform apply/destroy - no cloud credentials are exercised."),
        _v("terraform", risk_level=RiskLevel.HIGH,
           description="Discovery/validation/security-checks only, honestly BLOCKED for anything requiring a live cloud apply. terraform_apply/terraform_destroy always require policy approval/deny respectively; this skill never invokes either.",
           capabilities=["iac_discovery", "iac_security_scanning", "repository_fix_remediation"],
           allowed_tools=["shell.run", "filesystem.read", "filesystem.write", "git.diff"],
           prohibited_actions=["infra.resource_delete", "infra.terraform_destroy", "infra.cluster_resource_delete"],
           required_checks=["checkov"],
           verification_rules=["pytest", "git.diff"],
           escalation_rules=["infra.terraform_apply is REQUIRE_APPROVAL by policy; this skill never calls it itself",
                              "infra.finding severity=critical always escalates (policy DENY)"],
           approval_requirements=["infra.finding severity=high requires policy REQUIRE_APPROVAL"],
           dependencies=[SkillDependency("security", ">=1.0.0"), SkillDependency("testing", ">=1.0.0")],
           input_contract={"project_root": "str"}, output_contract={"findings": "list[SecurityFinding]"}),
    ),
    (
        _skill("kubernetes", "Kubernetes Manifest Review", "Discovers and validates Kubernetes manifests for security misconfiguration.",
               "Catch insecure Kubernetes manifests before a human applies them.",
               "Repository-only static manifest analysis via checkov's native k8s scanner; NEVER a live cluster (no kubectl apply/delete)."),
        _v("kubernetes", risk_level=RiskLevel.HIGH,
           description="Discovery/validation/security-checks/rollback-verification-expectations only. Honestly reports NOT_IMPLEMENTED/BLOCKED for any live-cluster capability - no kubectl credentials are ever exercised (ARCHITECTURE.md Phase 5/9 addenda).",
           capabilities=["k8s_manifest_discovery", "k8s_security_scanning", "repository_fix_remediation"],
           allowed_tools=["shell.run", "filesystem.read", "filesystem.write", "git.diff"],
           prohibited_actions=["infra.resource_delete", "infra.cluster_resource_delete"],
           required_checks=["checkov"],
           verification_rules=["pytest", "git.diff"],
           escalation_rules=["infra.cluster_apply is REQUIRE_APPROVAL by policy; this skill never calls it",
                              "infra.finding severity=critical always escalates (policy DENY)"],
           dependencies=[SkillDependency("security", ">=1.0.0")],
           input_contract={"project_root": "str"}, output_contract={"findings": "list[SecurityFinding]"}),
    ),
    (
        _skill("helm", "Helm Chart Review", "Validates rendered Helm chart output for security misconfiguration.",
               "Catch insecure Helm-templated manifests before a human installs/upgrades the release.",
               "Repository-only static analysis of `helm template` output; NEVER a live `helm install`/`helm upgrade`."),
        _v("helm", risk_level=RiskLevel.HIGH,
           description="A blocked/unavailable helm/checkov toolchain must report BLOCKED, never a false PASS (infra/scanners/helm_scanner.py's explicit trap-avoidance). Never invokes helm install/upgrade/delete.",
           capabilities=["helm_chart_discovery", "helm_security_scanning"],
           allowed_tools=["shell.run", "filesystem.read", "filesystem.write"],
           prohibited_actions=["infra.resource_delete", "infra.cluster_resource_delete"],
           required_checks=["checkov"],
           verification_rules=["pytest"],
           dependencies=[SkillDependency("kubernetes", ">=1.0.0")],
           input_contract={"project_root": "str"}, output_contract={"findings": "list[SecurityFinding]"}),
    ),
    (
        _skill("cicd", "CI/CD Pipeline Intelligence", "Discovers CI/CD pipeline configuration, monitors runs, diagnoses failures.",
               "Keep the pipeline green and diagnose failures deterministically rather than guessing.",
               "GitHub Actions discovery/monitoring/diagnosis via the real GitHub tool; never mutates workflow files without going through git/PR."),
        _v("cicd", risk_level=RiskLevel.MEDIUM,
           description="CI configuration failures (FailureClass.CI_CONFIGURATION) are never auto-retried (failure.py's NO_AUTO_RETRY set) - a malformed workflow is escalated, not blindly re-run.",
           capabilities=["pipeline_discovery", "run_monitoring", "failure_diagnosis"],
           allowed_tools=["shell.run", "filesystem.read", "github.get_workflow_run", "github.list_workflow_runs",
                          "github.list_workflow_run_jobs", "github.get_combined_status", "github.list_check_runs"],
           required_checks=["github.get_combined_status"],
           verification_rules=["pytest"],
           dependencies=[SkillDependency("testing", ">=1.0.0")],
           input_contract={"repo": "str"}, output_contract={"pipeline_status": "dict"}),
    ),
    (
        _skill("deployment", "Deployment Intelligence", "Plans, executes, and verifies deployments with rollback capability.",
               "Deploy safely: release gates pass, production always requires human approval, rollback is verified not assumed.",
               "Local fixture deployment provider today (Kubernetes provider documented as a future target, not exercised in this sandbox)."),
        _v("deployment", risk_level=RiskLevel.HIGH,
           description="deployment.deploy/deployment.rollback in production are REQUIRE_APPROVAL by policy; the only automatic-in-production carve-out is deployment.emergency_rollback (a distinct, narrowly-scoped action, never a flag on a normal rollback).",
           capabilities=["deployment_planning", "release_gate_verification", "rollback_planning"],
           allowed_tools=["deployment.plan", "deployment.deploy", "deployment.rollback", "deployment.verify",
                          "deployment.rollout_status", "deployment.list_evidence", "deployment.record_evidence"],
           required_checks=["pytest"],
           verification_rules=["deployment.verify", "pytest"],
           escalation_rules=["deployment.deploy environment=production requires human approval",
                              "deployment.rollback environment=production requires human approval unless deployment.emergency_rollback"],
           approval_requirements=["deployment.deploy environment=production", "deployment.rollback environment=production"],
           dependencies=[SkillDependency("testing", ">=1.0.0"), SkillDependency("security", ">=1.0.0")],
           input_contract={"project_id": "str", "environment": "str"}, output_contract={"deployment_id": "str", "final_state": "str"}),
    ),
    (
        _skill("incident-response", "Incident Response", "Correlates operational events into incidents, aids root-cause and remediation.",
               "Diagnose and respond to production incidents using real evidence, never a guessed root cause.",
               "Read-only diagnostics and non-destructive, non-production-mutating remediation only."),
        _v("incident-response", risk_level=RiskLevel.HIGH,
           description="operations.destructive_action/delete_production_data/disable_security_control/bypass_policy/force_push_protected_branch are all policy DENY - this skill never claims to perform any of them; restart/rollback/scale/config/secret/db changes in production always require approval.",
           capabilities=["incident_correlation", "root_cause_analysis", "diagnostic_collection"],
           allowed_tools=["operations.record_incident", "operations.list_incidents", "operations.find_similar_incidents",
                          "shell.run", "filesystem.read"],
           prohibited_actions=["operations.destructive_action", "operations.delete_production_data",
                                "operations.disable_security_control", "operations.bypass_policy",
                                "operations.force_push_protected_branch"],
           required_checks=["pytest"],
           verification_rules=["pytest"],
           escalation_rules=["operations.restart_workload/rollback/scale/configuration_change/secret_rotation/"
                              "database_change/infrastructure_mutation in production require human approval"],
           dependencies=[SkillDependency("database", ">=1.0.0"), SkillDependency("security", ">=1.0.0")],
           input_contract={"project_id": "str"}, output_contract={"incident_id": "str", "root_cause_confidence": "str"}),
    ),
    (
        _skill("database", "Database Change Management", "Governs how any database schema/data change may be made.",
               "Guarantee every schema change is reviewable, reversible in principle, and drift-detected - never an ad hoc mutation.",
               "Schema-change discipline generally; PostgreSQL specifics live in the postgresql skill."),
        _v("database", risk_level=RiskLevel.HIGH,
           description="Schema changes are migration-only; database.schema_change is a fixed REQUIRE_APPROVAL policy literal (config/policy.yaml); no direct production schema mutation, no parameterization shortcuts, no credential leakage.",
           capabilities=["schema_change_governance", "migration_review"],
           allowed_tools=["filesystem.read", "filesystem.write", "shell.run"],
           prohibited_actions=["operations.database_change"],
           required_checks=["migration_runner.apply_pending", "migration_runner.drift_report"],
           verification_rules=["migration_runner.drift_report", "pytest"],
           approval_requirements=["database.schema_change"],
           input_contract={"project_root": "str"}, output_contract={"migrations_applied": "list[str]"}),
    ),
    (
        _skill("postgresql", "PostgreSQL Operations", "Applies the Stage A/A.5 PostgreSQL migration-only, drift-detected discipline concretely.",
               "Keep the real running Postgres schema exactly synchronized with the migration files on disk - no exceptions.",
               "src/aep/db/migrations.py's apply/status/validate/drift_report runner against the real local database; parameterized SQL only in src/aep/db/postgres.py."),
        _v("postgresql", risk_level=RiskLevel.HIGH,
           description="Requires migration-only changes (schema-mutating DDL statements may only appear in migrations.py's own tracking-table bootstrap or supabase/migrations/*.sql - enforced by tests/test_db_migration_only_enforcement.py), parameterized SQL only (no f-string SQL), drift_report() before/after any change, and no credential value ever logged (dsn_from_parts never printed).",
           capabilities=["migration_apply", "migration_validate", "schema_drift_detection"],
           allowed_tools=["filesystem.read", "shell.run"],
           prohibited_actions=["operations.database_change"],
           required_checks=["migration_runner.apply_pending", "migration_runner.drift_report"],
           verification_rules=["migration_runner.drift_report", "pytest"],
           dependencies=[SkillDependency("database", ">=1.0.0")],
           input_contract={"dsn": "str (never logged)"}, output_contract={"drift_status": "str"}),
    ),
    (
        _skill("git", "Git Operations", "Local git operations: branch, commit, diff, log - never a remote push by itself.",
               "Provide safe, capability-scoped local version control operations.", "Local repository only; remote operations live in the github skill."),
        _v("git", risk_level=RiskLevel.LOW,
           description="git.push/git.branch to main/master are DENY by policy; this skill only ever uses git.push_local (a local-only push capability), never a remote push action.",
           capabilities=["local_version_control"],
           allowed_tools=["git.branch", "git.commit", "git.current_branch", "git.diff", "git.log", "git.push_local"],
           prohibited_actions=["git.push"],
           required_checks=["git.diff"],
           verification_rules=["git.diff"],
           input_contract={"repo_path": "str"}, output_contract={"commit_sha": "str"}),
    ),
    (
        _skill("github", "GitHub Operations", "Remote GitHub operations: branches, PRs, issues, workflow/status inspection.",
               "Provide safe, capability-scoped remote GitHub operations, gated by the same policy as local git.", "Real GitHub API via github/client.py; force-push and protected-branch push are gated exactly like local git."),
        _v("github", risk_level=RiskLevel.MEDIUM,
           description="github.push to main/master is DENY; github.push force=true is REQUIRE_APPROVAL - the identical rule shape as local git.push, per config/policy.yaml's Phase 2 addendum comment.",
           capabilities=["remote_version_control", "pull_request_management", "ci_status_inspection"],
           allowed_tools=["github.push_branch", "github.create_pull_request", "github.get_pull_request",
                          "github.update_pull_request", "github.comment_on_pr", "github.list_pr_files",
                          "github.list_pr_comments", "github.create_issue", "github.list_issues",
                          "github.get_branch", "github.list_branches", "github.get_repo", "github.get_commit",
                          "github.list_commits", "github.get_combined_status", "github.list_check_runs",
                          "github.get_workflow_run", "github.list_workflow_runs", "github.list_workflow_run_jobs"],
           prohibited_actions=["github.push"],
           required_checks=["github.get_combined_status"],
           verification_rules=["github.get_combined_status"],
           dependencies=[SkillDependency("git", ">=1.0.0")],
           input_contract={"repo": "str"}, output_contract={"pr_number": "int"}),
    ),
    (
        _skill("architecture-review", "Architecture Review", "Reviews structural/architectural decisions for consistency and risk.",
               "Catch architectural regressions and risk before they are merged, using real evidence (tests, diffs, findings) rather than opinion alone.",
               "Repository-level review; advisory only, never auto-merges."),
        _v("architecture-review", risk_level=RiskLevel.LOW,
           description="Advisory-only: recommendations are never self-authorizing - any change still passes through the normal policy/verification gates of whichever skill(s) actually perform it (security/testing/deployment).",
           capabilities=["structural_review", "risk_assessment"],
           allowed_tools=["filesystem.read", "git.diff", "git.log"],
           required_checks=["git.diff"],
           verification_rules=["git.diff"],
           dependencies=[SkillDependency("security", ">=1.0.0"), SkillDependency("testing", ">=1.0.0")],
           input_contract={"project_root": "str"}, output_contract={"recommendations": "list[str]"}),
    ),
    (
        _skill("code-review", "Code Review", "Reviews a diff for correctness, security, and test coverage before merge.",
               "Catch defects before merge using real test/scan evidence, not just static reading.",
               "Diff-level review of the actual changed files; always requires testing skill's real pytest evidence."),
        _v("code-review", risk_level=RiskLevel.LOW,
           description="A code-review recommendation is advisory; the actual merge/push decision is still gated by git/github skills' policy checks - code-review never bypasses them.",
           capabilities=["diff_review", "test_coverage_assessment"],
           allowed_tools=["filesystem.read", "git.diff", "git.log"],
           required_checks=["pytest"],
           verification_rules=["pytest", "git.diff"],
           dependencies=[SkillDependency("testing", ">=1.0.0")],
           input_contract={"repo_path": "str"}, output_contract={"issues_found": "list[str]"}),
    ),
    (
        _skill("testing", "Testing", "Runs the project's real test suite and reports genuine pass/fail, never a fabricated result.",
               "Provide ground truth about whether a change actually works.", "Whatever real test runner the target project uses (pytest in this platform's own suite)."),
        _v("testing", risk_level=RiskLevel.LOW,
           description="Verification is always a REAL test run (test.run capability) - this skill never reports a synthetic pass; an unavailable test runner is reported UNAVAILABLE, not silently skipped as if it passed.",
           capabilities=["test_execution", "coverage_reporting"],
           allowed_tools=["shell.run", "filesystem.read"],
           required_checks=["pytest"],
           verification_rules=["pytest"],
           input_contract={"project_root": "str"}, output_contract={"passed": "bool", "summary": "str"}),
    ),
    (
        _skill("cost-optimization", "Cost Optimization", "Analyzes read-only infrastructure/dependency data for cost-reduction opportunities.",
               "Surface cost-saving recommendations from real discovered data, never a projected/estimated capability claimed as live.",
               "Read-only analysis of infra discovery/dependency data already collected by other skills; never mutates anything."),
        _v("cost-optimization", risk_level=RiskLevel.LOW,
           description="Purely advisory and read-only - depends on infra discovery (read_only: true, already ALLOW by policy) and dependency-cve data; never itself invokes a mutating action.",
           capabilities=["cost_analysis", "resource_rightsizing_recommendation"],
           allowed_tools=["filesystem.read"],
           required_checks=["pytest"],
           verification_rules=["pytest"],
           dependencies=[SkillDependency("dependency-cve", ">=1.0.0")],
           input_contract={"project_root": "str"}, output_contract={"recommendations": "list[str]"}),
    ),
]


for _skill_obj, _version_obj in CANONICAL_SKILLS:
    if not _version_obj.purpose:
        _version_obj.purpose = _skill_obj.purpose
    if not _version_obj.scope:
        _version_obj.scope = _skill_obj.scope


def seed_canonical_skills(registry: SkillRegistry) -> list[SkillVersion]:
    """Registers every canonical skill's identity and publishes its 1.0.0
    version through the REAL `SkillRegistry`/repository path - never a
    bypass. Idempotent: re-running against an already-seeded registry is
    safe (`register_skill` is get-or-create; publishing an already-
    published 1.0.0 raises `SkillImmutabilityError`, which callers should
    treat as "already seeded", not a fatal error)."""
    from .registry import SkillImmutabilityError

    published: list[SkillVersion] = []
    for skill, version in CANONICAL_SKILLS:
        registry.register_skill(skill)
    for skill, version in CANONICAL_SKILLS:
        try:
            published.append(registry.publish(version))
        except SkillImmutabilityError:
            published.append(registry.get_version(version.skill_id, version.version))
    return published
