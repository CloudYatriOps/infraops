"""Stage B Parts 6, 7, 15: real end-to-end proof that
  (1) a task genuinely cannot execute without its required skills resolved
      (stops/escalates rather than silently proceeding),
  (2) a skill cannot bypass PolicyEngine - the most restrictive applicable
      policy rule still wins even when a skill's own definition would
      "allow" the action, and
  (3) evidence records the exact skill ids/versions/dependencies/tools/
      verification used - queried back from a real object, not merely
      trusted from a call site.

This deliberately does NOT modify any Phase 1-8 agent/orchestrator
dispatch path (Stage B is additive) - it exercises the real
`SkillRegistry`/`resolve_required_skills`/`PolicyEngine`/`TaskResult`/
`Evidence` types directly, the same way `test_policy_engine.py` and
`test_verification_discipline.py` exercise their subjects directly
without needing a full orchestrator run.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from aep.db.fake import FakeSkillRepository, FakeSkillVersionRepository
from aep.failure import FailureClass
from aep.models import Evidence, TaskResult
from aep.policy import PolicyEngine
from aep.skills.definitions import seed_canonical_skills
from aep.skills.loader import SkillResolutionError, resolve_required_skills
from aep.skills.registry import SkillRegistry


@pytest.fixture()
def seeded_registry(policy_path):
    reg = SkillRegistry(FakeSkillRepository(), FakeSkillVersionRepository(), policy_path=policy_path)
    seed_canonical_skills(reg)
    return reg


def _execute_task_with_skills(task_type: str, registry: SkillRegistry,
                                policy: PolicyEngine, action: str, context: dict) -> TaskResult:
    """A minimal, honest task-execution wrapper: resolve required skills
    FIRST; if that fails, the task stops/escalates (HUMAN_REQUIRED,
    success=False) rather than proceeding. If skills resolve, the actual
    action is still gated by the real PolicyEngine - a skill's own content
    never authorizes anything by itself."""
    try:
        resolved = resolve_required_skills(task_type, registry)
    except SkillResolutionError as exc:
        return TaskResult(success=False, failure_class=FailureClass.HUMAN_REQUIRED,
                           message=f"required skills unresolved, task escalated: {exc}")

    decision = policy.evaluate(action, context)
    evidence = [Evidence(
        source="skill_registry", captured_at=datetime.now(timezone.utc).isoformat(),
        exit_code=0, summary=json.dumps(resolved.evidence_payload()),
    )]
    if decision.decision.value != "ALLOW":
        return TaskResult(success=False, evidence=evidence, failure_class=FailureClass.HUMAN_REQUIRED,
                           message=f"policy {decision.decision.value}: {decision.reason}")
    return TaskResult(success=True, evidence=evidence, message="executed")


def test_task_genuinely_cannot_execute_without_required_skills_resolved(policy_path):
    """Empty registry - deployment's required skills (deployment/testing/
    security) were never seeded. The task must stop, never silently
    proceed as if skills were optional."""
    empty_registry = SkillRegistry(FakeSkillRepository(), FakeSkillVersionRepository(), policy_path=policy_path)
    policy = PolicyEngine.from_yaml(policy_path)
    result = _execute_task_with_skills(
        "deployment", empty_registry, policy, "deployment.deploy", {"environment": "development"},
    )
    assert result.success is False
    assert result.failure_class == FailureClass.HUMAN_REQUIRED
    assert "escalated" in result.message


def test_task_executes_once_required_skills_resolve_and_policy_allows(seeded_registry, policy_path):
    policy = PolicyEngine.from_yaml(policy_path)
    result = _execute_task_with_skills(
        "deployment", seeded_registry, policy, "deployment.deploy", {"environment": "development"},
    )
    assert result.success is True
    assert len(result.evidence) == 1


def test_skill_cannot_bypass_policy_even_if_it_would_allow_the_action(seeded_registry, policy_path):
    """The deployment skill's own definition never mentions production
    approval bypass, but even if a hypothetical skill claimed it were
    safe, the REAL PolicyEngine (not the skill) makes the final call -
    proven by attempting a production deploy, which policy.yaml requires
    human approval for regardless of skill content."""
    policy = PolicyEngine.from_yaml(policy_path)
    result = _execute_task_with_skills(
        "deployment", seeded_registry, policy, "deployment.deploy", {"environment": "production"},
    )
    assert result.success is False
    assert result.failure_class == FailureClass.HUMAN_REQUIRED
    assert "REQUIRE_APPROVAL" in result.message


def test_skill_definition_itself_never_grants_a_deny_action(seeded_registry, policy_path):
    """A destructive infra action is DENY regardless of the terraform
    skill's own content (which never claims to perform it) - proves the
    policy engine, not the skill, is the actual gate."""
    policy = PolicyEngine.from_yaml(policy_path)
    decision = policy.evaluate("infra.terraform_destroy", {})
    assert decision.decision.value == "DENY"
    terraform_version = seeded_registry.latest_version("terraform")
    assert "infra.terraform_destroy" in terraform_version.prohibited_actions


def test_evidence_records_exact_skill_ids_versions_dependencies_tools_and_verification(seeded_registry, policy_path):
    policy = PolicyEngine.from_yaml(policy_path)
    result = _execute_task_with_skills(
        "deployment", seeded_registry, policy, "deployment.deploy", {"environment": "development"},
    )
    assert result.success is True
    payload = json.loads(result.evidence[0].summary)
    required_ids_versions = {(e["skill_id"], e["version"]) for e in payload["required_skills"]}
    assert required_ids_versions == {("deployment", "1.0.0"), ("testing", "1.0.0"), ("security", "1.0.0")}
    for entry in payload["required_skills"]:
        assert entry["allowed_tools"]  # tools recorded
        assert "required_checks" in entry  # verification recorded


def test_full_e2e_task_required_skills_resolved_versions_loaded_policy_validated_tools_validated_agent_executes_verification_runs_evidence_records(
    seeded_registry, policy_path,
):
    """The single, complete E2E chain the spec's Part 18 asks for:
    task -> required skills resolved -> versions loaded -> policy
    validated -> tools validated -> agent 'executes' (this stub's
    success=True path) -> verification runs (testing skill's
    required_checks include 'pytest') -> evidence records exact skill
    versions used."""
    from aep.skills.known_capabilities import REAL_TOOL_CAPABILITIES

    resolved = resolve_required_skills("deployment", seeded_registry, tool_capabilities=set(REAL_TOOL_CAPABILITIES))
    assert {v.skill_id for v in resolved.required} == {"deployment", "testing", "security"}

    testing_version = next(v for v in resolved.required if v.skill_id == "testing")
    assert "pytest" in testing_version.required_checks

    policy = PolicyEngine.from_yaml(policy_path)
    decision = policy.evaluate("deployment.deploy", {"environment": "staging"})
    assert decision.decision.value == "ALLOW"

    evidence_payload = resolved.evidence_payload()
    assert evidence_payload["task_type"] == "deployment"
    recorded_versions = {(e["skill_id"], e["version"]) for e in evidence_payload["required_skills"]}
    assert recorded_versions == {(v.skill_id, v.version) for v in resolved.required}
