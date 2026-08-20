"""Stage B Part 14: the deterministic (non-LLM) task-intent -> required/
optional skill resolver, and Part 6's "missing/invalid required skill
stops the task" guarantee."""
from __future__ import annotations

import pytest

from aep.db.fake import FakeSkillRepository, FakeSkillVersionRepository
from aep.skills.definitions import seed_canonical_skills
from aep.skills.loader import SkillResolutionError, TASK_SKILL_RULES, resolve_required_skills
from aep.skills.registry import SkillRegistry


@pytest.fixture()
def seeded_registry(policy_path):
    reg = SkillRegistry(FakeSkillRepository(), FakeSkillVersionRepository(), policy_path=policy_path)
    seed_canonical_skills(reg)
    return reg


def test_rules_are_explicit_fixed_literals_not_generated():
    """Part 14: explicit rules first, never an opaque/dynamic mechanism."""
    assert isinstance(TASK_SKILL_RULES, dict)
    assert TASK_SKILL_RULES["deployment"]["required"] == ["deployment", "testing", "security"]
    assert TASK_SKILL_RULES["database_migration"]["required"] == ["database", "postgresql"]


def test_resolve_required_skills_for_every_known_task_type(seeded_registry):
    for task_type in TASK_SKILL_RULES:
        result = resolve_required_skills(task_type, seeded_registry)
        required_ids = {v.skill_id for v in result.required}
        assert required_ids == set(TASK_SKILL_RULES[task_type]["required"])


def test_unknown_task_type_has_no_requirements(seeded_registry):
    result = resolve_required_skills("some_task_type_nobody_declared", seeded_registry)
    assert result.required == []
    assert result.optional == []


def test_missing_required_skill_raises_and_stops(policy_path):
    empty_registry = SkillRegistry(FakeSkillRepository(), FakeSkillVersionRepository(), policy_path=policy_path)
    with pytest.raises(SkillResolutionError):
        resolve_required_skills("deployment", empty_registry)


def test_invalid_required_skill_dependency_raises_and_stops(policy_path):
    from aep.skills.models import Skill, SkillDependency, SkillVersion
    reg = SkillRegistry(FakeSkillRepository(), FakeSkillVersionRepository(), policy_path=policy_path)
    reg.register_skill(Skill(skill_id="testing", name="Testing"))
    reg.publish(SkillVersion(skill_id="testing", version="1.0.0",
                              dependencies=[SkillDependency("does-not-exist", "*")]))
    with pytest.raises(SkillResolutionError):
        resolve_required_skills("testing", reg)


def test_optional_skill_unavailability_is_reported_not_hidden(policy_path):
    from aep.skills.models import Skill, SkillVersion
    reg = SkillRegistry(FakeSkillRepository(), FakeSkillVersionRepository(), policy_path=policy_path)
    reg.register_skill(Skill(skill_id="security", name="Security"))
    reg.publish(SkillVersion(skill_id="security", version="1.0.0"))
    result = resolve_required_skills("security_scan", reg)
    assert result.unavailable_optional  # sast/secrets/dependency-cve never registered
    assert set(result.unavailable_optional) == {"sast", "secrets", "dependency-cve"}


def test_tool_scope_enforcement_a_skill_cannot_claim_a_tool_the_registry_lacks(seeded_registry):
    with pytest.raises(SkillResolutionError):
        resolve_required_skills("security_scan", seeded_registry, tool_capabilities={"filesystem.read"})
    # With the real full tool set present, it resolves cleanly.
    from aep.skills.known_capabilities import REAL_TOOL_CAPABILITIES
    result = resolve_required_skills("security_scan", seeded_registry, tool_capabilities=set(REAL_TOOL_CAPABILITIES))
    assert result.required[0].skill_id == "security"


def test_evidence_payload_records_skill_ids_versions_dependencies_tools(seeded_registry):
    result = resolve_required_skills("deployment", seeded_registry)
    payload = result.evidence_payload()
    assert payload["task_type"] == "deployment"
    ids = {e["skill_id"] for e in payload["required_skills"]}
    assert ids == {"deployment", "testing", "security"}
    for entry in payload["required_skills"]:
        assert "version" in entry and entry["version"] == "1.0.0"
        assert "allowed_tools" in entry
        assert "required_checks" in entry
