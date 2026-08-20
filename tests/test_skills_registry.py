"""Stage B Parts 1/2/12/16: registration, publish, self-validation,
immutability, listing - against the in-memory fake backend (zero network
dependency, fast)."""
from __future__ import annotations

import pytest

from aep.db.fake import FakeSkillRepository, FakeSkillVersionRepository
from aep.skills.models import LifecycleState, RiskLevel, Skill, SkillVersion
from aep.skills.registry import (
    SkillImmutabilityError,
    SkillNotFoundError,
    SkillRegistry,
    SkillValidationError,
)


@pytest.fixture()
def registry(policy_path):
    return SkillRegistry(FakeSkillRepository(), FakeSkillVersionRepository(), policy_path=policy_path)


def test_register_skill_is_idempotent(registry):
    s1 = registry.register_skill(Skill(skill_id="testing", name="Testing"))
    s2 = registry.register_skill(Skill(skill_id="testing", name="Testing (renamed attempt)"))
    assert s1.skill_id == s2.skill_id == "testing"
    assert len(registry.list_skills()) == 1


def test_publish_requires_registered_skill_first(registry):
    with pytest.raises(SkillNotFoundError):
        registry.publish(SkillVersion(skill_id="nope", version="1.0.0"))


def test_publish_then_get_and_list(registry):
    registry.register_skill(Skill(skill_id="testing", name="Testing"))
    published = registry.publish(SkillVersion(skill_id="testing", version="1.0.0", allowed_tools=["shell.run"]))
    assert published.lifecycle_state == LifecycleState.PUBLISHED
    assert published.published_at is not None
    fetched = registry.get_version("testing", "1.0.0")
    assert fetched.version == "1.0.0"
    assert registry.latest_version("testing").version == "1.0.0"
    assert len(registry.list_versions("testing")) == 1


def test_publishing_new_version_never_mutates_existing_row(registry):
    registry.register_skill(Skill(skill_id="testing", name="Testing"))
    registry.publish(SkillVersion(skill_id="testing", version="1.0.0", allowed_tools=["shell.run"]))
    registry.publish(SkillVersion(skill_id="testing", version="1.1.0", allowed_tools=["shell.run", "filesystem.read"]))
    v1 = registry.get_version("testing", "1.0.0")
    v2 = registry.get_version("testing", "1.1.0")
    assert v1.allowed_tools == ["shell.run"]
    assert v2.allowed_tools == ["shell.run", "filesystem.read"]
    assert registry.latest_version("testing").version == "1.1.0"
    assert len(registry.list_versions("testing")) == 2


def test_republishing_an_existing_version_is_rejected_not_overwritten(registry):
    registry.register_skill(Skill(skill_id="testing", name="Testing"))
    registry.publish(SkillVersion(skill_id="testing", version="1.0.0", allowed_tools=["shell.run"]))
    with pytest.raises(SkillImmutabilityError):
        registry.publish(SkillVersion(skill_id="testing", version="1.0.0", allowed_tools=["shell.run"]))
    # Content is untouched - proving the rejection, not a silent partial write.
    assert registry.get_version("testing", "1.0.0").allowed_tools == ["shell.run"]


def test_attempting_to_mutate_published_content_directly_is_rejected_at_repo_layer(registry):
    """Direct repository-layer mutation attempt (bypassing SkillRegistry.publish
    entirely) must also be rejected - the fake repository enforces the same
    invariant the real Postgres trigger enforces."""
    registry.register_skill(Skill(skill_id="testing", name="Testing"))
    registry.publish(SkillVersion(skill_id="testing", version="1.0.0", allowed_tools=["shell.run"]))
    from aep.db.models import SkillVersionRecord
    tampered = SkillVersionRecord(skill_id="testing", version="1.0.0", lifecycle_state="published",
                                   description="HACKED")
    with pytest.raises(ValueError):
        registry._versions.save(tampered)


def test_self_validation_rejects_unknown_tool(registry):
    registry.register_skill(Skill(skill_id="testing", name="Testing"))
    with pytest.raises(SkillValidationError):
        registry.publish(SkillVersion(skill_id="testing", version="1.0.0",
                                       allowed_tools=["not_a_real_tool.invented"]))


def test_self_validation_rejects_unknown_verification_check(registry):
    registry.register_skill(Skill(skill_id="testing", name="Testing"))
    with pytest.raises(SkillValidationError):
        registry.publish(SkillVersion(skill_id="testing", version="1.0.0",
                                       required_checks=["not_a_real_scanner"]))


def test_self_validation_rejects_unknown_policy_action(registry):
    registry.register_skill(Skill(skill_id="testing", name="Testing"))
    with pytest.raises(SkillValidationError):
        registry.publish(SkillVersion(skill_id="testing", version="1.0.0",
                                       prohibited_actions=["made.up_action"]))


def test_deprecate_marks_lifecycle_state_and_content_remains_readable(registry):
    registry.register_skill(Skill(skill_id="testing", name="Testing"))
    registry.publish(SkillVersion(skill_id="testing", version="1.0.0", allowed_tools=["shell.run"]))
    registry.deprecate("testing", "1.0.0")
    assert registry.is_deprecated("testing", "1.0.0")
    with pytest.raises(SkillNotFoundError):
        registry.latest_version("testing")  # no non-deprecated published version left
    assert registry.latest_version("testing", include_deprecated=True).version == "1.0.0"


def test_seed_canonical_skills_publishes_all_eighteen_and_passes_validation(registry):
    from aep.skills.definitions import seed_canonical_skills
    published = seed_canonical_skills(registry)
    assert len(published) == 18
    for skill in registry.list_skills():
        for version in registry.list_versions(skill.skill_id):
            assert registry.self_validate(version) == []
