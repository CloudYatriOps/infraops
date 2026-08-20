"""Stage B Part 12: version parsing/comparison/constraint satisfaction and
deprecated-version detection."""
from __future__ import annotations

import pytest

from aep.db.fake import FakeSkillRepository, FakeSkillVersionRepository
from aep.skills.models import Skill, SkillVersion
from aep.skills.registry import SkillRegistry
from aep.skills.versioning import compare_versions, parse_version, satisfies


def test_parse_version_valid():
    assert parse_version("1.2.3") == (1, 2, 3)


@pytest.mark.parametrize("bad", ["1.2", "1.2.3.4", "a.b.c", "", "1.2.x"])
def test_parse_version_invalid(bad):
    with pytest.raises(ValueError):
        parse_version(bad)


def test_compare_versions():
    assert compare_versions("1.0.0", "1.0.1") == -1
    assert compare_versions("2.0.0", "1.9.9") == 1
    assert compare_versions("1.0.0", "1.0.0") == 0


def test_satisfies_wildcard_exact_and_minimum():
    assert satisfies("1.0.0", "*")
    assert satisfies("1.0.0", "==1.0.0")
    assert not satisfies("1.0.1", "==1.0.0")
    assert satisfies("1.2.0", ">=1.0.0")
    assert not satisfies("0.9.0", ">=1.0.0")
    assert satisfies("1.0.0", "1.0.0")  # bare version == exact match


def test_deprecated_version_is_excluded_from_dependency_satisfaction(policy_path):
    registry = SkillRegistry(FakeSkillRepository(), FakeSkillVersionRepository(), policy_path=policy_path)
    registry.register_skill(Skill(skill_id="testing", name="Testing"))
    registry.publish(SkillVersion(skill_id="testing", version="1.0.0"))
    registry.deprecate("testing", "1.0.0")
    registry.register_skill(Skill(skill_id="code-review", name="Code Review"))
    from aep.skills.models import SkillDependency
    registry.publish(SkillVersion(skill_id="code-review", version="1.0.0",
                                   dependencies=[SkillDependency("testing", ">=1.0.0")]))
    res = registry.resolve_dependencies("code-review", "1.0.0")
    assert not res.ok
    assert any("testing" in c for c in res.conflicts)
