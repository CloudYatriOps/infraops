"""Stage B Part 14: dependency graph resolution - missing/version-conflict/
cycle detection, never silently ignored."""
from __future__ import annotations

from aep.db.fake import FakeSkillRepository, FakeSkillVersionRepository
from aep.skills.models import Skill, SkillDependency, SkillVersion
from aep.skills.registry import SkillRegistry


def _registry(policy_path):
    return SkillRegistry(FakeSkillRepository(), FakeSkillVersionRepository(), policy_path=policy_path)


def test_missing_dependency_detected(policy_path):
    reg = _registry(policy_path)
    reg.register_skill(Skill(skill_id="deployment", name="Deployment"))
    reg.publish(SkillVersion(skill_id="deployment", version="1.0.0",
                              dependencies=[SkillDependency("testing", "*")]))
    res = reg.resolve_dependencies("deployment", "1.0.0")
    assert not res.ok
    assert "testing" in res.missing
    assert res.conflicts == []
    assert res.cycle is None


def test_version_conflict_detected(policy_path):
    reg = _registry(policy_path)
    reg.register_skill(Skill(skill_id="testing", name="Testing"))
    reg.register_skill(Skill(skill_id="deployment", name="Deployment"))
    reg.publish(SkillVersion(skill_id="testing", version="1.0.0"))
    reg.publish(SkillVersion(skill_id="deployment", version="1.0.0",
                              dependencies=[SkillDependency("testing", ">=2.0.0")]))
    res = reg.resolve_dependencies("deployment", "1.0.0")
    assert not res.ok
    assert res.missing == []
    assert any("testing" in c for c in res.conflicts)


def test_cycle_detected_and_never_silently_ignored(policy_path):
    reg = _registry(policy_path)
    reg.register_skill(Skill(skill_id="a", name="A"))
    reg.register_skill(Skill(skill_id="b", name="B"))
    reg.register_skill(Skill(skill_id="c", name="C"))
    reg.publish(SkillVersion(skill_id="a", version="1.0.0", dependencies=[SkillDependency("b", "*")]))
    reg.publish(SkillVersion(skill_id="b", version="1.0.0", dependencies=[SkillDependency("c", "*")]))
    reg.publish(SkillVersion(skill_id="c", version="1.0.0", dependencies=[SkillDependency("a", "*")]))
    res = reg.resolve_dependencies("a", "1.0.0")
    assert not res.ok
    assert res.cycle is not None
    assert "a" in res.cycle


def test_deep_valid_chain_resolves_in_topological_order(policy_path):
    reg = _registry(policy_path)
    reg.register_skill(Skill(skill_id="testing", name="Testing"))
    reg.register_skill(Skill(skill_id="security", name="Security"))
    reg.register_skill(Skill(skill_id="deployment", name="Deployment"))
    reg.publish(SkillVersion(skill_id="testing", version="1.0.0"))
    reg.publish(SkillVersion(skill_id="security", version="1.0.0",
                              dependencies=[SkillDependency("testing", ">=1.0.0")]))
    reg.publish(SkillVersion(skill_id="deployment", version="1.0.0",
                              dependencies=[SkillDependency("testing", ">=1.0.0"),
                                            SkillDependency("security", ">=1.0.0")]))
    res = reg.resolve_dependencies("deployment", "1.0.0")
    assert res.ok
    order = [sid for sid, _ in res.resolved]
    assert order.index("testing") < order.index("security") < order.index("deployment")


def test_all_canonical_skill_dependencies_resolve_cleanly(policy_path):
    """Real proof over the actual seeded canonical skill set (deployment ->
    testing/security, terraform -> security/testing, postgresql ->
    database, etc.) - not a synthetic toy graph."""
    from aep.skills.definitions import seed_canonical_skills
    reg = _registry(policy_path)
    seed_canonical_skills(reg)
    for skill in reg.list_skills():
        for version in reg.list_versions(skill.skill_id):
            res = reg.resolve_dependencies(version.skill_id, version.version)
            assert res.ok, f"{version.skill_id}@{version.version}: {res.missing} {res.conflicts} {res.cycle}"
