"""Stage B Part 11: the Claude skill adapter is a deterministic, pure
projection of a canonical published SkillVersion - never a second,
independently-authored definition."""
from __future__ import annotations

from aep.skills.claude_adapter import (
    hash_projection,
    project_to_claude_skill,
    render_claude_skill_markdown,
)
from aep.skills.models import RiskLevel, SkillDependency, SkillVersion


def _sample_version() -> SkillVersion:
    return SkillVersion(
        skill_id="security", version="1.2.3", risk_level=RiskLevel.HIGH,
        description="d", purpose="p", scope="s",
        allowed_tools=["shell.run", "git.diff", "filesystem.read"],
        prohibited_actions=["secret.commit"],
        required_checks=["gitleaks", "semgrep"],
        verification_rules=["pytest"],
        escalation_rules=["critical findings escalate"],
        approval_requirements=["high findings require approval"],
        dependencies=[SkillDependency("testing", ">=1.0.0")],
    )


def test_projection_is_a_pure_function_of_content_repeated_hash_matches():
    v = _sample_version()
    h1 = hash_projection(v)
    h2 = hash_projection(v)
    assert h1 == h2
    m1 = render_claude_skill_markdown(v)
    m2 = render_claude_skill_markdown(v)
    assert m1 == m2


def test_projection_two_independently_constructed_equal_versions_hash_identically():
    """Determinism is about CONTENT, not object identity."""
    v1 = _sample_version()
    v2 = _sample_version()
    assert v1 is not v2
    assert hash_projection(v1) == hash_projection(v2)


def test_projection_changes_when_content_changes():
    v1 = _sample_version()
    v2 = _sample_version()
    v2.allowed_tools = v2.allowed_tools + ["git.commit"]
    assert hash_projection(v1) != hash_projection(v2)


def test_projected_fields_carry_canonical_identity_and_generated_from():
    v = _sample_version()
    projected = project_to_claude_skill(v)
    assert projected["canonical_skill_id"] == "security"
    assert projected["canonical_version"] == "1.2.3"
    assert "security@1.2.3" in projected["generated_from"]
    assert projected["applicable_tools"] == sorted(v.allowed_tools)
    assert projected["safety_constraints"]["risk_level"] == "high"
    assert projected["dependencies"] == ["testing>=1.0.0"]


def test_verification_expectations_include_both_required_checks_and_verification_rules():
    v = _sample_version()
    projected = project_to_claude_skill(v)
    assert set(v.required_checks) <= set(projected["verification_expectations"])
    assert set(v.verification_rules) <= set(projected["verification_expectations"])


def test_no_two_independently_authored_claude_definitions_exist():
    """Structural proof: the Claude artifact is ALWAYS produced by
    project_to_claude_skill/render_claude_skill_markdown from a real
    canonical SkillVersion - there is no second hand-authored template
    elsewhere in the skills package."""
    import pathlib
    skills_dir = pathlib.Path(__file__).resolve().parent.parent / "src" / "aep" / "skills"
    for path in skills_dir.glob("*.py"):
        if path.name == "claude_adapter.py":
            continue
        text = path.read_text()
        assert "canonical_skill_id" not in text, f"{path} independently constructs a Claude projection field"


def test_projecting_every_canonical_skill_is_deterministic(policy_path):
    from aep.db.fake import FakeSkillRepository, FakeSkillVersionRepository
    from aep.skills.definitions import seed_canonical_skills
    from aep.skills.registry import SkillRegistry

    reg = SkillRegistry(FakeSkillRepository(), FakeSkillVersionRepository(), policy_path=policy_path)
    seed_canonical_skills(reg)
    for skill in reg.list_skills():
        version = reg.latest_version(skill.skill_id)
        assert hash_projection(version) == hash_projection(version)
