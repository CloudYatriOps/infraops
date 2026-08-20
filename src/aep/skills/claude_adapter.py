"""Deterministic projector: canonical AEP `SkillVersion` -> Claude-compatible
skill artifact (Stage B Part 11).

This is the ONLY place a canonical skill is turned into a Claude-facing
representation - there is no second, independently-authored Claude skill
definition anywhere in this platform. Running the SAME published
(skill_id, version) through `project_to_claude_skill` twice must produce
byte-identical output; see `tests/test_skills_claude_adapter.py` for the
repeated-hash proof this module is required to satisfy.

Determinism is achieved by: never reading a clock/random source, sorting
every list of unordered-but-set-like content, and serializing with
`json.dumps(..., sort_keys=True)` for the machine-readable form.
"""
from __future__ import annotations

import hashlib
import json

from .models import SkillVersion


def project_to_claude_skill(version: SkillVersion) -> dict:
    """Pure function of `version`'s content - deterministic, no I/O."""
    return {
        "canonical_skill_id": version.skill_id,
        "canonical_version": version.version,
        "generated_from": f"aep-skill-registry:{version.skill_id}@{version.version}",
        "name": version.skill_id,
        "description": version.description,
        "instructions": _render_instructions(version),
        "applicable_tools": sorted(version.allowed_tools),
        "prohibited_actions": sorted(version.prohibited_actions),
        "verification_expectations": sorted(set(version.required_checks) | set(version.verification_rules)),
        "safety_constraints": {
            "risk_level": version.risk_level.value if hasattr(version.risk_level, "value") else version.risk_level,
            "approval_requirements": sorted(version.approval_requirements),
            "escalation_rules": sorted(version.escalation_rules),
        },
        "dependencies": sorted(
            f"{d.depends_on_skill_id}{d.version_constraint}" for d in version.dependencies
        ),
    }


def _render_instructions(version: SkillVersion) -> str:
    """Deterministic markdown body. Field order is fixed (not iteration
    over a dict), and every list is sorted, so two calls with identical
    input always produce the identical string."""
    lines = [
        f"# {version.skill_id} (v{version.version})",
        "",
        f"Purpose: {version.purpose}",
        f"Scope: {version.scope}",
        "",
        "## Allowed tools",
    ]
    lines += [f"- {t}" for t in sorted(version.allowed_tools)] or ["- (none)"]
    lines += ["", "## Prohibited actions"]
    lines += [f"- {a}" for a in sorted(version.prohibited_actions)] or ["- (none)"]
    lines += ["", "## Required verification"]
    lines += [f"- {c}" for c in sorted(set(version.required_checks) | set(version.verification_rules))] or ["- (none)"]
    lines += ["", "## Escalation rules"]
    lines += [f"- {r}" for r in sorted(version.escalation_rules)] or ["- (none)"]
    return "\n".join(lines)


def render_claude_skill_markdown(version: SkillVersion) -> str:
    """Full SKILL.md-shaped artifact: a deterministic YAML-ish frontmatter
    block (hand-built, not a YAML dumper, so key order is exactly what
    this function writes rather than a library's own ordering choice)
    followed by the instructions body."""
    projected = project_to_claude_skill(version)
    frontmatter = "\n".join([
        "---",
        f"canonical_skill_id: {projected['canonical_skill_id']}",
        f"canonical_version: {projected['canonical_version']}",
        f"generated_from: {projected['generated_from']}",
        f"name: {projected['name']}",
        f"description: {projected['description']}",
        "---",
    ])
    return frontmatter + "\n\n" + projected["instructions"]


def hash_projection(version: SkillVersion) -> str:
    """SHA-256 of the deterministic JSON projection - used to prove
    repeated-run determinism without depending on markdown whitespace."""
    payload = json.dumps(project_to_claude_skill(version), sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
