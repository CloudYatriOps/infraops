"""Canonical AEP skill model (Phase 9 Stage B, Part 1).

A `Skill` is the stable identity (skill_id, name, description) a canonical
capability procedure is published under. A `SkillVersion` is one immutable,
published snapshot of that procedure's content. Publishing a NEW version
never mutates an existing `SkillVersion` row - see `SkillRegistry.publish`
and the DB-level immutability trigger in
`supabase/migrations/0006_skill_registry.sql`.

These are plain dataclasses with zero AI-provider dependency - a skill is
declarative platform configuration, not a prompt template and not
something an `AIProvider` produces or consumes directly. `ClaudeSkillAdapter`
(claude_adapter.py) is the only place a canonical skill is projected into a
Claude-specific artifact, and it is a pure deterministic function of a
published `SkillVersion` - never a second, independently-authored
definition.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


def now() -> datetime:
    return datetime.now(timezone.utc)


class LifecycleState(str, Enum):
    DRAFT = "draft"
    PUBLISHED = "published"
    DEPRECATED = "deprecated"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class SkillDependency:
    """A dependency of one skill version on another SKILL (not a specific
    version) plus a version constraint. Constraints are simple and
    explicit - exact ("==1.0.0"), minimum ("&gt;=1.0.0"), or "*" (any
    published version) - deliberately not a full semver range grammar,
    since Stage B has no need for one yet and inventing one would be
    unverified surface area."""
    depends_on_skill_id: str
    version_constraint: str = "*"


@dataclass
class Skill:
    """The stable identity a skill's versions are published under. Never
    holds content itself - only bookkeeping (id/name/description/purpose/
    scope/lifecycle of the skill AS A LINE, independent of any one
    version)."""
    skill_id: str
    name: str
    description: str = ""
    purpose: str = ""
    scope: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


@dataclass
class SkillVersion:
    """One immutable, content-addressed snapshot of a skill's procedure.

    `version` follows a plain `MAJOR.MINOR.PATCH` string (compared via
    `versioning.parse_version`/`compare_versions`, not `packaging`, to
    avoid a new dependency for three integers).
    """
    skill_id: str
    version: str
    risk_level: RiskLevel = RiskLevel.LOW
    description: str = ""
    purpose: str = ""
    scope: str = ""
    capabilities: list[str] = field(default_factory=list)
    allowed_tools: list[str] = field(default_factory=list)
    prohibited_actions: list[str] = field(default_factory=list)
    required_checks: list[str] = field(default_factory=list)
    verification_rules: list[str] = field(default_factory=list)
    dependencies: list[SkillDependency] = field(default_factory=list)
    escalation_rules: list[str] = field(default_factory=list)
    approval_requirements: list[str] = field(default_factory=list)
    input_contract: dict = field(default_factory=dict)
    output_contract: dict = field(default_factory=dict)
    examples: list[dict] = field(default_factory=list)
    lifecycle_state: LifecycleState = LifecycleState.DRAFT
    compatibility_metadata: dict = field(default_factory=dict)
    id: Optional[str] = None  # DB-assigned uuid; None until persisted
    created_at: Optional[datetime] = None
    published_at: Optional[datetime] = None
    deprecated_at: Optional[datetime] = None

    def key(self) -> tuple[str, str]:
        return (self.skill_id, self.version)
