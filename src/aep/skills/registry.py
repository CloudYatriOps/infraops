"""SkillRegistry (Stage B Parts 1-2, 12, 16): register/publish skills and
skill versions, resolve/list/validate them, resolve dependency graphs, and
self-validate a version's referenced tools/policies/checks against the
REAL platform surface before allowing it to be published.

Backed by a `SkillRepository`/`SkillVersionRepository` pair (ABC in
`db/repositories.py`; real Postgres implementation in `db/postgres.py`;
in-memory fake in `db/fake.py`) so the same registry logic runs
identically against either backend - this class contains no SQL and no
AI-provider dependency.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import cmp_to_key
from typing import Optional

from .known_capabilities import (
    KNOWN_VERIFICATION_CHECKS,
    REAL_TOOL_CAPABILITIES,
    real_policy_actions,
)
from .models import LifecycleState, Skill, SkillDependency, SkillVersion
from .versioning import compare_versions, satisfies
from ..db.models import SkillDependencyRecord, SkillRecord, SkillVersionRecord
from ..db.repositories import SkillRepository, SkillVersionRepository


def _skill_to_record(skill: Skill) -> SkillRecord:
    return SkillRecord(
        skill_id=skill.skill_id, name=skill.name, description=skill.description,
        purpose=skill.purpose, scope=skill.scope,
        created_at=skill.created_at, updated_at=skill.updated_at,
    )


def _record_to_skill(record: SkillRecord) -> Skill:
    return Skill(
        skill_id=record.skill_id, name=record.name, description=record.description,
        purpose=record.purpose, scope=record.scope,
        created_at=record.created_at, updated_at=record.updated_at,
    )


def _version_to_record(v: SkillVersion) -> SkillVersionRecord:
    return SkillVersionRecord(
        skill_id=v.skill_id, version=v.version, risk_level=v.risk_level.value if hasattr(v.risk_level, "value") else v.risk_level,
        description=v.description, purpose=v.purpose, scope=v.scope,
        capabilities=list(v.capabilities), allowed_tools=list(v.allowed_tools),
        prohibited_actions=list(v.prohibited_actions), required_checks=list(v.required_checks),
        verification_rules=list(v.verification_rules),
        dependencies=[SkillDependencyRecord(d.depends_on_skill_id, d.version_constraint) for d in v.dependencies],
        escalation_rules=list(v.escalation_rules), approval_requirements=list(v.approval_requirements),
        input_contract=dict(v.input_contract), output_contract=dict(v.output_contract),
        examples=list(v.examples),
        lifecycle_state=v.lifecycle_state.value if hasattr(v.lifecycle_state, "value") else v.lifecycle_state,
        compatibility_metadata=dict(v.compatibility_metadata),
        id=v.id, created_at=v.created_at, published_at=v.published_at, deprecated_at=v.deprecated_at,
    )


def _record_to_version(r: SkillVersionRecord) -> SkillVersion:
    from .models import RiskLevel
    return SkillVersion(
        skill_id=r.skill_id, version=r.version, risk_level=RiskLevel(r.risk_level),
        description=r.description, purpose=r.purpose, scope=r.scope,
        capabilities=list(r.capabilities), allowed_tools=list(r.allowed_tools),
        prohibited_actions=list(r.prohibited_actions), required_checks=list(r.required_checks),
        verification_rules=list(r.verification_rules),
        dependencies=[SkillDependency(d.depends_on_skill_id, d.version_constraint) for d in r.dependencies],
        escalation_rules=list(r.escalation_rules), approval_requirements=list(r.approval_requirements),
        input_contract=dict(r.input_contract), output_contract=dict(r.output_contract),
        examples=list(r.examples), lifecycle_state=LifecycleState(r.lifecycle_state),
        compatibility_metadata=dict(r.compatibility_metadata),
        id=r.id, created_at=r.created_at, published_at=r.published_at, deprecated_at=r.deprecated_at,
    )


class SkillValidationError(Exception):
    """Raised when a skill version claims a tool/capability/policy action/
    verification check that does not actually exist in this platform, or
    when structural validation otherwise fails. Publishing must never
    proceed past this."""


class SkillImmutabilityError(Exception):
    """Raised when something attempts to publish over an existing
    (skill_id, version) pair, or to mutate a published version's content -
    publishing a new version is always a NEW row, never an edit."""


class SkillNotFoundError(Exception):
    pass


@dataclass
class DependencyResolution:
    skill_id: str
    version: str
    ok: bool
    missing: list[str] = field(default_factory=list)      # depends_on_skill_id never registered
    conflicts: list[str] = field(default_factory=list)    # registered, but no version satisfies constraint
    cycle: Optional[list[str]] = None                      # the cycle path, if one was found
    resolved: list[tuple[str, str]] = field(default_factory=list)  # (skill_id, version) topological order


class SkillRegistry:
    def __init__(self, skill_repo: SkillRepository, skill_version_repo: SkillVersionRepository,
                 policy_path: Optional[str] = None):
        self._skills = skill_repo
        self._versions = skill_version_repo
        self._policy_path = policy_path

    # ---- registration -----------------------------------------------------

    def register_skill(self, skill: Skill) -> Skill:
        """Idempotent get-or-create of the skill's stable identity row."""
        existing = self._skills.get(skill.skill_id)
        if existing is not None:
            return _record_to_skill(existing)
        self._skills.save(_skill_to_record(skill))
        return skill

    def self_validate(self, version: SkillVersion) -> list[str]:
        """Part 16: reject a skill claiming nonexistent functionality.
        Returns a list of human-readable problems (empty = clean). Never
        raises itself - `publish` raises using this list."""
        problems: list[str] = []
        for tool in version.allowed_tools:
            if tool not in REAL_TOOL_CAPABILITIES:
                problems.append(f"allowed_tools references unknown tool capability: {tool!r}")
        for check in version.required_checks:
            if check not in KNOWN_VERIFICATION_CHECKS:
                problems.append(f"required_checks references unknown verification check: {check!r}")
        for check in version.verification_rules:
            if check not in KNOWN_VERIFICATION_CHECKS:
                problems.append(f"verification_rules references unknown verification check: {check!r}")
        if self._policy_path:
            known_actions = real_policy_actions(self._policy_path)
            for action in version.prohibited_actions:
                if action not in known_actions:
                    problems.append(f"prohibited_actions references unknown policy action: {action!r}")
        if not version.skill_id:
            problems.append("skill_id is required")
        try:
            from .versioning import parse_version
            parse_version(version.version)
        except ValueError as exc:
            problems.append(str(exc))
        return problems

    def publish(self, version: SkillVersion) -> SkillVersion:
        """Validates, then persists a NEW (skill_id, version) row. Refuses
        (SkillImmutabilityError) if that exact pair already exists -
        publishing a corrected version always means a new version string,
        never editing this one. Refuses (SkillValidationError) if
        self-validation finds any problem."""
        if self._skills.get(version.skill_id) is None:
            raise SkillNotFoundError(
                f"skill {version.skill_id!r} is not registered; call register_skill first"
            )
        existing = self._versions.get(version.skill_id, version.version)
        if existing is not None:
            raise SkillImmutabilityError(
                f"skill version {version.skill_id}@{version.version} already exists; "
                "publish a new version instead of republishing an existing one"
            )
        problems = self.self_validate(version)
        if problems:
            raise SkillValidationError(
                f"refusing to publish {version.skill_id}@{version.version}: " + "; ".join(problems)
            )
        version.lifecycle_state = LifecycleState.PUBLISHED
        version.published_at = version.published_at or datetime.now(timezone.utc)
        self._versions.save(_version_to_record(version))
        return version

    # ---- resolution ---------------------------------------------------------

    def get_version(self, skill_id: str, version: str) -> SkillVersion:
        found = self._versions.get(skill_id, version)
        if found is None:
            raise SkillNotFoundError(f"no such skill version: {skill_id}@{version}")
        return _record_to_version(found)

    def list_versions(self, skill_id: str) -> list[SkillVersion]:
        versions = [_record_to_version(r) for r in self._versions.list_for_skill(skill_id)]
        return sorted(versions, key=cmp_to_key(lambda a, b: compare_versions(a.version, b.version)))

    def latest_version(self, skill_id: str, include_deprecated: bool = False) -> SkillVersion:
        versions = [v for v in self.list_versions(skill_id) if v.lifecycle_state != LifecycleState.DRAFT]
        if not include_deprecated:
            versions = [v for v in versions if v.lifecycle_state != LifecycleState.DEPRECATED]
        if not versions:
            raise SkillNotFoundError(f"no published version available for skill {skill_id!r}")
        return versions[-1]

    def list_skills(self) -> list[Skill]:
        return [_record_to_skill(r) for r in self._skills.list()]

    def deprecate(self, skill_id: str, version: str) -> SkillVersion:
        found = self.get_version(skill_id, version)
        self._versions.mark_deprecated(skill_id, version)
        found = self.get_version(skill_id, version)
        return found

    def is_deprecated(self, skill_id: str, version: str) -> bool:
        return self.get_version(skill_id, version).lifecycle_state == LifecycleState.DEPRECATED

    # ---- dependency graph (Part 14) ------------------------------------------

    def resolve_dependencies(self, skill_id: str, version: str) -> DependencyResolution:
        """Resolves the full transitive dependency graph for one skill
        version, detecting missing skills, unsatisfiable version
        constraints, and cycles. Never silently ignores any of the three -
        `ok=False` with the specific reason populated instead."""
        root = self.get_version(skill_id, version)
        missing: list[str] = []
        conflicts: list[str] = []
        resolved: list[tuple[str, str]] = []
        visiting: list[str] = []
        visited: set[str] = set()
        cycle: Optional[list[str]] = None

        def visit(sid: str, ver: str) -> None:
            nonlocal cycle
            if cycle is not None:
                return
            if sid in visiting:
                cycle = visiting[visiting.index(sid):] + [sid]
                return
            if sid in visited:
                return
            visiting.append(sid)
            try:
                node = self.get_version(sid, ver)
            except SkillNotFoundError:
                visiting.pop()
                return
            for dep in node.dependencies:
                if self._skills.get(dep.depends_on_skill_id) is None:
                    missing.append(dep.depends_on_skill_id)
                    continue
                candidates = [
                    v for v in self.list_versions(dep.depends_on_skill_id)
                    if v.lifecycle_state == LifecycleState.PUBLISHED
                    and satisfies(v.version, dep.version_constraint)
                ]
                if not candidates:
                    conflicts.append(
                        f"{dep.depends_on_skill_id} {dep.version_constraint} (from {sid}@{ver})"
                    )
                    continue
                chosen = candidates[-1]
                visit(chosen.skill_id, chosen.version)
                if cycle is not None:
                    return
            visiting.pop()
            visited.add(sid)
            resolved.append((sid, ver))

        visit(skill_id, version)
        ok = not missing and not conflicts and cycle is None
        return DependencyResolution(
            skill_id=skill_id, version=version, ok=ok,
            missing=sorted(set(missing)), conflicts=sorted(set(conflicts)),
            cycle=cycle, resolved=resolved,
        )
