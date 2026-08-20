"""Runtime skill loading before task execution (Stage B Parts 6, 14, 15).

`TASK_SKILL_RULES` is the deterministic, non-LLM capability resolver Part
14 requires: an explicit, fixed mapping from task intent -> required/
optional/forbidden skill ids. AI assistance (if ever added) would only be
allowed as an ADDITIONAL, optional enhancement layer on top of this
table - never the sole mechanism - and nothing in this module calls an AI
provider at all.

`resolve_required_skills` is the pre-execution gate: it resolves every
required skill's latest PUBLISHED version, walks its dependency graph, and
raises `SkillResolutionError` (never silently downgrades/skips) if any
required skill is missing, has no published version, or has an unresolved
dependency (missing/conflict/cycle). A caller (agent/orchestrator
integration point) is expected to stop/escalate the task on this
exception rather than proceeding without it - see
`tests/test_skills_runtime_integration.py` for a real proof that a task
genuinely cannot execute without its required skills resolved.

Skills never bypass `PolicyEngine` (Part 7): this module never evaluates
policy itself and grants no tool access - it only decides WHICH skill
versions must be loaded and validates that their `allowed_tools` are a
subset of what the caller's real tool registry actually has registered.
The policy decision for any concrete action a skill describes is still
made exclusively by `PolicyEngine.evaluate` at the point the action is
attempted, exactly as before Stage B existed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .models import SkillVersion
from .registry import SkillNotFoundError, SkillRegistry

# Fixed, explicit, deterministic task-intent -> skill mapping (Part 14).
# Task type strings match the real task `type` values agents/orchestrator
# code already uses (e.g. "security_scan", "deployment", ...) or a
# reasonable canonical name for a task class this stage introduces no new
# agent for. Not every existing Phase 1-8 task type is listed here -
# unlisted task types simply have no Stage B skill requirement (this
# module is purely additive; it does not retroactively gate work that
# never asked for skill resolution before Stage B existed).
TASK_SKILL_RULES: dict[str, dict[str, list[str]]] = {
    "security_scan": {"required": ["security"], "optional": ["sast", "secrets", "dependency-cve"], "forbidden": []},
    "sast_scan": {"required": ["sast"], "optional": [], "forbidden": []},
    "secret_scan": {"required": ["secrets"], "optional": [], "forbidden": []},
    "dependency_scan": {"required": ["dependency-cve"], "optional": [], "forbidden": []},
    "terraform_review": {"required": ["terraform"], "optional": ["security", "testing"], "forbidden": []},
    "kubernetes_review": {"required": ["kubernetes"], "optional": ["security"], "forbidden": []},
    "helm_review": {"required": ["helm"], "optional": ["kubernetes", "security"], "forbidden": []},
    "cicd_pipeline": {"required": ["cicd", "testing"], "optional": [], "forbidden": []},
    "deployment": {"required": ["deployment", "testing", "security"], "optional": [], "forbidden": []},
    "incident_response": {"required": ["incident-response"], "optional": ["database", "security"], "forbidden": []},
    "database_migration": {"required": ["database", "postgresql"], "optional": [], "forbidden": []},
    "git_operation": {"required": ["git"], "optional": [], "forbidden": []},
    "github_operation": {"required": ["github", "git"], "optional": [], "forbidden": []},
    "architecture_review": {"required": ["architecture-review"], "optional": ["security", "testing"], "forbidden": []},
    "code_review": {"required": ["code-review", "testing"], "optional": [], "forbidden": []},
    "testing": {"required": ["testing"], "optional": [], "forbidden": []},
    "cost_optimization": {"required": ["cost-optimization"], "optional": ["dependency-cve"], "forbidden": []},
}


class SkillResolutionError(Exception):
    """Raised when a required skill cannot be resolved (not registered, no
    published version, or an unresolved dependency). A task MUST stop/
    escalate on this, never proceed as if the skill were optional."""


@dataclass
class ResolvedSkillSet:
    task_type: str
    required: list[SkillVersion] = field(default_factory=list)
    optional: list[SkillVersion] = field(default_factory=list)
    unavailable_optional: list[str] = field(default_factory=list)  # optional skills that failed to resolve - reported, not hidden

    def evidence_payload(self) -> dict:
        """Exactly what Part 15 requires every meaningful agent run's
        evidence to record: skill ids+versions+dependencies+tools+
        policies-referenced+verification performed."""
        def _entry(v: SkillVersion) -> dict:
            return {
                "skill_id": v.skill_id,
                "version": v.version,
                "dependencies": [f"{d.depends_on_skill_id}{d.version_constraint}" for d in v.dependencies],
                "allowed_tools": sorted(v.allowed_tools),
                "prohibited_actions": sorted(v.prohibited_actions),
                "required_checks": sorted(v.required_checks),
                "verification_rules": sorted(v.verification_rules),
            }
        return {
            "task_type": self.task_type,
            "required_skills": [_entry(v) for v in self.required],
            "optional_skills": [_entry(v) for v in self.optional],
            "unavailable_optional_skills": sorted(self.unavailable_optional),
        }


def resolve_required_skills(task_type: str, registry: SkillRegistry,
                             tool_capabilities: Optional[set[str]] = None) -> ResolvedSkillSet:
    """The pre-execution gate. Raises `SkillResolutionError` (stop, never
    silently downgrade) if:
      * `task_type` has a rule and any REQUIRED skill has no resolvable
        published version, or
      * any required skill's dependency graph has a missing/conflicting/
        cyclical dependency, or
      * `tool_capabilities` is given and a required skill's
        `allowed_tools` is not a subset of it (the skill would describe a
        procedure this caller's real tool registry cannot actually back).
    A task type with no rule at all resolves to an empty required set -
    Stage B is additive and does not retroactively gate task types nobody
    asked it to gate.
    """
    rule = TASK_SKILL_RULES.get(task_type, {"required": [], "optional": [], "forbidden": []})
    result = ResolvedSkillSet(task_type=task_type)

    for skill_id in rule.get("required", []):
        try:
            version = registry.latest_version(skill_id)
        except SkillNotFoundError as exc:
            raise SkillResolutionError(
                f"required skill {skill_id!r} for task type {task_type!r} has no published "
                f"version; task must stop/escalate rather than proceed without it: {exc}"
            ) from exc
        dep_res = registry.resolve_dependencies(skill_id, version.version)
        if not dep_res.ok:
            raise SkillResolutionError(
                f"required skill {skill_id}@{version.version} has unresolved dependencies: "
                f"missing={dep_res.missing} conflicts={dep_res.conflicts} cycle={dep_res.cycle}"
            )
        if tool_capabilities is not None:
            missing_tools = set(version.allowed_tools) - tool_capabilities
            if missing_tools:
                raise SkillResolutionError(
                    f"required skill {skill_id}@{version.version} declares allowed_tools "
                    f"{sorted(missing_tools)} not present in the caller's real tool registry - "
                    "a skill can never grant capability the tool registry does not already have"
                )
        result.required.append(version)

    for skill_id in rule.get("optional", []):
        try:
            version = registry.latest_version(skill_id)
        except SkillNotFoundError:
            result.unavailable_optional.append(skill_id)
            continue
        dep_res = registry.resolve_dependencies(skill_id, version.version)
        if dep_res.ok:
            result.optional.append(version)
        else:
            result.unavailable_optional.append(skill_id)

    return result
