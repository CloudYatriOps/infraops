"""Phase 9 Stage B: Canonical AEP Skill Registry & Claude Skill Adapter.

See ARCHITECTURE.md addendum "Phase 9 Stage B Addendum" and
`docs/SKILLS.md` for the full design. This package has zero AI-provider
dependency - a skill is declarative platform configuration, resolved
deterministically (`skills/loader.py`'s fixed task-intent rules), never an
AI-generated artifact.
"""
from .models import LifecycleState, RiskLevel, Skill, SkillDependency, SkillVersion
from .registry import (
    DependencyResolution,
    SkillImmutabilityError,
    SkillNotFoundError,
    SkillRegistry,
    SkillValidationError,
)
from .loader import ResolvedSkillSet, SkillResolutionError, resolve_required_skills

__all__ = [
    "LifecycleState", "RiskLevel", "Skill", "SkillDependency", "SkillVersion",
    "DependencyResolution", "SkillImmutabilityError", "SkillNotFoundError",
    "SkillRegistry", "SkillValidationError",
    "ResolvedSkillSet", "SkillResolutionError", "resolve_required_skills",
]
