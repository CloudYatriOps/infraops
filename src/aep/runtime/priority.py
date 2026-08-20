"""Deterministic, explainable priority model (Phase 8 Part 6).

No opaque AI scoring: every score is a sum of fixed, documented weights
over observable dimensions, and `explain()` always returns the exact
weighted contributions that produced the total - "no opaque AI scoring
without a deterministic fallback" per the spec, except here there IS no AI
scoring at all, only the deterministic model.
"""
from __future__ import annotations

from dataclasses import dataclass, field


# Fixed weights. Ordering intent (documented, not just implied by numbers):
#   CRITICAL production security issue > active production incident >
#   failed deployment > HIGH CVE > CI failure > scheduled maintenance scan
WEIGHTS = {
    "severity_critical": 1000,
    "severity_high": 400,
    "severity_medium": 150,
    "severity_low": 50,
    "production_impact": 300,
    "active_incident": 500,
    "deployment_blocked": 350,
    "recurrence": 100,       # per prior recurrence, capped
    "sla_age_per_hour": 5,   # capped
    "human_escalation": 250,
    "dependency_blocking_count": 20,  # per task this one unblocks, capped
}

_RECURRENCE_CAP = 5
_SLA_HOURS_CAP = 24
_DEPENDENCY_CAP = 10


@dataclass
class PriorityInput:
    task_type: str
    severity: str = "low"           # critical|high|medium|low
    production_impact: bool = False
    active_incident: bool = False
    deployment_blocked: bool = False
    recurrence_count: int = 0
    age_hours: float = 0.0
    human_escalation: bool = False
    blocks_other_tasks: int = 0


@dataclass
class PriorityScore:
    total: int
    contributions: dict = field(default_factory=dict)
    reason: str = ""

    def to_dict(self) -> dict:
        return {"total": self.total, "contributions": self.contributions, "reason": self.reason}


def score(pi: PriorityInput) -> PriorityScore:
    contributions: dict[str, int] = {}

    sev_key = f"severity_{pi.severity}" if pi.severity in ("critical", "high", "medium", "low") else None
    if sev_key:
        contributions["severity"] = WEIGHTS[sev_key]

    if pi.production_impact:
        contributions["production_impact"] = WEIGHTS["production_impact"]
    if pi.active_incident:
        contributions["active_incident"] = WEIGHTS["active_incident"]
    if pi.deployment_blocked:
        contributions["deployment_blocked"] = WEIGHTS["deployment_blocked"]
    if pi.recurrence_count:
        contributions["recurrence"] = WEIGHTS["recurrence"] * min(pi.recurrence_count, _RECURRENCE_CAP)
    if pi.age_hours:
        contributions["sla_age"] = int(WEIGHTS["sla_age_per_hour"] * min(pi.age_hours, _SLA_HOURS_CAP))
    if pi.human_escalation:
        contributions["human_escalation"] = WEIGHTS["human_escalation"]
    if pi.blocks_other_tasks:
        contributions["dependency_blocking"] = (
            WEIGHTS["dependency_blocking_count"] * min(pi.blocks_other_tasks, _DEPENDENCY_CAP)
        )

    total = sum(contributions.values())
    parts = ", ".join(f"{k}={v}" for k, v in contributions.items()) or "no scoring dimension matched"
    reason = f"priority {total} for task_type={pi.task_type}: {parts}"
    return PriorityScore(total=total, contributions=contributions, reason=reason)
