"""Phase 10 Wave 3: evidence-based predictive risk intelligence.

Deterministic, NOT machine learning - a per-project weighted score built
entirely from real persisted evidence, reusing `detect_patterns()` and
`compute_health_signals()` from `incident_patterns.py` as INPUTS rather
than re-deriving pattern/health detection here (same "inputs only, no
duplicated engine" discipline as Wave 2's own relationship to
`FindingRepository`/deployment evidence/incident memory).

Scope:
  * IN: a per-project `RiskPrediction` (risk_horizon, trend, score,
    factor breakdown, explanation) computed from findings + the
    patterns/signals Wave 2 already knows how to detect.
  * OUT: no new storage primitive, no raw SQL, no second ranking engine -
    the output plugs into the EXISTING `rank_findings()` in
    `prioritization.py` as one more optional factor.
  * Wave 3 uses persisted current/historical evidence only, no memory
    integration - `MemoryRecord`/`MemoryRepository` are not consulted
    anywhere in this module. If a future wave adds memory as an advisory
    input here, it must keep memory strictly lower-weight and prove (with
    a test, not just a claim) that current live evidence always outranks
    it, matching `incident_patterns.py::test_current_evidence_outranks_memory`.

All finding/pattern/signal description/explanation text is treated as
inert data for scoring purposes only - never as an instruction. See
`tests/test_risk_prediction.py::test_prompt_injection_in_description_is_inert`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from ..db.models import FindingRecord, ProjectRecord
from ..db.repositories import FindingRepository, ProjectRepository
from .incident_patterns import (
    FREQUENT_DEPLOYMENT_ROLLBACK,
    REPEATED_FAILED_REMEDIATION,
    UNRESOLVED_CRITICAL_FINDINGS,
    HealthSignal,
    IncidentPattern,
    SignalState,
    compute_health_signals,
    detect_patterns,
)

# ---------------------------------------------------------------------------
# Factor weights. Named literals, deterministic, sum to 1.0.
# ---------------------------------------------------------------------------
WEIGHT_RECURRENCE_RATE = 0.20            # cross-project pattern occurrence for this project
WEIGHT_SEVERITY_TREND = 0.15             # 30d-window critical/high finding trend
WEIGHT_PRODUCTION_IMPACT = 0.15          # fraction of open findings affecting production
WEIGHT_RECENT_INCIDENT_ACTIVITY = 0.15   # incident-memory activity in the last 30 days
WEIGHT_UNRESOLVED_CRITICAL_FINDINGS = 0.15  # from Wave 2's UNRESOLVED_CRITICAL_FINDINGS signal
WEIGHT_FAILED_REMEDIATION_COUNT = 0.10   # from Wave 2's REPEATED_FAILED_REMEDIATION signal
WEIGHT_DEPLOYMENT_INSTABILITY = 0.10     # from Wave 2's FREQUENT_DEPLOYMENT_ROLLBACK signal

_TOTAL_WEIGHT = (WEIGHT_RECURRENCE_RATE + WEIGHT_SEVERITY_TREND + WEIGHT_PRODUCTION_IMPACT
                 + WEIGHT_RECENT_INCIDENT_ACTIVITY + WEIGHT_UNRESOLVED_CRITICAL_FINDINGS
                 + WEIGHT_FAILED_REMEDIATION_COUNT + WEIGHT_DEPLOYMENT_INSTABILITY)
assert abs(_TOTAL_WEIGHT - 1.0) < 1e-9, f"risk_prediction weights must sum to 1.0, got {_TOTAL_WEIGHT}"

# `failed_remediation_count` and `deployment_instability` DO have a real
# data source in this schema (`IncidentMemoryRecord.remediation_succeeded`
# via `incidents_by_project`, and `DeploymentRecord.final_state` via
# `deployment_evidence_by_project` - the same sources Wave 2's
# `REPEATED_FAILED_REMEDIATION`/`FREQUENT_DEPLOYMENT_ROLLBACK` signals
# already use) so their weights are kept nonzero. Both parameters are
# OPTIONAL (default `{}`), matching `compute_health_signals`'s own
# optional-injection convention - when omitted, their raw/score are
# honestly 0.0, never invented.

_RECURRENCE_CAP = 5
_RECENT_INCIDENT_CAP = 5
_RECENT_WINDOW_DAYS = 30
_PREVIOUS_WINDOW_DAYS = 60
_RECENT_PATTERN_HORIZON_DAYS = 14  # a CONFIRMED cross-project pattern seen this recently -> IMMEDIATE

RISK_HORIZON_IMMEDIATE = "IMMEDIATE"
RISK_HORIZON_NEAR_TERM = "NEAR_TERM"
RISK_HORIZON_ELEVATED = "ELEVATED"
RISK_HORIZON_UNKNOWN = "UNKNOWN"

TREND_INCREASING = "INCREASING"
TREND_STABLE = "STABLE"
TREND_DECREASING = "DECREASING"
TREND_UNKNOWN = "UNKNOWN"


@dataclass
class RiskPrediction:
    project_id: str
    risk_horizon: str
    trend: str
    score: float
    breakdown: dict = field(default_factory=dict)
    explanation: str = ""

    def to_dict(self) -> dict:
        return {
            "project_id": self.project_id, "risk_horizon": self.risk_horizon,
            "trend": self.trend, "score": round(self.score, 6),
            "breakdown": self.breakdown, "explanation": self.explanation,
        }


def _age_days(dt) -> Optional[float]:
    if dt is None:
        return None
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt)
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max((datetime.now(timezone.utc) - dt).total_seconds() / 86400.0, 0.0)


def _severity_trend(findings: list[FindingRecord]) -> tuple[str, float]:
    """Real-evidence-only trend: compares the count of critical/high
    findings discovered in the last 30 days vs the prior 30-day window
    (same two windows Wave 2's `SECURITY_FINDINGS_INCREASING` compares).
    Returns `(trend, score)`; `UNKNOWN`/0.0 when fewer than 2 dated
    critical/high findings exist - never guessed from a single point."""
    dated = [f for f in findings if f.discovered_at is not None
             and (f.severity or "").lower() in ("critical", "high")]
    if len(dated) < 2:
        return TREND_UNKNOWN, 0.0
    recent = sum(1 for f in dated if _age_days(f.discovered_at) <= _RECENT_WINDOW_DAYS)
    previous = sum(1 for f in dated
                    if _RECENT_WINDOW_DAYS < _age_days(f.discovered_at) <= _PREVIOUS_WINDOW_DAYS)
    if recent > previous:
        return TREND_INCREASING, 1.0
    if recent < previous:
        return TREND_DECREASING, 0.0
    return TREND_STABLE, 0.5


def _production_impact_score(findings: list[FindingRecord], project: Optional[ProjectRecord]) -> float:
    open_findings = [f for f in findings if f.status == "OPEN"]
    if not open_findings:
        return 0.0
    prod_count = 0
    for f in open_findings:
        env = (f.evidence or {}).get("environment")
        if env and str(env).lower() in ("production", "prod"):
            prod_count += 1
        elif project is not None and project.default_posture == "deny":
            prod_count += 1
    return prod_count / len(open_findings)


def _signal_for_project(signals: list[HealthSignal], signal_id: str, project_id: str) -> Optional[HealthSignal]:
    matches = [s for s in signals if s.signal_id == signal_id and project_id in s.affected_projects]
    if not matches:
        return None
    # Deterministic: the strongest (highest score) match for this project.
    return max(matches, key=lambda s: (s.score or 0.0, s.state))


def _recurrence_for_project(patterns: list[IncidentPattern], project_id: str) -> tuple[int, float, Optional[IncidentPattern]]:
    matches = [p for p in patterns if project_id in p.affected_project_ids]
    if not matches:
        return 0, 0.0, None
    top = max(matches, key=lambda p: p.occurrence_count)
    return top.occurrence_count, min(top.occurrence_count / _RECURRENCE_CAP, 1.0), top


def _recent_incident_activity(incidents: list) -> tuple[int, float]:
    count = 0
    for inc in incidents:
        age = _age_days(getattr(inc, "recorded_at", None))
        if age is not None and age <= _RECENT_WINDOW_DAYS:
            count += 1
    return count, min(count / _RECENT_INCIDENT_CAP, 1.0)


def _risk_horizon(
    has_evidence: bool,
    trend: str,
    unresolved_signal: Optional[HealthSignal],
    recurrence_pattern: Optional[IncidentPattern],
    project_pattern_recency_days: Optional[float],
    other_project_signals: list[HealthSignal],
) -> str:
    if not has_evidence:
        return RISK_HORIZON_UNKNOWN
    if unresolved_signal is not None and unresolved_signal.state == SignalState.CONFIRMED:
        return RISK_HORIZON_IMMEDIATE
    if (recurrence_pattern is not None and project_pattern_recency_days is not None
            and project_pattern_recency_days <= _RECENT_PATTERN_HORIZON_DAYS
            and recurrence_pattern.occurrence_count >= 3):
        return RISK_HORIZON_IMMEDIATE
    if trend == TREND_INCREASING:
        return RISK_HORIZON_NEAR_TERM
    if any(s.state in (SignalState.CONFIRMED, SignalState.LIKELY) for s in other_project_signals):
        return RISK_HORIZON_NEAR_TERM
    return RISK_HORIZON_ELEVATED


def predict_risk(
    finding_repo: FindingRepository,
    project_repo: Optional[ProjectRepository] = None,
    project_ids: Optional[list[str]] = None,
    incident_patterns: Optional[list[IncidentPattern]] = None,
    health_signals: Optional[list[HealthSignal]] = None,
    deployment_evidence_by_project: Optional[dict] = None,
    incidents_by_project: Optional[dict] = None,
) -> list[RiskPrediction]:
    """Deterministic per-project risk prediction. Reuses `detect_patterns()`
    / `compute_health_signals()` (computed internally unless already
    provided by the caller - mirrors `incident_patterns.py`'s own
    optional-injection style) rather than re-deriving pattern/health
    detection here.
    """
    all_findings = finding_repo.list(None, None)

    projects_by_id: dict[str, ProjectRecord] = {}
    all_project_ids: list[str]
    if project_repo is not None:
        all_projects = project_repo.list()
        projects_by_id = {p.id: p for p in all_projects}
        all_project_ids = [p.id for p in all_projects]
    else:
        all_project_ids = sorted({f.project_id for f in all_findings})

    if project_ids is not None:
        wanted = set(project_ids)
        all_project_ids = [p for p in all_project_ids if p in wanted]

    deployment_evidence_by_project = deployment_evidence_by_project or {}
    incidents_by_project = incidents_by_project or {}

    if incident_patterns is None:
        incident_patterns = detect_patterns(
            finding_repo, project_ids=project_ids,
            deployment_evidence_by_project=deployment_evidence_by_project,
        )
    if health_signals is None:
        health_signals = compute_health_signals(
            finding_repo, project_repo,
            deployment_evidence_by_project=deployment_evidence_by_project,
            incidents_by_project=incidents_by_project, project_ids=project_ids,
        )

    findings_by_project: dict[str, list[FindingRecord]] = {}
    for f in all_findings:
        findings_by_project.setdefault(f.project_id, []).append(f)

    results: list[RiskPrediction] = []
    for project_id in all_project_ids:
        project = projects_by_id.get(project_id)
        findings = findings_by_project.get(project_id, [])
        has_evidence = bool(findings)

        trend, trend_score = _severity_trend(findings)
        recurrence_count, recurrence_score, recurrence_pattern = _recurrence_for_project(
            incident_patterns, project_id)
        prod_score = _production_impact_score(findings, project)
        incidents = incidents_by_project.get(project_id, [])
        incident_count, incident_score = _recent_incident_activity(incidents)

        unresolved_signal = _signal_for_project(health_signals, UNRESOLVED_CRITICAL_FINDINGS, project_id)
        unresolved_score = unresolved_signal.score if unresolved_signal else 0.0
        failed_remediation_signal = _signal_for_project(health_signals, REPEATED_FAILED_REMEDIATION, project_id)
        failed_remediation_score = failed_remediation_signal.score if failed_remediation_signal else 0.0
        rollback_signal = _signal_for_project(health_signals, FREQUENT_DEPLOYMENT_ROLLBACK, project_id)
        rollback_score = rollback_signal.score if rollback_signal else 0.0

        breakdown = {
            "recurrence_rate": {
                "raw": recurrence_count, "score": recurrence_score, "weight": WEIGHT_RECURRENCE_RATE,
                "contribution": recurrence_score * WEIGHT_RECURRENCE_RATE,
                "note": "max cross-project IncidentPattern.occurrence_count touching this project "
                        "(detect_patterns()), capped at 5",
            },
            "severity_trend": {
                "raw": trend, "score": trend_score, "weight": WEIGHT_SEVERITY_TREND,
                "contribution": trend_score * WEIGHT_SEVERITY_TREND,
                "note": "30d-window vs prior-30d-window critical/high finding count comparison; "
                        "UNKNOWN/0.0 when fewer than 2 dated critical/high findings exist",
            },
            "production_impact": {
                "raw": round(prod_score, 4), "score": prod_score, "weight": WEIGHT_PRODUCTION_IMPACT,
                "contribution": prod_score * WEIGHT_PRODUCTION_IMPACT,
                "note": "fraction of this project's OPEN findings tagged production "
                        "(evidence['environment']) or covered by a deny-posture project default",
            },
            "recent_incident_activity": {
                "raw": incident_count, "score": incident_score, "weight": WEIGHT_RECENT_INCIDENT_ACTIVITY,
                "contribution": incident_score * WEIGHT_RECENT_INCIDENT_ACTIVITY,
                "note": "count of IncidentMemoryRecord.recorded_at within the last 30 days for this "
                        "project (incidents_by_project, optional - 0 when omitted), capped at 5",
            },
            "unresolved_critical_findings": {
                "raw": unresolved_signal.evidence_ids if unresolved_signal else [],
                "score": unresolved_score, "weight": WEIGHT_UNRESOLVED_CRITICAL_FINDINGS,
                "contribution": unresolved_score * WEIGHT_UNRESOLVED_CRITICAL_FINDINGS,
                "note": "compute_health_signals()'s UNRESOLVED_CRITICAL_FINDINGS signal score for "
                        "this project, reused directly (not recomputed here)",
            },
            "failed_remediation_count": {
                "raw": failed_remediation_signal.evidence_ids if failed_remediation_signal else [],
                "score": failed_remediation_score, "weight": WEIGHT_FAILED_REMEDIATION_COUNT,
                "contribution": failed_remediation_score * WEIGHT_FAILED_REMEDIATION_COUNT,
                "note": "compute_health_signals()'s REPEATED_FAILED_REMEDIATION signal score "
                        "(from IncidentMemoryRecord.remediation_succeeded, via incidents_by_project - "
                        "optional, 0.0 when not supplied)",
            },
            "deployment_instability": {
                "raw": rollback_signal.evidence_ids if rollback_signal else [],
                "score": rollback_score, "weight": WEIGHT_DEPLOYMENT_INSTABILITY,
                "contribution": rollback_score * WEIGHT_DEPLOYMENT_INSTABILITY,
                "note": "compute_health_signals()'s FREQUENT_DEPLOYMENT_ROLLBACK signal score "
                        "(from DeploymentRecord.final_state, via deployment_evidence_by_project - "
                        "optional, 0.0 when not supplied)",
            },
        }
        total = sum(v["contribution"] for v in breakdown.values())

        other_signals = [s for s in health_signals if project_id in s.affected_projects
                          and s.signal_id != UNRESOLVED_CRITICAL_FINDINGS]
        project_pattern_recency_days: Optional[float] = None
        if recurrence_pattern is not None:
            own_ts = [f.discovered_at for f in findings
                      if f.id in recurrence_pattern.finding_ids and f.discovered_at is not None]
            if own_ts:
                project_pattern_recency_days = _age_days(max(own_ts))
        horizon = _risk_horizon(has_evidence, trend, unresolved_signal, recurrence_pattern,
                                 project_pattern_recency_days, other_signals)

        explanation_parts = [f"project {project_id}: score={total:.4f}, trend={trend}, horizon={horizon}."]
        if recurrence_pattern is not None:
            explanation_parts.append(
                f"Recurring pattern {recurrence_pattern.fingerprint!r} seen "
                f"{recurrence_pattern.occurrence_count} time(s) across "
                f"{len(recurrence_pattern.affected_project_ids)} project(s).")
        if unresolved_signal is not None:
            explanation_parts.append(unresolved_signal.explanation)
        if not has_evidence:
            explanation_parts.append("No findings on record for this project - insufficient evidence.")

        results.append(RiskPrediction(
            project_id=project_id, risk_horizon=horizon, trend=trend, score=total,
            breakdown=breakdown, explanation=" ".join(explanation_parts),
        ))

    results.sort(key=lambda r: (-r.score, r.project_id))
    return results


def risk_prediction_to_dict(item: RiskPrediction) -> dict:
    return item.to_dict()


def risk_prediction_score_map(predictions: list[RiskPrediction]) -> dict:
    """`{project_id: score}` map for `prioritization.rank_findings()`'s
    optional `risk_scores_by_project` bonus factor."""
    return {p.project_id: p.score for p in predictions}
