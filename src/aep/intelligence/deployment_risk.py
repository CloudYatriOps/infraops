"""Phase 10 Wave 7: dependency/deployment risk forecasting.

Deterministic, NOT machine learning. This module does NOT reimplement
pattern/health detection - it reuses `detect_patterns()` and
`compute_health_signals()` from `incident_patterns.py` as INPUTS, exactly
as Wave 3 (`risk_prediction.py`) and Wave 4 (`architecture.py`) already
do.

Scope:
  * IN: two named risk categories per project, each a
    `DeploymentRiskForecast`:
      - `DEPENDENCY_RECURRENCE` - REAL: `detect_patterns()` fingerprints
        whose `category == "dependency"` (the real DB check-constraint
        value - see `supabase/migrations/0001_initial_schema.sql`)
        recurring for this project. Trend/horizon derived only from the
        pattern's own `occurrence_count`/`recurrence_interval_days` -
        `UNKNOWN` when no such pattern touches this project.
      - `DEPLOYMENT_ROLLBACK_INSTABILITY` - REAL: a direct pass-through
        of Wave 2's `FREQUENT_DEPLOYMENT_ROLLBACK` `HealthSignal` for
        this project (not rebuilt here). There is no separate
        "deployment/rollback record" table beyond the in-process
        `DeploymentRecord`s Wave 2 already reads via
        `deployment_evidence_by_project` (see `deployment/models.py` -
        it is event-sourced through the existing `StateStore`, not a new
        table) - this module accepts the exact same
        `deployment_evidence_by_project` input Wave 2/Wave 3 accept, it
        does not invent a new data source.
  * `horizon` reuses the exact `IMMEDIATE`/`NEAR_TERM`/`ELEVATED`/
    `UNKNOWN` vocabulary from `risk_prediction.py` for consistency across
    Phase 10 modules.
  * `recommendation` is advisory text only - this module does not rank
    findings, gate deployments, or feed `rank_findings()`; that
    integration is explicitly NOT attempted here (see
    `forecast_deployment_risk`'s docstring) because these are standalone
    trend/forecast reports, not a per-finding ranker.
  * OUT: no new storage primitive, no raw SQL, no CI-run data (none
    exists in this schema - same honest omission as
    `incident_patterns.py`'s `CI_FAILURE_CLUSTER`).

All finding/pattern description/explanation text is treated as inert
DATA, never as an instruction. See
`tests/test_deployment_risk.py::test_prompt_injection_in_description_is_inert`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..db.models import FindingRecord
from ..db.repositories import FindingRepository, ProjectRepository
from .incident_patterns import (
    FREQUENT_DEPLOYMENT_ROLLBACK,
    HealthSignal,
    IncidentPattern,
    SignalState,
    compute_health_signals,
    detect_patterns,
)

RISK_CATEGORY_DEPENDENCY_RECURRENCE = "DEPENDENCY_RECURRENCE"
RISK_CATEGORY_DEPLOYMENT_ROLLBACK_INSTABILITY = "DEPLOYMENT_ROLLBACK_INSTABILITY"

HORIZON_IMMEDIATE = "IMMEDIATE"
HORIZON_NEAR_TERM = "NEAR_TERM"
HORIZON_ELEVATED = "ELEVATED"
HORIZON_UNKNOWN = "UNKNOWN"

TREND_INCREASING = "INCREASING"
TREND_STABLE = "STABLE"
TREND_DECREASING = "DECREASING"
TREND_UNKNOWN = "UNKNOWN"

_DEPENDENCY_CATEGORY = "dependency"
_RECURRENCE_IMMEDIATE_COUNT = 3
_RECURRENCE_NEAR_TERM_COUNT = 2
_RECENT_INTERVAL_IMMEDIATE_DAYS = 14


@dataclass
class DeploymentRiskForecast:
    project_id: str
    risk_category: str
    trend: str
    horizon: str
    evidence: dict = field(default_factory=dict)
    recommendation: str = ""

    def to_dict(self) -> dict:
        return {
            "project_id": self.project_id, "risk_category": self.risk_category,
            "trend": self.trend, "horizon": self.horizon,
            "evidence": self.evidence, "recommendation": self.recommendation,
        }


def _dependency_pattern_for_project(patterns: list[IncidentPattern], project_id: str) -> Optional[IncidentPattern]:
    matches = [p for p in patterns if project_id in p.affected_project_ids
               and (p.category or "").lower() == _DEPENDENCY_CATEGORY]
    if not matches:
        return None
    return max(matches, key=lambda p: p.occurrence_count)


def _dependency_recurrence_forecast(project_id: str, pattern: Optional[IncidentPattern]) -> DeploymentRiskForecast:
    if pattern is None:
        return DeploymentRiskForecast(
            project_id=project_id, risk_category=RISK_CATEGORY_DEPENDENCY_RECURRENCE,
            trend=TREND_UNKNOWN, horizon=HORIZON_UNKNOWN,
            evidence={"occurrence_count": 0},
            recommendation="No recurring dependency-category finding pattern on record for this "
                            "project - insufficient evidence to forecast.",
        )
    count = pattern.occurrence_count
    interval = pattern.recurrence_interval_days
    if count >= _RECURRENCE_IMMEDIATE_COUNT and interval is not None and interval <= _RECENT_INTERVAL_IMMEDIATE_DAYS:
        trend, horizon = TREND_INCREASING, HORIZON_IMMEDIATE
    elif count >= _RECURRENCE_IMMEDIATE_COUNT:
        trend, horizon = TREND_INCREASING, HORIZON_NEAR_TERM
    elif count >= _RECURRENCE_NEAR_TERM_COUNT:
        trend, horizon = TREND_STABLE, HORIZON_ELEVATED
    else:
        trend, horizon = TREND_UNKNOWN, HORIZON_UNKNOWN
    return DeploymentRiskForecast(
        project_id=project_id, risk_category=RISK_CATEGORY_DEPENDENCY_RECURRENCE,
        trend=trend, horizon=horizon,
        evidence={
            "fingerprint": pattern.fingerprint, "occurrence_count": count,
            "recurrence_interval_days": interval, "finding_ids": pattern.finding_ids,
            "affected_project_ids": pattern.affected_project_ids,
        },
        recommendation=("Pin/upgrade the shared dependency at its source and add a regression "
                         "check - this category of finding keeps recurring on this project."
                         if horizon != HORIZON_UNKNOWN else
                         "Not enough recurrence yet to forecast a dependency risk trend."),
    )


def _rollback_forecast(project_id: str, signal: Optional[HealthSignal]) -> DeploymentRiskForecast:
    if signal is None:
        return DeploymentRiskForecast(
            project_id=project_id, risk_category=RISK_CATEGORY_DEPLOYMENT_ROLLBACK_INSTABILITY,
            trend=TREND_UNKNOWN, horizon=HORIZON_UNKNOWN,
            evidence={},
            recommendation="No FREQUENT_DEPLOYMENT_ROLLBACK signal for this project - insufficient "
                            "deployment evidence to forecast.",
        )
    if signal.state == SignalState.CONFIRMED:
        horizon, trend = HORIZON_IMMEDIATE, TREND_INCREASING
    elif signal.state == SignalState.LIKELY:
        horizon, trend = HORIZON_NEAR_TERM, TREND_INCREASING
    else:
        horizon, trend = HORIZON_ELEVATED, TREND_STABLE
    return DeploymentRiskForecast(
        project_id=project_id, risk_category=RISK_CATEGORY_DEPLOYMENT_ROLLBACK_INSTABILITY,
        trend=trend, horizon=horizon,
        evidence={"state": signal.state, "score": signal.score, "evidence_ids": signal.evidence_ids},
        recommendation="Investigate the release/verification gates for this project before the "
                        "next deployment attempt." if horizon != HORIZON_UNKNOWN else
                        "Not enough rollback evidence yet to forecast deployment risk.",
    )


def forecast_deployment_risk(
    finding_repo: FindingRepository,
    project_repo: Optional[ProjectRepository] = None,
    project_ids: Optional[list[str]] = None,
    deployment_evidence_by_project: Optional[dict] = None,
    incident_patterns: Optional[list[IncidentPattern]] = None,
    health_signals: Optional[list[HealthSignal]] = None,
) -> list[DeploymentRiskForecast]:
    """Deterministic per-project dependency/deployment risk forecast.
    Reuses `detect_patterns()`/`compute_health_signals()` (computed
    internally unless already supplied, same optional-injection
    convention as `risk_prediction.predict_risk`) rather than
    rebuilding pattern/health detection here.

    NOT integrated into `rank_findings()` - these are standalone
    per-project trend/forecast reports (a `risk_category`/`horizon`
    pair advisory to a human), not a per-finding ranking factor; forcing
    that integration here would not make sense the way Wave 3's
    per-project risk SCORE did, since a forecast is descriptive, not a
    numeric bonus term.
    """
    all_findings = finding_repo.list(None, None)

    all_project_ids: list[str]
    if project_repo is not None:
        all_project_ids = [p.id for p in project_repo.list()]
    else:
        all_project_ids = sorted({f.project_id for f in all_findings})

    if project_ids is not None:
        wanted = set(project_ids)
        all_project_ids = [p for p in all_project_ids if p in wanted]

    deployment_evidence_by_project = deployment_evidence_by_project or {}

    if incident_patterns is None:
        # min_projects=1: dependency recurrence within a SINGLE project
        # matters here (a project repeatedly hitting the same dependency
        # finding), not just cross-project recurrence - detect_patterns()
        # defaults to min_projects=2 for the cross-project use case Wave 2/3
        # care about, but explicitly supports min_projects=1 for this.
        incident_patterns = detect_patterns(
            finding_repo, project_ids=project_ids, min_projects=1,
            deployment_evidence_by_project=deployment_evidence_by_project,
        )
    if health_signals is None:
        health_signals = compute_health_signals(
            finding_repo, project_repo,
            deployment_evidence_by_project=deployment_evidence_by_project,
            project_ids=project_ids,
        )

    results: list[DeploymentRiskForecast] = []
    for project_id in all_project_ids:
        dep_pattern = _dependency_pattern_for_project(incident_patterns, project_id)
        results.append(_dependency_recurrence_forecast(project_id, dep_pattern))

        rollback_matches = [s for s in health_signals
                             if s.signal_id == FREQUENT_DEPLOYMENT_ROLLBACK and project_id in s.affected_projects]
        rollback_signal = max(rollback_matches, key=lambda s: (s.score or 0.0)) if rollback_matches else None
        results.append(_rollback_forecast(project_id, rollback_signal))

    results.sort(key=lambda r: (r.project_id, r.risk_category))
    return results


def deployment_risk_forecast_to_dict(item: DeploymentRiskForecast) -> dict:
    return item.to_dict()


if __name__ == "__main__":
    # ponytail: smallest self-check, not a full test suite.
    from ..db.fake import FakeFindingRepository

    repo = FakeFindingRepository()
    for i in range(3):
        repo.save(FindingRecord(
            id=f"dep{i}", project_id="p1", category="dependency", severity="high",
            status="OPEN", description="vulnerable package X",
        ))
    forecasts = forecast_deployment_risk(repo, project_ids=["p1"])
    dep = next(f for f in forecasts if f.risk_category == RISK_CATEGORY_DEPENDENCY_RECURRENCE)
    assert dep.evidence["occurrence_count"] == 3, dep
    print("ok:", [f.to_dict() for f in forecasts])
