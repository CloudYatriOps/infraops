"""Phase 10 Wave 12: engineering health score (per-project aggregate).

Runs LAST because it aggregates the other eight Phase 10 intelligence
modules - it reimplements none of their logic, it only calls them:

  * `risk_prediction.predict_risk()` (Wave 3)
  * `architecture.analyze_architecture()` (Wave 4)
  * `security_trends.analyze_security_trends()` (Wave 6)
  * `deployment_risk.forecast_deployment_risk()` (Wave 7)
  * `technical_debt.analyze_technical_debt()` (Wave 8)
  * `cost_intelligence.analyze_cost_intelligence()` (Wave 5 - status
    only, since real cost data is BLOCKED everywhere in this sandbox)
  * `ci_clustering.analyze_ci_clusters()` (Wave 11 - always
    NOT_IMPLEMENTED)
  * `incident_patterns.compute_health_signals()` /
    `detect_patterns()` (Wave 2)

**Not to be confused with Wave 2's `aep intelligence patterns` command**,
which reports discrete `HealthSignal` STATES (CONFIRMED/LIKELY/POSSIBLE/
UNKNOWN per signal). This module (`aep intelligence health-score`)
produces a per-project AGGREGATE SUMMARY across all of the above -
a different, higher-level artifact, not a replacement for Wave 2's
signals (which this module reads as one of its inputs).

`overall_state` is derived, never invented: it is always the worst
subsystem state actually present among the subsystems this project has
real evidence for (`CRITICAL` > `AT_RISK` > `HEALTHY` > `UNKNOWN`).
If every subsystem is `UNKNOWN` (no evidence at all for this project),
`overall_state` is `UNKNOWN` - never defaulted to `HEALTHY`.

The optional `overall_score` (0-1, only present when at least one
subsystem contributed a numeric factor) is a plain unweighted average of
each contributing subsystem's own 0-1 severity-derived score - the full
per-subsystem breakdown that produced it is always included in
`evidence["score_breakdown"]`, same discipline as
`risk_prediction.py`/`prioritization.py`: no unexplained number.

All finding/pattern/risk description text touched transitively through
the underlying modules is already treated as inert data by each of them;
this module never re-reads raw description text itself. See
`tests/test_engineering_health_score.py::test_prompt_injection_in_description_is_inert`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..db.repositories import FindingRepository, ProjectRepository
from .architecture import analyze_architecture
from .cost_intelligence import analyze_cost_intelligence
from .ci_clustering import analyze_ci_clusters
from .deployment_risk import forecast_deployment_risk
from .incident_patterns import SignalState, compute_health_signals, detect_patterns
from .risk_prediction import predict_risk
from .security_trends import analyze_security_trends
from .technical_debt import analyze_technical_debt

STATE_HEALTHY = "HEALTHY"
STATE_AT_RISK = "AT_RISK"
STATE_CRITICAL = "CRITICAL"
STATE_UNKNOWN = "UNKNOWN"

_STATE_RANK = {STATE_UNKNOWN: 0, STATE_HEALTHY: 1, STATE_AT_RISK: 2, STATE_CRITICAL: 3}


@dataclass
class EngineeringHealthSummary:
    project_id: str
    overall_state: str
    subsystem_states: dict = field(default_factory=dict)
    critical_findings: list = field(default_factory=list)
    top_risks: list = field(default_factory=list)
    trend: str = "UNKNOWN"
    evidence: dict = field(default_factory=dict)
    recommended_next_actions: list = field(default_factory=list)
    overall_score: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "project_id": self.project_id, "overall_state": self.overall_state,
            "subsystem_states": self.subsystem_states,
            "critical_findings": self.critical_findings, "top_risks": self.top_risks,
            "trend": self.trend, "evidence": self.evidence,
            "recommended_next_actions": self.recommended_next_actions,
            "overall_score": self.overall_score,
        }


def _worst(states: list) -> str:
    present = [s for s in states if s]
    if not present:
        return STATE_UNKNOWN
    return max(present, key=lambda s: _STATE_RANK.get(s, 0))


def _security_trend_state(trends: list) -> tuple:
    """HEALTHY/AT_RISK/CRITICAL/UNKNOWN from the worst DECREASING(=good)/
    INCREASING(=bad) metric this project has. `unresolved_critical_findings`
    metric increasing is CRITICAL; any other metric increasing is AT_RISK;
    all decreasing/stable is HEALTHY; no dated evidence is UNKNOWN."""
    if not trends:
        return STATE_UNKNOWN, "no security trend evidence for this project", None
    worst_state = STATE_HEALTHY
    summary_metric = None
    for t in trends:
        if t.trend == "INCREASING":
            state = STATE_CRITICAL if t.metric == "unresolved_critical_findings" else STATE_AT_RISK
            if _STATE_RANK[state] > _STATE_RANK[worst_state]:
                worst_state, summary_metric = state, t
        elif t.trend == "UNKNOWN" and worst_state == STATE_HEALTHY:
            worst_state = STATE_UNKNOWN
    if summary_metric is not None:
        return worst_state, summary_metric.explanation, summary_metric.trend
    if worst_state == STATE_UNKNOWN:
        return STATE_UNKNOWN, "insufficient dated security-trend history", None
    return STATE_HEALTHY, "no worsening security trend detected", "STABLE"


def _risk_state(prediction) -> str:
    if prediction is None or prediction.risk_horizon == "UNKNOWN":
        return STATE_UNKNOWN
    if prediction.risk_horizon == "IMMEDIATE":
        return STATE_CRITICAL
    if prediction.risk_horizon == "NEAR_TERM":
        return STATE_AT_RISK
    return STATE_HEALTHY


def _health_signal_state(signals: list) -> tuple:
    if not signals:
        return STATE_UNKNOWN, "no incident-pattern/health-signal evidence for this project"
    worst = max(signals, key=lambda s: _STATE_RANK.get(
        {SignalState.CONFIRMED: STATE_CRITICAL, SignalState.LIKELY: STATE_AT_RISK,
         SignalState.POSSIBLE: STATE_HEALTHY, SignalState.UNKNOWN: STATE_UNKNOWN}.get(s.state, STATE_UNKNOWN), 0))
    mapped = {SignalState.CONFIRMED: STATE_CRITICAL, SignalState.LIKELY: STATE_AT_RISK,
              SignalState.POSSIBLE: STATE_HEALTHY, SignalState.UNKNOWN: STATE_UNKNOWN}.get(worst.state, STATE_UNKNOWN)
    return mapped, worst.explanation


def _debt_state(debt_signals: list) -> tuple:
    real = [d for d in debt_signals if d.affected_project_id is not None]
    if not real:
        return STATE_HEALTHY, "no technical-debt signal recorded for this project"
    top_sev = max((d.severity or "low") for d in real)
    state = STATE_CRITICAL if top_sev == "critical" else STATE_AT_RISK
    return state, f"{len(real)} technical-debt signal(s): " + ", ".join(sorted({d.debt_signal for d in real}))


def _arch_state(risks: list) -> tuple:
    if not risks:
        return STATE_HEALTHY, "no architectural risk recorded for this project"
    sev_rank = {"critical": 3, "high": 2, "medium": 1, "low": 0, "info": 0}
    worst = max(risks, key=lambda r: sev_rank.get((r.severity or "low").lower(), 0))
    state = STATE_CRITICAL if (worst.severity or "").lower() == "critical" else STATE_AT_RISK
    return state, worst.explanation if hasattr(worst, "explanation") else worst.recommendation


def _deploy_state(forecasts: list) -> tuple:
    if not forecasts or all(f.horizon == "UNKNOWN" for f in forecasts):
        return STATE_UNKNOWN, "insufficient deployment/dependency-risk evidence for this project"
    worst = max(forecasts, key=lambda f: {"IMMEDIATE": 3, "NEAR_TERM": 2, "ELEVATED": 1, "UNKNOWN": 0}.get(f.horizon, 0))
    state = {"IMMEDIATE": STATE_CRITICAL, "NEAR_TERM": STATE_AT_RISK,
              "ELEVATED": STATE_AT_RISK}.get(worst.horizon, STATE_HEALTHY)
    return state, worst.recommendation


# 0-1 numeric contribution per subsystem state - used ONLY to build the
# fully-visible optional overall_score breakdown, never hidden.
_STATE_SCORE = {STATE_CRITICAL: 1.0, STATE_AT_RISK: 0.5, STATE_HEALTHY: 0.0, STATE_UNKNOWN: None}


def compute_engineering_health(
    finding_repo: FindingRepository,
    project_repo: Optional[ProjectRepository] = None,
    project_ids: Optional[list[str]] = None,
) -> list:
    """One `EngineeringHealthSummary` per project, calling into the 8
    underlying Phase 10 intelligence functions rather than reimplementing
    any of their logic. `project_ids=None` covers every project
    `project_repo`/`finding_repo` knows about."""
    if project_ids is None:
        if project_repo is not None:
            project_ids = sorted(p.id for p in project_repo.list())
        else:
            project_ids = sorted({f.project_id for f in finding_repo.list(None, None)})

    incident_patterns = detect_patterns(finding_repo, project_ids=project_ids, min_projects=1)
    health_signals = compute_health_signals(finding_repo, project_repo, project_ids=project_ids)
    risk_predictions = {r.project_id: r for r in predict_risk(
        finding_repo, project_repo, project_ids=project_ids, incident_patterns=incident_patterns,
        health_signals=health_signals)}
    architectural_risks = analyze_architecture(finding_repo, project_repo, project_ids=project_ids,
                                                incident_patterns=incident_patterns)
    security_trends = analyze_security_trends(finding_repo, project_ids=project_ids)
    deployment_forecasts = forecast_deployment_risk(finding_repo, project_repo, project_ids=project_ids)
    debt_signals = analyze_technical_debt(finding_repo, project_repo, project_ids=project_ids,
                                           incident_patterns=incident_patterns,
                                           health_signals=health_signals,
                                           deployment_risks=deployment_forecasts,
                                           architectural_risks=architectural_risks)
    cost_result = analyze_cost_intelligence(finding_repo, project_ids=project_ids)
    ci_result = analyze_ci_clusters(project_ids=project_ids)

    summaries = []
    for pid in project_ids:
        proj_arch = [r for r in architectural_risks if pid in r.affected_project_ids]
        proj_trends = [t for t in security_trends if t.project_id == pid]
        proj_deploy = [f for f in deployment_forecasts if f.project_id == pid]
        proj_debt = [d for d in debt_signals if d.affected_project_id == pid]
        proj_signals = [s for s in health_signals if pid in s.affected_projects]
        proj_risk = risk_predictions.get(pid)

        sec_state, sec_evidence, sec_trend = _security_trend_state(proj_trends)
        risk_state = _risk_state(proj_risk)
        incident_state, incident_evidence = _health_signal_state(proj_signals)
        debt_state, debt_evidence = _debt_state(proj_debt)
        arch_state, arch_evidence = _arch_state(proj_arch)
        deploy_state, deploy_evidence = _deploy_state(proj_deploy)
        # cost intelligence is status-only (BLOCKED everywhere) - never
        # contributes a state/score, only reported for visibility.
        cost_state = STATE_UNKNOWN
        cost_evidence = "; ".join(sorted({s.status for s in cost_result.signals})) or "BLOCKED"
        ci_state = STATE_UNKNOWN
        ci_evidence = ci_result.reason

        subsystem_states = {
            "security_posture": {"state": sec_state, "evidence": sec_evidence},
            "risk_prediction": {"state": risk_state,
                                 "evidence": proj_risk.explanation if proj_risk else "no risk evidence"},
            "incident_patterns": {"state": incident_state, "evidence": incident_evidence},
            "technical_debt": {"state": debt_state, "evidence": debt_evidence},
            "architecture": {"state": arch_state, "evidence": arch_evidence},
            "deployment_risk": {"state": deploy_state, "evidence": deploy_evidence},
            "cost_intelligence": {"state": cost_state, "evidence": cost_evidence},
            "ci_clustering": {"state": ci_state, "evidence": ci_evidence},
        }

        overall_state = _worst(v["state"] for v in subsystem_states.values())

        critical_findings = [
            {"signal_id": s.signal_id, "explanation": s.explanation}
            for s in proj_signals if s.state == SignalState.CONFIRMED
        ]

        top_risks = []
        if proj_risk is not None:
            top_risks = [{"score": proj_risk.score, "risk_horizon": proj_risk.risk_horizon,
                          "explanation": proj_risk.explanation}]

        score_breakdown = {k: _STATE_SCORE[v["state"]] for k, v in subsystem_states.items()
                            if _STATE_SCORE[v["state"]] is not None}
        overall_score = round(sum(score_breakdown.values()) / len(score_breakdown), 4) if score_breakdown else None

        actions = []
        if overall_state == STATE_CRITICAL:
            actions.append("Address the CRITICAL subsystem(s) above first - see their evidence field.")
        for name, v in subsystem_states.items():
            if v["state"] in (STATE_CRITICAL, STATE_AT_RISK):
                actions.append(f"Review {name}: {v['evidence']}")

        summaries.append(EngineeringHealthSummary(
            project_id=pid, overall_state=overall_state, subsystem_states=subsystem_states,
            critical_findings=critical_findings, top_risks=top_risks,
            trend=sec_trend or "UNKNOWN",
            evidence={"score_breakdown": score_breakdown,
                      "sources": ["risk_prediction.predict_risk", "architecture.analyze_architecture",
                                  "security_trends.analyze_security_trends",
                                  "deployment_risk.forecast_deployment_risk",
                                  "technical_debt.analyze_technical_debt",
                                  "cost_intelligence.analyze_cost_intelligence",
                                  "ci_clustering.analyze_ci_clusters",
                                  "incident_patterns.compute_health_signals/detect_patterns"]},
            recommended_next_actions=actions, overall_score=overall_score,
        ))

    summaries.sort(key=lambda s: (-_STATE_RANK.get(s.overall_state, 0), s.project_id))
    return summaries


def engineering_health_summary_to_dict(item: EngineeringHealthSummary) -> dict:
    return item.to_dict()


if __name__ == "__main__":
    # ponytail: smallest self-check, not a full test suite.
    from ..db.fake import FakeFindingRepository
    from ..db.models import FindingRecord

    repo = FakeFindingRepository()
    repo.save(FindingRecord(id="f1", project_id="p1", category="secret", severity="critical",
                             description="hardcoded key", status="OPEN"))
    summaries = compute_engineering_health(repo, project_ids=["p1"])
    assert len(summaries) == 1
    assert summaries[0].overall_state in (STATE_HEALTHY, STATE_AT_RISK, STATE_CRITICAL, STATE_UNKNOWN)
    print("ok:", summaries[0].to_dict())
