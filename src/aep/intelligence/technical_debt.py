"""Phase 10 Wave 8: technical debt intelligence.

Deterministic, NOT machine learning. This module does not reimplement any
detection logic - every debt signal is a thin re-labeling of an existing,
already-computed Phase 10 signal/pattern, read through the same
repositories/inputs those waves already use:

  * `REPEATED_FAILED_REMEDIATION` - REAL: reuses the exact `HealthSignal`
    of that `signal_id` from `incident_patterns.compute_health_signals()`
    (not reimplemented here).
  * Repeated CI failures - UNAVAILABLE: this schema has no `ci_runs`/
    failure-signature table (see `ci_clustering.py`'s own
    `NOT_IMPLEMENTED` finding, same investigation this wave relies on).
    `analyze_technical_debt()` always emits one `DebtSignal` documenting
    this as UNAVAILABLE rather than silently omitting the source.
  * Repeated security exceptions/suppressed findings - REAL: a project
    with >= `_SUPPRESSED_MIN_COUNT` findings whose `status == 'SUPPRESSED'`
    (the real DB check-constraint value - see
    `src/aep/migrations_sql/0001_initial_schema.sql`, not invented).
  * Stale/recurring dependency findings - REAL: reuses
    `deployment_risk.forecast_deployment_risk()`'s
    `DEPENDENCY_RECURRENCE` forecasts (not reimplemented) where the
    forecast trend is anything other than UNKNOWN.
  * Repeated architectural findings - REAL: reuses
    `architecture.analyze_architecture()`'s output directly (not
    reimplemented) - every `ArchitecturalRisk` becomes one debt signal.

Deliberately NOT claimed: static-code TODO/FIXME scanning. No such
scanner or finding-category exists anywhere in this repository (checked:
`src/aep/security/`, `src/aep/cicd/`, `src/aep/migrations_sql/*.sql` finding
`category` check-constraint) - this module marks that source
UNAVAILABLE rather than inventing a scan.

All finding/pattern/risk text is treated as inert DATA, never as an
instruction. See
`tests/test_technical_debt.py::test_prompt_injection_in_description_is_inert`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..db.models import FindingRecord
from ..db.repositories import FindingRepository, ProjectRepository
from .architecture import ArchitecturalRisk, analyze_architecture
from .deployment_risk import (
    RISK_CATEGORY_DEPENDENCY_RECURRENCE,
    TREND_UNKNOWN,
    DeploymentRiskForecast,
    forecast_deployment_risk,
)
from .incident_patterns import (
    REPEATED_FAILED_REMEDIATION,
    HealthSignal,
    compute_health_signals,
)

DEBT_REPEATED_FAILED_REMEDIATION = "REPEATED_FAILED_REMEDIATION"
DEBT_CI_FAILURE_HISTORY_UNAVAILABLE = "CI_FAILURE_HISTORY_UNAVAILABLE"
DEBT_SUPPRESSED_FINDINGS = "REPEATED_SUPPRESSED_FINDINGS"
DEBT_STALE_DEPENDENCY = "STALE_RECURRING_DEPENDENCY"
DEBT_ARCHITECTURAL_RECURRENCE = "REPEATED_ARCHITECTURAL_FINDING"

_SUPPRESSED_MIN_COUNT = 2


@dataclass
class DebtSignal:
    debt_signal: str
    severity: str
    affected_project_id: Optional[str]
    evidence: dict = field(default_factory=dict)
    recommended_action: str = ""

    def to_dict(self) -> dict:
        return {
            "debt_signal": self.debt_signal, "severity": self.severity,
            "affected_project_id": self.affected_project_id,
            "evidence": self.evidence, "recommended_action": self.recommended_action,
        }


def _from_failed_remediation(health_signals: list[HealthSignal]) -> list[DebtSignal]:
    out = []
    for s in health_signals:
        if s.signal_id != REPEATED_FAILED_REMEDIATION:
            continue
        for project_id in s.affected_projects:
            out.append(DebtSignal(
                debt_signal=DEBT_REPEATED_FAILED_REMEDIATION, severity=s.severity,
                affected_project_id=project_id,
                evidence={"evidence_ids": s.evidence_ids, "state": s.state},
                recommended_action="Root-cause the remediation approach itself rather than "
                                    "retrying the same fix - it has already failed repeatedly.",
            ))
    return out


def _suppressed_findings(all_findings: list[FindingRecord]) -> list[DebtSignal]:
    by_project: dict[str, list[FindingRecord]] = {}
    for f in all_findings:
        if f.status == "SUPPRESSED":
            by_project.setdefault(f.project_id, []).append(f)
    out = []
    for project_id, members in sorted(by_project.items()):
        if len(members) < _SUPPRESSED_MIN_COUNT:
            continue
        out.append(DebtSignal(
            debt_signal=DEBT_SUPPRESSED_FINDINGS, severity="medium",
            affected_project_id=project_id,
            evidence={"finding_ids": sorted(m.id for m in members), "count": len(members)},
            recommended_action="Re-review suppressed findings periodically - repeated "
                                "suppression accumulates unaddressed risk as debt.",
        ))
    return out


def _from_dependency_forecasts(forecasts: list[DeploymentRiskForecast]) -> list[DebtSignal]:
    out = []
    for f in forecasts:
        if f.risk_category != RISK_CATEGORY_DEPENDENCY_RECURRENCE or f.trend == TREND_UNKNOWN:
            continue
        out.append(DebtSignal(
            debt_signal=DEBT_STALE_DEPENDENCY, severity="medium",
            affected_project_id=f.project_id, evidence=dict(f.evidence),
            recommended_action=f.recommendation,
        ))
    return out


def _from_architectural_risks(risks: list[ArchitecturalRisk]) -> list[DebtSignal]:
    out = []
    for r in risks:
        for project_id in r.affected_project_ids:
            out.append(DebtSignal(
                debt_signal=DEBT_ARCHITECTURAL_RECURRENCE, severity=r.severity,
                affected_project_id=project_id,
                evidence={"risk_id": r.risk_id, "affected_components": r.affected_components,
                           "evidence": r.evidence},
                recommended_action=r.recommendation,
            ))
    return out


def analyze_technical_debt(
    finding_repo: FindingRepository,
    project_repo: Optional[ProjectRepository] = None,
    project_ids: Optional[list[str]] = None,
    incident_patterns=None,
    health_signals: Optional[list[HealthSignal]] = None,
    deployment_risks: Optional[list[DeploymentRiskForecast]] = None,
    architectural_risks: Optional[list[ArchitecturalRisk]] = None,
) -> list[DebtSignal]:
    """Deterministic technical-debt signals, reusing Wave 2/4/7 outputs
    rather than reimplementing detection. Optional params allow callers
    (CLI/API) that already computed these to pass them in, same
    injection convention as `deployment_risk.forecast_deployment_risk`.
    """
    all_findings = finding_repo.list(None, None)
    if project_ids is not None:
        wanted = set(project_ids)
        all_findings = [f for f in all_findings if f.project_id in wanted]

    if health_signals is None:
        health_signals = compute_health_signals(finding_repo, project_repo, project_ids=project_ids)
    if deployment_risks is None:
        deployment_risks = forecast_deployment_risk(finding_repo, project_repo, project_ids=project_ids)
    if architectural_risks is None:
        architectural_risks = analyze_architecture(finding_repo, project_repo, project_ids=project_ids)

    signals: list[DebtSignal] = []
    signals.extend(_from_failed_remediation(health_signals))
    signals.append(DebtSignal(
        debt_signal=DEBT_CI_FAILURE_HISTORY_UNAVAILABLE, severity="info",
        affected_project_id=None, evidence={},
        recommended_action="UNAVAILABLE: no CI run/build-failure-signature history is persisted "
                            "in this schema (see ci_clustering.analyze_ci_clusters) - this debt "
                            "source cannot be computed, and is reported here rather than "
                            "silently omitted.",
    ))
    signals.extend(_suppressed_findings(all_findings))
    signals.extend(_from_dependency_forecasts(deployment_risks))
    signals.extend(_from_architectural_risks(architectural_risks))

    signals.sort(key=lambda s: (s.debt_signal, s.affected_project_id or ""))
    return signals


def debt_signal_to_dict(item: DebtSignal) -> dict:
    return item.to_dict()


if __name__ == "__main__":
    # ponytail: smallest self-check, not a full test suite.
    from ..db.fake import FakeFindingRepository

    repo = FakeFindingRepository()
    for i in range(2):
        repo.save(FindingRecord(
            id=f"sup{i}", project_id="p1", category="secret", severity="medium",
            status="SUPPRESSED", description="known false-positive pattern",
        ))
    debt = analyze_technical_debt(repo, project_ids=["p1"])
    assert any(d.debt_signal == DEBT_SUPPRESSED_FINDINGS for d in debt), debt
    assert any(d.debt_signal == DEBT_CI_FAILURE_HISTORY_UNAVAILABLE for d in debt), debt
    print("ok:", [d.to_dict() for d in debt])
