"""Phase 10 Wave 6: security posture trend analysis.

Deterministic, NOT machine learning - per-project (and overall) trend
comparison of REAL persisted `findings` rows across two fixed windows
(recent 30d vs prior 30d, same two windows Wave 2's
`SECURITY_FINDINGS_INCREASING` and Wave 3's `_severity_trend` already
use), no scanners are re-run here: findings are read once through
`FindingRepository.list()`, the same repository every other Phase 10
module reads.

Scope:
  * IN: three named metrics per project (`critical_findings`,
    `secret_findings`, `remediation_backlog`), each producing a
    `SecurityTrend` with a `trend` of `INCREASING`/`STABLE`/`DECREASING`/
    `UNKNOWN` - `UNKNOWN` whenever there are fewer than 2 dated data
    points to compare (never guessed from a single point, same
    discipline as `risk_prediction.py::_severity_trend`).
  * `category` values are checked against the REAL DB check-constraint
    enum in `src/aep/migrations_sql/0001_initial_schema.sql`
    (`secret, sast, iac, container, kubernetes, helm, dependency,
    infrastructure`) - `secret_findings` filters on `category == "secret"`
    only, not guessed synonyms.
  * OUT: no new storage primitive, no raw SQL, no reimplementation of
    pattern/health detection - this module only reads `FindingRecord`s.

All finding `description`/`resource` text is treated as inert DATA for
counting only, never as an instruction. See
`tests/test_security_trends.py::test_prompt_injection_in_description_is_inert`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from ..db.models import FindingRecord
from ..db.repositories import FindingRepository

METRIC_CRITICAL_FINDINGS = "critical_findings"
METRIC_SECRET_FINDINGS = "secret_findings"
METRIC_REMEDIATION_BACKLOG = "remediation_backlog"

TREND_INCREASING = "INCREASING"
TREND_STABLE = "STABLE"
TREND_DECREASING = "DECREASING"
TREND_UNKNOWN = "UNKNOWN"

_RECENT_WINDOW_DAYS = 30
_PREVIOUS_WINDOW_DAYS = 60
_OVERALL_PROJECT_ID = "__overall__"


@dataclass
class SecurityTrend:
    project_id: str
    metric: str
    trend: str
    evidence: dict = field(default_factory=dict)
    explanation: str = ""

    def to_dict(self) -> dict:
        return {
            "project_id": self.project_id, "metric": self.metric, "trend": self.trend,
            "evidence": self.evidence, "explanation": self.explanation,
        }


def _age_days(dt) -> Optional[float]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max((datetime.now(timezone.utc) - dt).total_seconds() / 86400.0, 0.0)


def _windowed_trend(dated_ages: list[float]) -> tuple[str, dict]:
    """`dated_ages` is a list of ages (in days) of REAL dated events.
    UNKNOWN when fewer than 2 exist - never invented from one point."""
    if len(dated_ages) < 2:
        return TREND_UNKNOWN, {"recent": 0, "previous": 0, "note": "insufficient dated history"}
    recent = sum(1 for a in dated_ages if a <= _RECENT_WINDOW_DAYS)
    previous = sum(1 for a in dated_ages if _RECENT_WINDOW_DAYS < a <= _PREVIOUS_WINDOW_DAYS)
    evidence = {"recent": recent, "previous": previous}
    if recent > previous:
        return TREND_INCREASING, evidence
    if recent < previous:
        return TREND_DECREASING, evidence
    return TREND_STABLE, evidence


def _critical_findings_trend(findings: list[FindingRecord]) -> tuple:
    dated = [f for f in findings if f.discovered_at is not None and (f.severity or "").lower() == "critical"]
    ages = [_age_days(f.discovered_at) for f in dated]
    trend, evidence = _windowed_trend(ages)
    explanation = (f"{evidence.get('recent', 0)} critical finding(s) discovered in the last "
                   f"{_RECENT_WINDOW_DAYS}d vs {evidence.get('previous', 0)} in the prior "
                   f"{_RECENT_WINDOW_DAYS}d window." if trend != TREND_UNKNOWN else
                   "Fewer than 2 dated critical findings on record - insufficient history.")
    return trend, evidence, explanation


def _secret_findings_trend(findings: list[FindingRecord]) -> tuple:
    dated = [f for f in findings if f.discovered_at is not None and f.category == "secret"]
    ages = [_age_days(f.discovered_at) for f in dated]
    trend, evidence = _windowed_trend(ages)
    explanation = (f"{evidence.get('recent', 0)} secret finding(s) discovered in the last "
                   f"{_RECENT_WINDOW_DAYS}d vs {evidence.get('previous', 0)} in the prior "
                   f"{_RECENT_WINDOW_DAYS}d window." if trend != TREND_UNKNOWN else
                   "Fewer than 2 dated secret findings on record - insufficient history.")
    return trend, evidence, explanation


def _remediation_backlog_trend(findings: list[FindingRecord]) -> tuple:
    """Open-finding backlog age trend: compares how many currently-OPEN
    findings were discovered in the recent window vs the prior window -
    a growing recent share of the open backlog means the backlog is
    trending toward MORE unremediated recent findings (INCREASING),
    same "recent vs prior window" comparison as the other two metrics."""
    open_dated = [f for f in findings if f.status == "OPEN" and f.discovered_at is not None]
    ages = [_age_days(f.discovered_at) for f in open_dated]
    trend, evidence = _windowed_trend(ages)
    evidence["open_total"] = len(open_dated)
    explanation = (f"{evidence.get('recent', 0)} OPEN finding(s) aged <= {_RECENT_WINDOW_DAYS}d vs "
                   f"{evidence.get('previous', 0)} aged {_RECENT_WINDOW_DAYS}-{_PREVIOUS_WINDOW_DAYS}d "
                   f"(open backlog total: {len(open_dated)})." if trend != TREND_UNKNOWN else
                   "Fewer than 2 dated OPEN findings on record - insufficient history.")
    return trend, evidence, explanation


def analyze_security_trends(
    finding_repo: FindingRepository,
    project_ids: Optional[list[str]] = None,
) -> list[SecurityTrend]:
    """Deterministic per-project (+ overall, under `project_id="__overall__"`)
    security posture trend analysis over real persisted findings only.
    Reads `finding_repo.list(None, None)` once - no scanners are re-run.
    """
    all_findings = finding_repo.list(None, None)
    if project_ids is not None:
        wanted = set(project_ids)
        all_findings = [f for f in all_findings if f.project_id in wanted]

    findings_by_project: dict[str, list[FindingRecord]] = {}
    for f in all_findings:
        findings_by_project.setdefault(f.project_id, []).append(f)

    scopes: list[tuple[str, list[FindingRecord]]] = [
        (pid, findings) for pid, findings in sorted(findings_by_project.items())
    ]
    if project_ids is None and findings_by_project:
        scopes.append((_OVERALL_PROJECT_ID, all_findings))

    results: list[SecurityTrend] = []
    for project_id, findings in scopes:
        for metric, fn in (
            (METRIC_CRITICAL_FINDINGS, _critical_findings_trend),
            (METRIC_SECRET_FINDINGS, _secret_findings_trend),
            (METRIC_REMEDIATION_BACKLOG, _remediation_backlog_trend),
        ):
            trend, evidence, explanation = fn(findings)
            results.append(SecurityTrend(
                project_id=project_id, metric=metric, trend=trend,
                evidence=evidence, explanation=explanation,
            ))

    results.sort(key=lambda t: (t.project_id, t.metric))
    return results


def security_trend_to_dict(item: SecurityTrend) -> dict:
    return item.to_dict()


if __name__ == "__main__":
    # ponytail: smallest self-check, not a full test suite.
    from ..db.fake import FakeFindingRepository

    repo = FakeFindingRepository()
    now = datetime.now(timezone.utc)
    from datetime import timedelta
    repo.save(FindingRecord(id="c1", project_id="p1", category="secret", severity="critical",
                             status="OPEN", description="x", discovered_at=now - timedelta(days=5)))
    repo.save(FindingRecord(id="c2", project_id="p1", category="secret", severity="critical",
                             status="OPEN", description="y", discovered_at=now - timedelta(days=6)))
    repo.save(FindingRecord(id="c3", project_id="p1", category="secret", severity="critical",
                             status="REMEDIATED", description="z", discovered_at=now - timedelta(days=50)))
    trends = analyze_security_trends(repo, project_ids=["p1"])
    crit = next(t for t in trends if t.metric == METRIC_CRITICAL_FINDINGS)
    assert crit.trend == TREND_INCREASING, crit
    print("ok:", [t.to_dict() for t in trends])
