"""Phase 10 Wave 1: deterministic cross-project prioritization.

Ranks OPEN `FindingRecord`s (already persisted by the existing security/
operations engines - this module is a pure read-side consumer of
`FindingRepository`/`ProjectRepository`, it never scans/writes findings
itself) across MULTIPLE projects into one explainable, ranked list.

Scope (read this before extending):
  * IN for this pass: findings only, via `FindingRepository.list()` /
    `ProjectRepository.list()` - both already exist and are used
    unchanged (Wave 1 API's `/findings` handler calls the exact same
    `FindingRepository.list`).
  * OUT for this pass, and NOT silently faked: incidents
    (`IncidentMemoryRecord`, `src/aep/operations/memory.py`) and
    deployment evidence (`src/aep/deployment/evidence.py`). Both are real
    and queryable, but neither currently carries a `severity`/`category`
    concept the way `FindingRecord` does - `IncidentMemoryRecord` has
    `confidence`/`root_cause`/`environment` but no severity, and
    deployment evidence records a rollout event, not an open item to
    triage. Forcing them into this factor model would mean inventing
    fields that do not exist in the schema, which is exactly what
    ARCHITECTURE.md's "no fake SLA field" instruction (mirrored here)
    warns against. See ARCHITECTURE.md §35 / docs/PHASE10.md for the
    honest deferral and what a future wave would need to add first
    (a severity concept on `IncidentMemoryRecord`) to include them.
  * AI re-ranking: not built. Optional per spec; skipped for this small
    pass. The ranking below is 100% deterministic and independently
    inspectable, matching the "explicit rules first, AI only ever an
    enhancement layer on top, never the sole mechanism" discipline
    `src/aep/skills/known_capabilities.py` documents for Stage B and
    `AIGateway.route()`'s `RoutingDecision` documents for Stage C.
  * Memory (`MemoryRecord`/`MemoryRepository`, Stage A): NOT consulted.
    Wiring it in as a low-weight advisory input was in-scope per the
    spec but optional; skipped here to keep this pass small - documented
    honestly rather than forced. `rank_findings()` is evidence-only.

Every ranked item's `PrioritizedFinding.breakdown` traces the total score
back to each named factor's raw value, normalized [0,1] score, weight,
and contribution - the same "explainable reason, not a black box" bar
`RoutingDecision.reason` set in Stage C.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from ..db.models import FindingRecord, ProjectRecord
from ..db.repositories import FindingRepository, ProjectRepository

# ---------------------------------------------------------------------------
# Factor weights. Named literals, deterministic - NOT machine-learned, NOT
# tunable at runtime. Must sum to 1.0 (asserted below, and by
# tests/test_prioritization.py).
# ---------------------------------------------------------------------------
WEIGHT_SEVERITY = 0.30          # how bad the finding itself is
WEIGHT_RISK = 0.15              # explicit risk annotation (evidence["risk"]),
                                 # falls back to severity if absent - documented
                                 # below, never invented independently of
                                 # existing data.
WEIGHT_PRODUCTION_IMPACT = 0.20  # does this affect a production environment
WEIGHT_RECURRENCE = 0.15        # how many times this (project, category) has
                                 # recurred among all findings on record
WEIGHT_AGE = 0.10                # how long the finding has been open
WEIGHT_BLAST_RADIUS = 0.10      # simple heuristic: count of other OPEN
                                 # findings on the same project/resource
WEIGHT_SLA = 0.0                 # NO-OP. `FindingRecord`/`ProjectRecord` have
                                 # no SLA/due-date concept anywhere in the
                                 # schema (checked supabase/migrations/*.sql
                                 # and db/models.py) - rather than invent a
                                 # fake SLA field to get a nonzero weight,
                                 # this factor is included explicitly, at
                                 # weight 0, so its absence is visible and
                                 # traceable in every breakdown instead of
                                 # silently missing.

_TOTAL_WEIGHT = (WEIGHT_SEVERITY + WEIGHT_RISK + WEIGHT_PRODUCTION_IMPACT
                 + WEIGHT_RECURRENCE + WEIGHT_AGE + WEIGHT_BLAST_RADIUS + WEIGHT_SLA)
assert abs(_TOTAL_WEIGHT - 1.0) < 1e-9, f"prioritization weights must sum to 1.0, got {_TOTAL_WEIGHT}"

# Phase 10 Wave 2 addition: an OPTIONAL 8th factor, only present in a
# finding's breakdown when the caller passes `recurring_pattern_finding_ids`
# to `rank_findings()` (see `src/aep/intelligence/incident_patterns.py`,
# which computes that set from cross-project pattern detection). This is a
# deliberate BONUS factor layered on top of the base 7 (which continue to
# sum to exactly 1.0 and are unaffected/untouched when this parameter is
# omitted - the default, used by every pre-Wave-2 caller/test) rather than
# a rebalancing of the existing weights, so Wave 1's numeric behavior is
# 100% unchanged for every existing caller. Documented explicitly here
# rather than silently bolted on.
WEIGHT_RECURRING_PATTERN = 0.10

# Phase 10 Wave 3 addition: another OPTIONAL bonus factor, only present
# when the caller passes `risk_scores_by_project` (a `{project_id: 0..1
# score}` map, computed from `src/aep/intelligence/risk_prediction.py`'s
# `predict_risk()` output - see `risk_prediction_score_map()` below).
# Same bonus-on-top discipline as `recurring_pattern`: the base 7 factors
# are unaffected/untouched when this is omitted.
WEIGHT_RISK_PREDICTION = 0.10

_SEVERITY_SCORES = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}
_SEVERITY_DEFAULT = 0.1  # unknown/unset severity string

_RECURRENCE_CAP = 5      # >=5 prior occurrences of the same (project, category) -> max score
_BLAST_RADIUS_CAP = 10   # >=10 other open findings on the same project/resource -> max score
_AGE_CAP_DAYS = 90       # >=90 days open -> max score

# Environment strings treated as "production" when present on
# `FindingRecord.evidence["environment"]` (set by whichever scanner/engine
# recorded the finding - this module never invents the value itself).
_PRODUCTION_ENV_VALUES = {"production", "prod"}


@dataclass
class PrioritizedFinding:
    """One ranked item. `breakdown` maps each named factor to its raw
    input, normalized [0,1] score, weight, and contribution to the final
    `score` - every number in `score` must be reconstructable from this
    dict alone (see test_prioritization.py::test_breakdown_sums_to_score)."""
    finding_id: str
    project_id: str
    category: str
    severity: str
    status: str
    resource: Optional[str]
    discovered_at: Optional[str]
    score: float
    breakdown: dict = field(default_factory=dict)
    rank: int = 0


def _severity_score(severity: Optional[str]) -> float:
    return _SEVERITY_SCORES.get((severity or "").lower(), _SEVERITY_DEFAULT)


def _risk_score(finding: FindingRecord) -> float:
    """Explicit risk annotation if the recording engine set one
    (`evidence["risk"]`, a literal severity-shaped string) - falls back to
    the finding's own severity when absent. `FindingRecord` has no
    separate `risk` column (only `TaskRecord` does), so this is the
    honest choice: reuse real data (severity) rather than invent a
    disconnected risk score."""
    raw = (finding.evidence or {}).get("risk")
    if raw:
        return _severity_score(str(raw))
    return _severity_score(finding.severity)


def _production_impact_score(finding: FindingRecord, project: Optional[ProjectRecord]) -> float:
    """1.0 if this finding is known to affect a production environment,
    else 0.0. Two real signals, checked in order:
      1. `finding.evidence["environment"]` - set by the recording scanner
         when it knows the environment (e.g. infra/cloud scanners tag
         resources by environment).
      2. `project.default_posture == "deny"` - `ProjectRecord`'s only
         posture field; a deny-by-default project is the platform's
         existing convention for "treat this stricter", used here as the
         nearest real proxy for "production-grade" when no explicit
         environment tag exists. Documented assumption, not a schema
         change.
    Neither present -> 0.0 (unknown is never assumed to be production)."""
    env = (finding.evidence or {}).get("environment")
    if env and str(env).lower() in _PRODUCTION_ENV_VALUES:
        return 1.0
    if project is not None and project.default_posture == "deny":
        return 1.0
    return 0.0


def _age_days(discovered_at: Optional[datetime]) -> float:
    if discovered_at is None:
        return 0.0
    if discovered_at.tzinfo is None:
        discovered_at = discovered_at.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - discovered_at
    return max(delta.total_seconds() / 86400.0, 0.0)


def _normalized_age_score(days: float) -> float:
    return min(days / _AGE_CAP_DAYS, 1.0)


def _normalized_recurrence_score(count: int) -> float:
    return min(count / _RECURRENCE_CAP, 1.0)


def _normalized_blast_radius_score(count: int) -> float:
    return min(count / _BLAST_RADIUS_CAP, 1.0)


def rank_findings(
    finding_repo: FindingRepository,
    project_repo: Optional[ProjectRepository] = None,
    project_ids: Optional[list[str]] = None,
    statuses: tuple[str, ...] = ("OPEN",),
    recurring_pattern_finding_ids: Optional[set] = None,
    risk_scores_by_project: Optional[dict] = None,
) -> list[PrioritizedFinding]:
    """Deterministically ranks findings across every project `finding_repo`
    knows about (or a filtered subset via `project_ids`), highest priority
    first. Pure function of what is already persisted - issues exactly one
    `FindingRepository.list(None, None)` call (same repository/method the
    Wave 1 `/findings` API handler already uses) plus, if `project_repo`
    is given, one `ProjectRepository.list()` call for posture lookups.
    """
    all_findings = finding_repo.list(None, None)

    projects_by_id: dict[str, ProjectRecord] = {}
    if project_repo is not None:
        projects_by_id = {p.id: p for p in project_repo.list()}

    # Recurrence: how many times (any status) has this (project, category)
    # been seen at all - computed from the FULL unfiltered set, since a
    # closed finding still counts as "this has recurred before".
    recurrence_counts: dict[tuple[str, str], int] = {}
    for f in all_findings:
        key = (f.project_id, f.category)
        recurrence_counts[key] = recurrence_counts.get(key, 0) + 1

    candidates = [f for f in all_findings if f.status in statuses]
    if project_ids is not None:
        wanted = set(project_ids)
        candidates = [f for f in candidates if f.project_id in wanted]

    # Blast radius: count of OTHER open findings on the same project/resource
    # (same resource if set, else same project) - a simple heuristic per
    # spec, not a real dependency graph.
    def _blast_radius(f: FindingRecord) -> int:
        others = 0
        for g in candidates:
            if g.id == f.id:
                continue
            if g.project_id != f.project_id:
                continue
            if f.resource and g.resource:
                if g.resource == f.resource:
                    others += 1
            elif not f.resource and not g.resource:
                others += 1
        return others

    results: list[PrioritizedFinding] = []
    for f in candidates:
        project = projects_by_id.get(f.project_id)
        recurrence_count = recurrence_counts.get((f.project_id, f.category), 1) - 1
        blast_radius_count = _blast_radius(f)
        age_days = _age_days(f.discovered_at)

        sev_score = _severity_score(f.severity)
        risk_score = _risk_score(f)
        prod_score = _production_impact_score(f, project)
        recur_score = _normalized_recurrence_score(recurrence_count)
        age_score = _normalized_age_score(age_days)
        blast_score = _normalized_blast_radius_score(blast_radius_count)
        sla_score = 0.0

        breakdown = {
            "severity": {"raw": f.severity, "score": sev_score, "weight": WEIGHT_SEVERITY,
                         "contribution": sev_score * WEIGHT_SEVERITY},
            "risk": {"raw": (f.evidence or {}).get("risk", f.severity), "score": risk_score,
                     "weight": WEIGHT_RISK, "contribution": risk_score * WEIGHT_RISK},
            "production_impact": {"raw": (f.evidence or {}).get("environment"), "score": prod_score,
                                   "weight": WEIGHT_PRODUCTION_IMPACT,
                                   "contribution": prod_score * WEIGHT_PRODUCTION_IMPACT},
            "recurrence": {"raw": recurrence_count, "score": recur_score, "weight": WEIGHT_RECURRENCE,
                           "contribution": recur_score * WEIGHT_RECURRENCE},
            "age": {"raw": round(age_days, 2), "score": age_score, "weight": WEIGHT_AGE,
                    "contribution": age_score * WEIGHT_AGE},
            "blast_radius": {"raw": blast_radius_count, "score": blast_score, "weight": WEIGHT_BLAST_RADIUS,
                              "contribution": blast_score * WEIGHT_BLAST_RADIUS},
            "sla": {"raw": None, "score": sla_score, "weight": WEIGHT_SLA, "contribution": 0.0,
                    "note": "no SLA/due-date concept exists in the schema; weight is 0 by design, "
                            "not silently omitted - see module docstring / ARCHITECTURE.md §35"},
        }
        if recurring_pattern_finding_ids is not None:
            in_pattern = f.id in recurring_pattern_finding_ids
            pattern_score = 1.0 if in_pattern else 0.0
            breakdown["recurring_pattern"] = {
                "raw": in_pattern, "score": pattern_score, "weight": WEIGHT_RECURRING_PATTERN,
                "contribution": pattern_score * WEIGHT_RECURRING_PATTERN,
                "note": "Phase 10 Wave 2 bonus factor - 1.0 iff this finding is part of a "
                        "cross-project recurring incident pattern (src/aep/intelligence/"
                        "incident_patterns.py); only present when the caller supplies "
                        "recurring_pattern_finding_ids",
            }
        if risk_scores_by_project is not None:
            proj_risk_score = float(risk_scores_by_project.get(f.project_id, 0.0))
            breakdown["risk_prediction"] = {
                "raw": proj_risk_score, "score": proj_risk_score, "weight": WEIGHT_RISK_PREDICTION,
                "contribution": proj_risk_score * WEIGHT_RISK_PREDICTION,
                "note": "Phase 10 Wave 3 bonus factor - this finding's project-level predictive "
                        "risk score (src/aep/intelligence/risk_prediction.py::predict_risk()); "
                        "only present when the caller supplies risk_scores_by_project",
            }
        total = sum(v["contribution"] for v in breakdown.values())

        results.append(PrioritizedFinding(
            finding_id=f.id, project_id=f.project_id, category=f.category, severity=f.severity,
            status=f.status, resource=f.resource,
            discovered_at=f.discovered_at.isoformat() if f.discovered_at else None,
            score=total, breakdown=breakdown,
        ))

    # Highest score first; ties broken by older discovered_at first, then id
    # for full determinism/stability.
    results.sort(key=lambda r: (-r.score, r.discovered_at or "", r.finding_id))
    for i, r in enumerate(results, start=1):
        r.rank = i
    return results


def prioritized_finding_to_dict(item: PrioritizedFinding) -> dict:
    return {
        "rank": item.rank, "finding_id": item.finding_id, "project_id": item.project_id,
        "category": item.category, "severity": item.severity, "status": item.status,
        "resource": item.resource, "discovered_at": item.discovered_at,
        "score": round(item.score, 6), "breakdown": item.breakdown,
    }
