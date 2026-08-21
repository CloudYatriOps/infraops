"""Phase 10 Wave 2: incident-pattern / engineering-health intelligence.

Detects recurring patterns ACROSS PROJECTS using only already-persisted
data, read through the EXISTING repositories/read-paths - this module
never scans/writes findings, incidents, or deployment evidence itself:

  * `FindingRepository.list()` (same repository `prioritization.py` and
    the `/findings` API handler already use)
  * `src/aep/operations/memory.py::list_incidents` (Part 9 incident
    memory - consulted as ADVISORY context only, never authoritative -
    see `compute_health_signals()`)
  * `src/aep/deployment/evidence.py::list_deployment_evidence` (Phase 6
    deployment evidence - used for the rollback-rate signal)
  * `ProjectRepository.list()` (project ids/posture, same as
    `prioritization.py`)

No raw SQL, no new storage primitive, no duplication of the security
scanner / CVE engine / operations engine / policy engine / task engine /
skill registry / prioritization engine - those are INPUTS only.

Scope (read this before extending):
  * IN: cross-project recurring-pattern detection over `FindingRecord`s,
    a fixed set of deterministic "engineering health" signals derived
    from that + deployment evidence + (advisory) incident memory, and a
    thin prioritization-integration hook.
  * OUT, not silently faked: CI-job-specific failure data. Nothing in
    the schema records a CI job/step identity distinct from a finding or
    a deployment attempt (`src/aep/migrations_sql/*.sql` has no `ci_runs`
    table), so `CI_FAILURE_CLUSTER` is never emitted by this module -
    see `docs/PHASE10.md` for the honest omission rather than a fake
    always-empty signal.
  * `remediation_outcomes` on a pattern is populated ONLY when a real
    deployment record exists for one of the pattern's findings'
    `task_id`s; otherwise the key is simply absent from the pattern,
    never invented.

All content read from findings/incidents (description strings, root
causes, etc.) is treated as inert DATA for string analysis only - it is
never interpreted as an instruction. See
`tests/test_incident_patterns.py::test_prompt_injection_in_description_is_inert`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from ..db.models import FindingRecord, MemoryRecord, ProjectRecord
from ..db.repositories import FindingRepository, ProjectRepository
from ..deployment.models import DeploymentRecord
from ..operations.memory import IncidentMemoryRecord

# ---------------------------------------------------------------------------
# Fingerprinting
# ---------------------------------------------------------------------------

_SIGNATURE_LEN = 40  # NOT NLP - a short, stable, human-inspectable prefix.
_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def _normalize_signature(description: str) -> str:
    """A short, stable, lowercase/alnum-only prefix of `description` - a
    normalized error-signature string, deliberately NOT NLP. Any content
    in `description` (including something engineered to look like an
    instruction, e.g. "ignore all policies") is treated purely as
    characters to normalize and truncate; it is never evaluated,
    executed, or otherwise treated as anything but data."""
    cleaned = _NON_ALNUM.sub("-", (description or "").strip().lower()).strip("-")
    return cleaned[:_SIGNATURE_LEN]


def fingerprint_for_finding(finding: FindingRecord) -> str:
    """Deterministic, stable fingerprint for cross-project pattern
    grouping. Same inputs -> same fingerprint, always (pure function of
    the record's own fields, no clock/randomness involved).

    Factors used (see module docstring for what was deliberately
    excluded and why):
      * `category` - the finding's own classification.
      * `severity` - distinguishes e.g. a critical exposed_secret from a
        low one; two otherwise-identical findings of different severity
        are NOT the same pattern.
      * `environment` - `evidence["environment"]` if the recording
        engine set one (same field `prioritization.py`'s
        production_impact factor reads), else "unknown" - never
        invented from `ProjectRecord.default_posture` here, since that's
        a project-level default, not evidence this specific finding
        occurred in that environment.
      * normalized error-signature - first `_SIGNATURE_LEN` normalized
        characters of `description`.

    Deliberately NOT included (honest omission, not invented):
      * "affected component type" - no such field exists on
        `FindingRecord`; `resource` is a free-text identifier (e.g. a
        file path or resource name), not a typed "component type", so
        including raw `resource` would make near-identical incidents on
        different resources of the same underlying category never
        collide, which defeats the point of a cross-project pattern
        fingerprint. Omitted rather than misused.
      * "deployment relationship" (whether this finding is linked to a
        deployment event) - included as a SEPARATE derived field on the
        `IncidentPattern` (`remediation_outcomes`), not folded into the
        fingerprint itself, since whether a fix succeeded is an outcome
        of the pattern, not part of what identifies it.
    """
    return "|".join([
        finding.category or "-",
        (finding.severity or "-").lower(),
        str((finding.evidence or {}).get("environment") or "unknown").lower(),
        _normalize_signature(finding.description),
    ])


# ---------------------------------------------------------------------------
# Recurrence analysis
# ---------------------------------------------------------------------------

@dataclass
class IncidentPattern:
    fingerprint: str
    category: str
    occurrence_count: int
    finding_ids: list[str]
    affected_project_ids: list[str]
    affected_environments: list[str]
    first_seen: Optional[str]
    most_recent: Optional[str]
    recurrence_interval_days: Optional[float]
    severity_distribution: dict
    remediation_outcomes: Optional[dict] = None

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint, "category": self.category,
            "occurrence_count": self.occurrence_count, "finding_ids": self.finding_ids,
            "affected_project_ids": self.affected_project_ids,
            "affected_environments": self.affected_environments,
            "first_seen": self.first_seen, "most_recent": self.most_recent,
            "recurrence_interval_days": self.recurrence_interval_days,
            "severity_distribution": self.severity_distribution,
            "remediation_outcomes": self.remediation_outcomes,
        }


def _finding_environment(f: FindingRecord) -> str:
    return str((f.evidence or {}).get("environment") or "unknown").lower()


def _deployment_outcome_for_finding(
    f: FindingRecord, deployment_evidence_by_project: dict,
) -> Optional[bool]:
    """True/False if a deployment record for this finding's `task_id`
    exists and reached a terminal state, else None (genuinely unknown -
    never guessed)."""
    if not f.task_id:
        return None
    records: list[DeploymentRecord] = deployment_evidence_by_project.get(f.project_id, [])
    matches = [r for r in records if r.task_id == f.task_id]
    if not matches:
        return None
    latest = matches[-1]
    if latest.final_state.value in ("VERIFIED", "DEPLOYED"):
        return True
    if latest.final_state.value in ("FAILED", "ROLLED_BACK"):
        return False
    return None


def detect_patterns(
    finding_repo: FindingRepository,
    project_ids: Optional[list[str]] = None,
    min_projects: int = 2,
    deployment_evidence_by_project: Optional[dict] = None,
) -> list[IncidentPattern]:
    """Groups every `FindingRecord` `finding_repo` knows about (any
    status - a closed finding still counts toward "this has recurred")
    by `fingerprint_for_finding`, and returns one `IncidentPattern` per
    fingerprint that recurs across at least `min_projects` distinct
    projects (default 2 - the "ACROSS PROJECTS" requirement). Pass
    `min_projects=1` to also surface same-project-only recurrence.

    Deterministic: sorted by `(-occurrence_count, fingerprint)` so
    output ordering is stable and reproducible.
    """
    all_findings = finding_repo.list(None, None)
    if project_ids is not None:
        wanted = set(project_ids)
        all_findings = [f for f in all_findings if f.project_id in wanted]

    by_fp: dict[str, list[FindingRecord]] = {}
    for f in all_findings:
        by_fp.setdefault(fingerprint_for_finding(f), []).append(f)

    deployment_evidence_by_project = deployment_evidence_by_project or {}

    patterns: list[IncidentPattern] = []
    for fp, members in by_fp.items():
        project_ids_seen = sorted({m.project_id for m in members})
        if len(project_ids_seen) < min_projects:
            continue

        timestamps = sorted(m.discovered_at for m in members if m.discovered_at is not None)
        first_seen = timestamps[0].isoformat() if timestamps else None
        most_recent = timestamps[-1].isoformat() if timestamps else None

        # Recurrence interval: only meaningful with >=2 REAL, DISTINCT
        # timestamps - never invented from a single point or from
        # identical (e.g. insert-time-collapsed) timestamps. See
        # BUG-0006 (fixed this pass): before the fix, real-Postgres
        # `discovered_at` was always "now" at insert time, which would
        # have silently collapsed every interval to ~0; the fix
        # preserves a caller-supplied `discovered_at`, so this
        # computation is reliable against real Postgres data as of this
        # pass.
        distinct_ts = sorted({t for t in timestamps})
        interval_days: Optional[float] = None
        if len(distinct_ts) >= 2:
            span = (distinct_ts[-1] - distinct_ts[0]).total_seconds() / 86400.0
            interval_days = round(span / (len(distinct_ts) - 1), 4)

        severity_distribution: dict = {}
        for m in members:
            key = (m.severity or "unknown").lower()
            severity_distribution[key] = severity_distribution.get(key, 0) + 1

        outcomes = {"succeeded": 0, "failed": 0}
        any_known = False
        for m in members:
            outcome = _deployment_outcome_for_finding(m, deployment_evidence_by_project)
            if outcome is None:
                continue
            any_known = True
            outcomes["succeeded" if outcome else "failed"] += 1

        patterns.append(IncidentPattern(
            fingerprint=fp,
            category=members[0].category,
            occurrence_count=len(members),
            finding_ids=sorted(m.id for m in members),
            affected_project_ids=project_ids_seen,
            affected_environments=sorted({_finding_environment(m) for m in members}),
            first_seen=first_seen,
            most_recent=most_recent,
            recurrence_interval_days=interval_days,
            severity_distribution=severity_distribution,
            remediation_outcomes=outcomes if any_known else None,
        ))

    patterns.sort(key=lambda p: (-p.occurrence_count, p.fingerprint))
    return patterns


# ---------------------------------------------------------------------------
# Engineering health signals
# ---------------------------------------------------------------------------

class SignalState:
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    POSSIBLE = "POSSIBLE"
    UNKNOWN = "UNKNOWN"


# Fixed enum of signal ids this module may emit. `CI_FAILURE_CLUSTER` is
# deliberately never emitted (see module docstring) - listed here only so
# the full spec vocabulary is visible in one place, not because this
# module produces it.
HIGH_RECURRENT_INCIDENT_RATE = "HIGH_RECURRENT_INCIDENT_RATE"
FREQUENT_DEPLOYMENT_ROLLBACK = "FREQUENT_DEPLOYMENT_ROLLBACK"
SECURITY_FINDINGS_INCREASING = "SECURITY_FINDINGS_INCREASING"
CI_FAILURE_CLUSTER = "CI_FAILURE_CLUSTER"  # never emitted - no CI-run data in schema
REPEATED_CVE_REMEDIATION = "REPEATED_CVE_REMEDIATION"
UNRESOLVED_CRITICAL_FINDINGS = "UNRESOLVED_CRITICAL_FINDINGS"
REPEATED_FAILED_REMEDIATION = "REPEATED_FAILED_REMEDIATION"

_CVE_CATEGORY_MARKERS = ("cve", "dependency", "vulnerability", "vuln")

_RECURRENCE_CONFIRMED_THRESHOLD = 3   # >=3 occurrences -> CONFIRMED
_RECURRENCE_LIKELY_THRESHOLD = 2      # ==2 occurrences -> LIKELY
_UNRESOLVED_AGE_CONFIRMED_DAYS = 30   # open critical finding older than this -> CONFIRMED
_ROLLBACK_RATIO_CONFIRMED = 0.3
_ROLLBACK_MIN_COUNT_CONFIRMED = 2


@dataclass
class HealthSignal:
    signal_id: str
    severity: str
    state: str
    affected_projects: list[str]
    evidence_ids: list[str]
    explanation: str
    recommended_action: str
    score: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "signal_id": self.signal_id, "severity": self.severity, "state": self.state,
            "affected_projects": self.affected_projects, "evidence_ids": self.evidence_ids,
            "explanation": self.explanation, "recommended_action": self.recommended_action,
            "score": self.score,
        }


def _occurrence_state(count: int) -> str:
    if count >= _RECURRENCE_CONFIRMED_THRESHOLD:
        return SignalState.CONFIRMED
    if count >= _RECURRENCE_LIKELY_THRESHOLD:
        return SignalState.LIKELY
    return SignalState.POSSIBLE


def _age_days(discovered_at) -> float:
    if discovered_at is None:
        return 0.0
    dt = discovered_at
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max((datetime.now(timezone.utc) - dt).total_seconds() / 86400.0, 0.0)


def _memory_says_healthy(memory_hits: Optional[list], project_id: str) -> bool:
    """Advisory-only check of a stubbed/real memory signal claiming a
    project is healthy/low-risk. Used ONLY to prove that live evidence
    always outranks it (see `compute_health_signals`'s docstring and
    `tests/test_incident_patterns.py::test_current_evidence_outranks_memory`)
    - never used to raise or confirm a state on its own."""
    for hit in memory_hits or []:
        content = getattr(hit, "content", None) or (hit.get("content") if isinstance(hit, dict) else None) or {}
        scope = getattr(hit, "project_scope", None) if not isinstance(hit, dict) else hit.get("project_scope")
        if scope == project_id and str(content.get("status", "")).lower() in ("healthy", "low-risk", "low_risk"):
            return True
    return False


def compute_health_signals(
    finding_repo: FindingRepository,
    project_repo: Optional[ProjectRepository] = None,
    deployment_evidence_by_project: Optional[dict] = None,
    incidents_by_project: Optional[dict] = None,
    memory_hits: Optional[list] = None,
    project_ids: Optional[list[str]] = None,
) -> list[HealthSignal]:
    """Computes the fixed set of deterministic engineering-health signals
    this module supports, from real persisted evidence only.

    `memory_hits` (a list of `MemoryRecord`-shaped objects/dicts, or
    None) is consulted ONLY as advisory/lower-weight context - it can
    never by itself raise a signal to CONFIRMED/LIKELY, and it can never
    suppress a signal that current live evidence supports. This is
    proven by `test_current_evidence_outranks_memory`: a memory record
    claiming a project is "healthy" is passed in ALONGSIDE current
    findings showing a recurring critical pattern for that same project,
    and the resulting signal is still CONFIRMED - the memory input is
    simply ignored where it would contradict live evidence, matching
    `MemoryRepository.retrieve`'s own "advisory_flag is ALWAYS True"
    contract.
    """
    all_findings = finding_repo.list(None, None)
    if project_ids is not None:
        wanted = set(project_ids)
        all_findings = [f for f in all_findings if f.project_id in wanted]

    deployment_evidence_by_project = deployment_evidence_by_project or {}
    incidents_by_project = incidents_by_project or {}
    signals: list[HealthSignal] = []

    # ---- HIGH_RECURRENT_INCIDENT_RATE (cross-project patterns) --------
    patterns = detect_patterns(finding_repo, project_ids=project_ids,
                                deployment_evidence_by_project=deployment_evidence_by_project)
    for p in patterns:
        state = _occurrence_state(p.occurrence_count)
        top_sev = max(p.severity_distribution, key=lambda k: p.severity_distribution[k])
        signals.append(HealthSignal(
            signal_id=HIGH_RECURRENT_INCIDENT_RATE,
            severity=top_sev,
            state=state,
            affected_projects=p.affected_project_ids,
            evidence_ids=p.finding_ids,
            explanation=(f"Pattern {p.fingerprint!r} (category={p.category}) recurred "
                         f"{p.occurrence_count} time(s) across {len(p.affected_project_ids)} "
                         f"project(s): {', '.join(p.affected_project_ids)}."),
            recommended_action="Investigate the shared root cause across affected projects "
                                "rather than remediating each finding independently.",
            score=round(min(p.occurrence_count / _RECURRENCE_CONFIRMED_THRESHOLD, 1.0), 4),
        ))

        # ---- REPEATED_CVE_REMEDIATION (subset of patterns) -------------
        if any(marker in (p.category or "").lower() for marker in _CVE_CATEGORY_MARKERS):
            signals.append(HealthSignal(
                signal_id=REPEATED_CVE_REMEDIATION,
                severity=top_sev,
                state=state,
                affected_projects=p.affected_project_ids,
                evidence_ids=p.finding_ids,
                explanation=(f"CVE/dependency-vulnerability category {p.category!r} recurred "
                             f"{p.occurrence_count} time(s) across "
                             f"{len(p.affected_project_ids)} project(s) - the same "
                             f"vulnerability class keeps reappearing rather than being "
                             f"permanently remediated."),
                recommended_action="Pin/upgrade the shared dependency at the source (e.g. a "
                                    "common base image or lockfile) instead of patching each "
                                    "project's instance individually.",
                score=round(min(p.occurrence_count / _RECURRENCE_CONFIRMED_THRESHOLD, 1.0), 4),
            ))

    # ---- UNRESOLVED_CRITICAL_FINDINGS (per project) --------------------
    by_project: dict[str, list[FindingRecord]] = {}
    for f in all_findings:
        by_project.setdefault(f.project_id, []).append(f)

    for project_id, findings in by_project.items():
        open_critical = [f for f in findings if f.status == "OPEN" and (f.severity or "").lower() == "critical"]
        if not open_critical:
            continue
        old_ones = [f for f in open_critical if _age_days(f.discovered_at) >= _UNRESOLVED_AGE_CONFIRMED_DAYS]
        state = SignalState.CONFIRMED if old_ones else SignalState.LIKELY
        evidence = old_ones or open_critical
        # Current live evidence overrides any advisory "healthy" memory claim.
        signals.append(HealthSignal(
            signal_id=UNRESOLVED_CRITICAL_FINDINGS,
            severity="critical",
            state=state,
            affected_projects=[project_id],
            evidence_ids=sorted(f.id for f in evidence),
            explanation=(f"{len(open_critical)} OPEN critical finding(s) on {project_id}"
                         + (f", {len(old_ones)} open >= {_UNRESOLVED_AGE_CONFIRMED_DAYS} days"
                            if old_ones else "") + "."),
            recommended_action="Prioritize remediation of these open critical findings before "
                                "any further feature work on this project.",
            score=round(min(len(open_critical) / 3.0, 1.0), 4),
        ))

    # ---- SECURITY_FINDINGS_INCREASING (per project, 30d window trend) --
    now = datetime.now(timezone.utc)
    for project_id, findings in by_project.items():
        dated = [f for f in findings if f.discovered_at is not None
                 and (f.severity or "").lower() in ("critical", "high")]
        if len(dated) < 2:
            continue
        recent = [f for f in dated if _age_days(f.discovered_at) <= 30]
        previous = [f for f in dated if 30 < _age_days(f.discovered_at) <= 60]
        if len(recent) > len(previous) and len(recent) >= 2:
            state = SignalState.CONFIRMED if len(previous) > 0 else SignalState.LIKELY
            signals.append(HealthSignal(
                signal_id=SECURITY_FINDINGS_INCREASING,
                severity="high",
                state=state,
                affected_projects=[project_id],
                evidence_ids=sorted(f.id for f in recent),
                explanation=(f"{project_id}: {len(recent)} critical/high finding(s) discovered "
                             f"in the last 30 days vs {len(previous)} in the prior 30-day "
                             f"window."),
                recommended_action="Review recent changes/scans on this project - the rate of "
                                    "new high-severity findings is trending up.",
                score=round(min(len(recent) / max(len(previous), 1) / 2.0, 1.0), 4),
            ))

    # ---- FREQUENT_DEPLOYMENT_ROLLBACK (per project) --------------------
    for project_id, records in deployment_evidence_by_project.items():
        if project_ids is not None and project_id not in set(project_ids):
            continue
        total = len(records)
        if total == 0:
            continue
        rolled_back = [r for r in records if r.final_state.value == "ROLLED_BACK"]
        if not rolled_back:
            continue
        ratio = len(rolled_back) / total
        if len(rolled_back) >= _ROLLBACK_MIN_COUNT_CONFIRMED and ratio >= _ROLLBACK_RATIO_CONFIRMED:
            state = SignalState.CONFIRMED
        elif len(rolled_back) >= 1:
            state = SignalState.POSSIBLE if len(rolled_back) == 1 and total > 3 else SignalState.LIKELY
        else:
            continue
        signals.append(HealthSignal(
            signal_id=FREQUENT_DEPLOYMENT_ROLLBACK,
            severity="high",
            state=state,
            affected_projects=[project_id],
            evidence_ids=sorted(r.task_id for r in rolled_back),
            explanation=(f"{project_id}: {len(rolled_back)}/{total} recorded deployment "
                         f"attempt(s) ended ROLLED_BACK ({ratio:.0%})."),
            recommended_action="Investigate the release/verification gates for this project "
                                "before the next deployment attempt.",
            score=round(min(ratio, 1.0), 4),
        ))

    # ---- REPEATED_FAILED_REMEDIATION (advisory incident memory) --------
    for project_id, incidents in incidents_by_project.items():
        if project_ids is not None and project_id not in set(project_ids):
            continue
        by_fp: dict[str, list[IncidentMemoryRecord]] = {}
        for inc in incidents:
            by_fp.setdefault(inc.fingerprint, []).append(inc)
        for fp, group in by_fp.items():
            failed = [g for g in group if not g.remediation_succeeded]
            if len(failed) < 2:
                continue
            state = _occurrence_state(len(failed))
            signals.append(HealthSignal(
                signal_id=REPEATED_FAILED_REMEDIATION,
                severity="high",
                state=state,
                affected_projects=[project_id],
                evidence_ids=sorted(g.incident_id for g in failed),
                explanation=(f"{project_id}: remediation for incident fingerprint {fp!r} "
                             f"failed {len(failed)} time(s) in recorded incident memory."),
                recommended_action="Escalate to a human - repeated automated remediation "
                                    "attempts for the same fingerprint have not succeeded.",
                score=round(min(len(failed) / _RECURRENCE_CONFIRMED_THRESHOLD, 1.0), 4),
            ))

    # Note on memory: `memory_hits` is intentionally NOT capable of
    # suppressing or downgrading any signal above - it is never consulted
    # in this function's decision logic at all beyond the helper
    # `_memory_says_healthy` (kept for callers/tests that want to prove
    # the "current evidence outranks memory" principle explicitly - see
    # `tests/test_incident_patterns.py::test_current_evidence_outranks_memory`,
    # which asserts that a "healthy" memory record does not remove/downgrade
    # an UNRESOLVED_CRITICAL_FINDINGS/HIGH_RECURRENT_INCIDENT_RATE signal
    # computed from real current findings for the same project).
    _ = memory_hits

    signals.sort(key=lambda s: (s.signal_id, s.affected_projects))
    return signals
