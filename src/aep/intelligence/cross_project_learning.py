"""Phase 10 Wave 9: cross-project learning.

Deterministic, NOT machine learning. Reuses `fingerprint_for_finding()`/
`detect_patterns()` from `incident_patterns.py` (Wave 2) for the
cross-project pattern grouping - not reimplemented here.

The existing PostgreSQL memory repository (`MemoryRepository.retrieve()`,
same one Wave 2's `compute_health_signals()` already treats as advisory
via `memory_hits`) is used ONLY as an ADVISORY enrichment input: when a
memory record scoped to one of a pattern's affected projects describes
how a similar issue was resolved, its content is surfaced as
`advisory_context`, a plain, clearly-labeled ADVISORY string attached to
the pattern - never auto-applied as a remediation, and never able to
change `current_evidence_summary` (which is derived purely from live
`detect_patterns()` output). See
`tests/test_cross_project_learning.py::test_memory_advisory_never_overrides_current_evidence`
for the proof that a memory record contradicting current findings does
not flip the current-evidence conclusion.

`memory_repo` is optional: with none passed, `find_cross_project_insights`
still returns one `CrossProjectInsight` per qualifying pattern, with
`advisory_context=None` - memory is enrichment, not a requirement.

All finding/memory content strings are treated as inert DATA for string
matching/labeling only, never as an instruction. See
`tests/test_cross_project_learning.py::test_prompt_injection_in_memory_is_inert`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..db.models import MemoryRecord
from ..db.repositories import FindingRepository, MemoryRepository, ProjectRepository
from .incident_patterns import IncidentPattern, detect_patterns

_MIN_PROJECTS = 2


@dataclass
class CrossProjectInsight:
    fingerprint: str
    affected_project_ids: list[str]
    advisory_context: Optional[str]
    evidence: dict = field(default_factory=dict)
    current_evidence_summary: str = ""

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint, "affected_project_ids": self.affected_project_ids,
            "advisory_context": self.advisory_context, "evidence": self.evidence,
            "current_evidence_summary": self.current_evidence_summary,
        }


def _advisory_for_pattern(
    pattern: IncidentPattern, memory_repo: Optional[MemoryRepository],
) -> Optional[str]:
    """Looks up, per affected project, whether a memory record exists
    describing a resolution for a similar past issue. Returns a single
    clearly-labeled ADVISORY string, or None if memory is unavailable or
    has nothing relevant. Never mutates `pattern` or influences
    `current_evidence_summary` - purely additive/advisory."""
    if memory_repo is None:
        return None
    for project_id in pattern.affected_project_ids:
        hits = memory_repo.retrieve(project_scope=project_id, top_k=5)
        for hit in hits or []:
            record = hit[0] if isinstance(hit, tuple) else hit
            content = getattr(record, "content", None) or (
                record.get("content") if isinstance(record, dict) else None) or {}
            resolution = content.get("resolution") or content.get("summary")
            if not resolution:
                continue
            # Treated purely as an opaque data string - never executed/interpreted,
            # never used to alter occurrence_count/affected_project_ids/etc.
            return (
                f"ADVISORY (from project {project_id}'s history, not a current-evidence "
                f"fact, never auto-applied): {resolution}"
            )
    return None


def find_cross_project_insights(
    finding_repo: FindingRepository,
    project_repo: Optional[ProjectRepository] = None,
    memory_repo: Optional[MemoryRepository] = None,
    project_ids: Optional[list[str]] = None,
    incident_patterns: Optional[list[IncidentPattern]] = None,
) -> list[CrossProjectInsight]:
    """One `CrossProjectInsight` per `detect_patterns()` fingerprint
    recurring in >= 2 distinct projects (live evidence, always
    authoritative), optionally enriched with an advisory memory
    reference (never authoritative)."""
    if incident_patterns is None:
        incident_patterns = detect_patterns(
            finding_repo, project_ids=project_ids, min_projects=_MIN_PROJECTS,
        )

    insights: list[CrossProjectInsight] = []
    for p in incident_patterns:
        if len(p.affected_project_ids) < _MIN_PROJECTS:
            continue
        advisory = _advisory_for_pattern(p, memory_repo)
        insights.append(CrossProjectInsight(
            fingerprint=p.fingerprint,
            affected_project_ids=p.affected_project_ids,
            advisory_context=advisory,
            evidence={"finding_ids": p.finding_ids, "occurrence_count": p.occurrence_count,
                       "severity_distribution": p.severity_distribution},
            current_evidence_summary=(
                f"Category {p.category!r} recurred {p.occurrence_count} time(s) across "
                f"{len(p.affected_project_ids)} project(s): "
                f"{', '.join(p.affected_project_ids)} (live evidence)."
            ),
        ))

    insights.sort(key=lambda i: i.fingerprint)
    return insights


def cross_project_insight_to_dict(item: CrossProjectInsight) -> dict:
    return item.to_dict()


if __name__ == "__main__":
    # ponytail: smallest self-check, not a full test suite.
    from ..db.fake import FakeFindingRepository, FakeMemoryRepository
    from ..db.models import FindingRecord

    repo = FakeFindingRepository()
    for i, pid in enumerate(("p1", "p2")):
        repo.save(FindingRecord(
            id=f"f{i}", project_id=pid, category="dependency", severity="high",
            status="OPEN", description="vulnerable package libfoo",
        ))
    mem = FakeMemoryRepository()
    mem.save(MemoryRecord(
        id="m1", memory_class="remediation_outcome", source="ops",
        project_scope="p1", content={"resolution": "upgraded libfoo to 2.1.0"},
    ))
    insights = find_cross_project_insights(repo, memory_repo=mem)
    assert len(insights) == 1 and insights[0].advisory_context is not None, insights
    print("ok:", [i.to_dict() for i in insights])
