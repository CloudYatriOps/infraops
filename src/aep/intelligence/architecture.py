"""Phase 10 Wave 4: architecture intelligence.

Deterministic, NOT machine learning, NOT a dependency/service-topology
graph platform - there is no "OpsGraph" concept, no service dependency
graph, no CI-run table anywhere in this schema (see
`incident_patterns.py`'s own honest omission of `CI_FAILURE_CLUSTER`).
Every signal below is derived ONLY from what is actually queryable
through the existing repositories:

  * `FindingRepository.list()` - `FindingRecord.resource` (a free-text
    identifier, e.g. a file/module path) and `.category` distribution,
    per project and across projects.
  * `ProjectRepository.list()` - project ids/count, used only to know
    which projects exist, never to infer a dependency graph between them
    (no such data is persisted).
  * `detect_patterns()` from `incident_patterns.py` (Wave 2) - reused
    as an INPUT, not reimplemented, for the cross-project duplicated-
    infrastructure signal.

Signals emitted (each documents its own exact evidence source):

  * `RESOURCE_HOTSPOT` - REAL: the same `(project_id, resource)` pair
    accumulates >=3 findings (any category/severity/status). A resource
    with repeated findings is a concrete, evidence-backed hotspot.
  * `DUPLICATED_INFRASTRUCTURE_RISK` - REAL (derived from Wave 2): a
    `detect_patterns()` fingerprint (category+severity+environment+
    normalized description) recurs across >=2 projects - the same
    underlying category of issue was independently introduced into
    more than one project's infrastructure, a proxy for shared/
    duplicated infra risk. This is NOT a claim that the projects are
    architecturally coupled or share a dependency edge - no such edge
    exists in the data; it only means the same finding pattern appears
    in more than one project.
  * `FINDING_DIVERSITY_COMPLEXITY` - REAL: a project with a high number
    of DISTINCT unresolved (OPEN) finding categories is used as an
    honest PROXY for "this project's surface touches many different
    concern areas" (a complexity/coupling proxy from finding diversity,
    exactly as spec'd) - it is explicitly NOT a call-graph/dependency
    coupling metric, because no such data exists in this schema.
  * `SECURITY_BOUNDARY_WEAKNESS` - REAL: repeated (>=2) OPEN findings
    whose `category` or `resource` contains one of "iam", "secret",
    "network", "access_control", "permission" for a single project.
    `category` is checked against this project's real, DB-constrained
    category set (which includes `secret`); `resource` is also checked
    since the finding schema has no separate IAM/network/access-control
    category value - a finding whose resource is e.g. `iam/role.tf` or
    `network/sg.tf` is real evidence of a boundary-adjacent finding even
    though the category column itself is coarser (e.g. `iac`).

UNAVAILABLE, not fabricated: service topology, dependency graphs, call
graphs, deployment-frequency-derived "blast radius" beyond what
`prioritization.py` already computes, and any notion of "OpsGraph" - none
of these are backed by real data in this schema, so none are emitted.

All finding `description`/`resource`/`category` text is treated as inert
DATA for aggregation/counting only, never as an instruction. See
`tests/test_architecture_intelligence.py::test_prompt_injection_in_description_is_inert`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..db.models import FindingRecord
from ..db.repositories import FindingRepository, ProjectRepository
from .incident_patterns import IncidentPattern, detect_patterns

RESOURCE_HOTSPOT = "RESOURCE_HOTSPOT"
DUPLICATED_INFRASTRUCTURE_RISK = "DUPLICATED_INFRASTRUCTURE_RISK"
FINDING_DIVERSITY_COMPLEXITY = "FINDING_DIVERSITY_COMPLEXITY"
SECURITY_BOUNDARY_WEAKNESS = "SECURITY_BOUNDARY_WEAKNESS"

_HOTSPOT_MIN_COUNT = 3
_DUPLICATED_MIN_PROJECTS = 2
_DIVERSITY_MIN_CATEGORIES = 4
_BOUNDARY_MIN_COUNT = 2
_BOUNDARY_MARKERS = ("iam", "secret", "network", "access_control", "permission")


@dataclass
class ArchitecturalRisk:
    risk_id: str
    category: str
    severity: str
    affected_project_ids: list[str]
    affected_components: list[str]
    evidence: list[str] = field(default_factory=list)
    explanation: str = ""
    recommendation: str = ""

    def to_dict(self) -> dict:
        return {
            "risk_id": self.risk_id, "category": self.category, "severity": self.severity,
            "affected_project_ids": self.affected_project_ids,
            "affected_components": self.affected_components,
            "evidence": self.evidence, "explanation": self.explanation,
            "recommendation": self.recommendation,
        }


def _severity_rank(findings: list[FindingRecord]) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    best = "low"
    best_rank = 0
    for f in findings:
        rank = order.get((f.severity or "").lower(), 0)
        if rank > best_rank:
            best_rank = rank
            best = (f.severity or "low").lower()
    return best


def _resource_hotspots(findings_by_project: dict[str, list[FindingRecord]]) -> list[ArchitecturalRisk]:
    risks: list[ArchitecturalRisk] = []
    for project_id, findings in findings_by_project.items():
        by_resource: dict[str, list[FindingRecord]] = {}
        for f in findings:
            if not f.resource:
                continue
            by_resource.setdefault(f.resource, []).append(f)
        for resource, members in sorted(by_resource.items()):
            if len(members) < _HOTSPOT_MIN_COUNT:
                continue
            severity = _severity_rank(members)
            risks.append(ArchitecturalRisk(
                risk_id=RESOURCE_HOTSPOT, category="hotspot", severity=severity,
                affected_project_ids=[project_id], affected_components=[resource],
                evidence=sorted(m.id for m in members),
                explanation=(f"{resource!r} in project {project_id} accumulated "
                             f"{len(members)} finding(s) - a repeated hotspot rather than "
                             f"an isolated incident."),
                recommendation="Prioritize a structural fix (refactor/redesign) for this "
                                "resource over remediating each finding individually.",
            ))
    return risks


def _duplicated_infrastructure(patterns: list[IncidentPattern]) -> list[ArchitecturalRisk]:
    risks: list[ArchitecturalRisk] = []
    for p in patterns:
        if len(p.affected_project_ids) < _DUPLICATED_MIN_PROJECTS:
            continue
        top_sev = max(p.severity_distribution, key=lambda k: p.severity_distribution[k])
        risks.append(ArchitecturalRisk(
            risk_id=DUPLICATED_INFRASTRUCTURE_RISK, category=p.category, severity=top_sev,
            affected_project_ids=p.affected_project_ids, affected_components=[p.fingerprint],
            evidence=p.finding_ids,
            explanation=(f"Pattern {p.fingerprint!r} (category={p.category}) recurred "
                         f"{p.occurrence_count} time(s) across {len(p.affected_project_ids)} "
                         f"project(s): {', '.join(p.affected_project_ids)} - the same class of "
                         f"issue was independently introduced in more than one project's "
                         f"infrastructure (not a claim of a dependency edge between them; no "
                         f"topology data exists in this schema)."),
            recommendation="Consolidate the shared root cause (e.g. a common template/module/"
                            "base image) instead of fixing each project's copy separately.",
        ))
    return risks


def _finding_diversity(findings_by_project: dict[str, list[FindingRecord]]) -> list[ArchitecturalRisk]:
    risks: list[ArchitecturalRisk] = []
    for project_id, findings in sorted(findings_by_project.items()):
        open_findings = [f for f in findings if f.status == "OPEN"]
        categories = sorted({f.category for f in open_findings if f.category})
        if len(categories) < _DIVERSITY_MIN_CATEGORIES:
            continue
        risks.append(ArchitecturalRisk(
            risk_id=FINDING_DIVERSITY_COMPLEXITY, category="complexity", severity="medium",
            affected_project_ids=[project_id], affected_components=categories,
            evidence=sorted(f.id for f in open_findings),
            explanation=(f"Project {project_id} has {len(categories)} distinct unresolved "
                         f"finding categories ({', '.join(categories)}) - a proxy for broad, "
                         f"possibly under-modularized surface area (derived only from finding "
                         f"category diversity, NOT a call-graph/dependency coupling metric - "
                         f"no such data exists in this schema)."),
            recommendation="Consider whether this project's scope should be split, and whether "
                            "ownership/review coverage matches its actual surface area.",
        ))
    return risks


def _security_boundary_weakness(findings_by_project: dict[str, list[FindingRecord]]) -> list[ArchitecturalRisk]:
    risks: list[ArchitecturalRisk] = []
    for project_id, findings in sorted(findings_by_project.items()):
        boundary = [f for f in findings if f.status == "OPEN"
                    and any(marker in (f.category or "").lower()
                            or marker in (f.resource or "").lower()
                            for marker in _BOUNDARY_MARKERS)]
        if len(boundary) < _BOUNDARY_MIN_COUNT:
            continue
        severity = _severity_rank(boundary)
        components = sorted({f.resource for f in boundary if f.resource}) or [project_id]
        risks.append(ArchitecturalRisk(
            risk_id=SECURITY_BOUNDARY_WEAKNESS, category="security_boundary", severity=severity,
            affected_project_ids=[project_id], affected_components=components,
            evidence=sorted(f.id for f in boundary),
            explanation=(f"Project {project_id} has {len(boundary)} OPEN finding(s) in "
                         f"IAM/secrets/network-boundary categories - a recurring weakness at "
                         f"the project's security boundary rather than a one-off."),
            recommendation="Review the identity/secret/network boundary design for this "
                            "project as a whole, not just the individual findings.",
        ))
    return risks


def analyze_architecture(
    finding_repo: FindingRepository,
    project_repo: Optional[ProjectRepository] = None,
    project_ids: Optional[list[str]] = None,
    incident_patterns: Optional[list[IncidentPattern]] = None,
) -> list[ArchitecturalRisk]:
    """Deterministic architecture-level risk signals derived only from
    persisted finding/pattern evidence (see module docstring for exactly
    what each signal is/isn't backed by). `incident_patterns` reuses
    `detect_patterns()` (computed internally unless already supplied by
    the caller, matching `risk_prediction.py`'s own optional-injection
    convention) rather than re-deriving pattern detection here.
    """
    all_findings = finding_repo.list(None, None)
    if project_ids is not None:
        wanted = set(project_ids)
        all_findings = [f for f in all_findings if f.project_id in wanted]

    if project_repo is not None:
        known_ids = {p.id for p in project_repo.list()}
        if project_ids is not None:
            known_ids &= set(project_ids)
    else:
        known_ids = {f.project_id for f in all_findings}

    findings_by_project: dict[str, list[FindingRecord]] = {pid: [] for pid in known_ids}
    for f in all_findings:
        findings_by_project.setdefault(f.project_id, []).append(f)

    if incident_patterns is None:
        incident_patterns = detect_patterns(finding_repo, project_ids=project_ids)

    risks: list[ArchitecturalRisk] = []
    risks.extend(_resource_hotspots(findings_by_project))
    risks.extend(_duplicated_infrastructure(incident_patterns))
    risks.extend(_finding_diversity(findings_by_project))
    risks.extend(_security_boundary_weakness(findings_by_project))

    _SEVERITY_SORT = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    risks.sort(key=lambda r: (_SEVERITY_SORT.get(r.severity, 4), r.risk_id,
                               r.affected_project_ids, r.affected_components))
    return risks


def architectural_risk_to_dict(item: ArchitecturalRisk) -> dict:
    return item.to_dict()
