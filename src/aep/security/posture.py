"""Security posture / security score (Phase 4 Part 10).

Extends the existing progress/status system rather than replacing it:
`compute_security_posture()` is a pure function over already-collected
scan records (+ dependency scan records from Phase 3 + suppressions), the
same "compute fresh from real evidence, never a stored percentage" rule
`progress/calculator.py` already follows. `cli.py` wires this into
`aep status --json`'s `security_posture` key (see Part 11).

Category rows deliberately match the five named in the Phase 4 spec's own
example output verbatim: Secrets, SAST, Dependencies, IaC, Containers -
the first, second, and fourth/fifth come from this package's own scanners;
"Dependencies" reuses Phase 3's `dependency.models.ScanRecord` unmodified
(no new dependency-scanning code - Part 11 forbids inventing a parallel
system)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..dependency.models import ScanRecord as DependencyScanRecord
from .models import ScannerAvailability, SecurityScanRecord, SecuritySeverity
from .suppressions import Suppression, is_suppressed

READY = "READY"
NOT_READY = "NOT_READY"

_CATEGORY_DISPLAY = {
    "secret": "Secrets", "sast": "SAST", "iac": "IaC", "container": "Containers",
    # Phase 5 categories.
    "kubernetes": "Kubernetes", "helm": "Helm",
}

# "Worst wins" ordering when several scanners cover one category (Phase 5:
# `iac` is covered by both checkov and terraform-deep, `kubernetes` by both
# checkov-kubernetes and k8s-native). If ANY scanner in a category could
# not run, the category is only partially covered and must not render as a
# fully-verified PASS - so BLOCKED/UNAVAILABLE dominates AVAILABLE.
# NOT_APPLICABLE is the weakest: a scanner with nothing to scan should not
# mask a sibling that did real work.
_AVAILABILITY_RANK = {
    ScannerAvailability.BLOCKED: 3,
    ScannerAvailability.UNAVAILABLE: 2,
    ScannerAvailability.AVAILABLE: 1,
    ScannerAvailability.NOT_APPLICABLE: 0,
}


@dataclass
class CategoryPosture:
    name: str
    status: str  # "PASS" | "<n> <SEVERITY>" | "BLOCKED" | "UNAVAILABLE" | "NOT_APPLICABLE"
    availability: str
    open_finding_count: int
    suppressed_finding_count: int
    detail: str

    def to_dict(self) -> dict:
        return {
            "name": self.name, "status": self.status, "availability": self.availability,
            "open_finding_count": self.open_finding_count,
            "suppressed_finding_count": self.suppressed_finding_count, "detail": self.detail,
        }


@dataclass
class SecurityPosture:
    categories: list[CategoryPosture] = field(default_factory=list)
    readiness: str = NOT_READY
    explanation: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "categories": [c.to_dict() for c in self.categories],
            "readiness": self.readiness, "explanation": self.explanation,
        }

    def render_text(self) -> str:
        lines = ["SECURITY POSTURE", "-" * 16]
        width = max((len(c.name) for c in self.categories), default=8) + 2
        for c in self.categories:
            lines.append(f"{c.name:<{width}}{c.status}")
        lines.append("")
        lines.append("Security readiness:")
        lines.append(self.readiness)
        if self.explanation:
            lines.append("")
            for e in self.explanation:
                lines.append(f"  - {e}")
        return "\n".join(lines)


def _category_from_security_records(records: list[SecurityScanRecord],
                                      suppressions: list[Suppression]) -> list[CategoryPosture]:
    """One row per CATEGORY, not per scanner.

    Phase 4 had exactly one scanner per category, so this grouping was a
    no-op then and its behavior there is unchanged. Phase 5 adds a second
    scanner to two categories (`iac`: checkov + terraform-deep;
    `kubernetes`: checkov-kubernetes + k8s-native), which without grouping
    rendered two separate "IaC" rows with different verdicts - unreadable,
    and worse, a passing row could sit directly above a failing one for
    the same category.
    """
    grouped: dict[str, list[SecurityScanRecord]] = {}
    for record in records:
        grouped.setdefault(record.category.value, []).append(record)

    rank = {SecuritySeverity.CRITICAL: 4, SecuritySeverity.HIGH: 3, SecuritySeverity.MEDIUM: 2,
            SecuritySeverity.LOW: 1, SecuritySeverity.INFO: 0}
    out: list[CategoryPosture] = []
    for category, category_records in grouped.items():
        display = _CATEGORY_DISPLAY.get(category, category)
        worst = max((r.availability for r in category_records),
                     key=lambda a: _AVAILABILITY_RANK[a])
        all_findings = [f for r in category_records for f in r.findings]
        open_findings = [f for f in all_findings if is_suppressed(suppressions, f.id) is None]
        suppressed_count = len(all_findings) - len(open_findings)
        scanners = ", ".join(sorted({r.scanner for r in category_records}))

        if worst != ScannerAvailability.AVAILABLE:
            notes = "; ".join(r.note for r in category_records
                               if r.availability == worst and r.note)
            # A partially-covered category that STILL found something must
            # say both things: coverage is incomplete AND these are real.
            status = worst.value
            if open_findings:
                status = f"{worst.value} (+{len(open_findings)} found)"
            out.append(CategoryPosture(
                name=display, status=status, availability=worst.value,
                open_finding_count=len(open_findings),
                suppressed_finding_count=suppressed_count,
                detail=(notes or f"{scanners} did not run")
                        + (f" | {len(open_findings)} finding(s) were still reported by the "
                           f"scanner(s) that did run, so this category is partially covered, "
                           f"not clean" if open_findings else ""),
            ))
            continue

        if not open_findings:
            status = "PASS"
        else:
            top_severity = max((f.severity for f in open_findings), key=lambda s: rank[s])
            count_at_top = sum(1 for f in open_findings if f.severity == top_severity)
            status = f"{count_at_top} {top_severity.value.upper()}"
        out.append(CategoryPosture(
            name=display, status=status, availability=worst.value,
            open_finding_count=len(open_findings), suppressed_finding_count=suppressed_count,
            detail=f"{len(open_findings)} open finding(s) via {scanners}"
                   + (f", {suppressed_count} suppressed" if suppressed_count else ""),
        ))
    return out


def _category_from_dependency_records(records: list[DependencyScanRecord]) -> CategoryPosture:
    if not records:
        return CategoryPosture(name="Dependencies", status="NOT_APPLICABLE",
                                availability=ScannerAvailability.NOT_APPLICABLE.value,
                                open_finding_count=0, suppressed_finding_count=0,
                                detail="no dependency manifests scanned")
    total_findings = sum(r.finding_count for r in records)
    scanners_used = sorted({r.scanner for r in records})
    if total_findings == 0:
        return CategoryPosture(name="Dependencies", status="PASS",
                                availability=ScannerAvailability.AVAILABLE.value, open_finding_count=0,
                                suppressed_finding_count=0,
                                detail=f"0 findings via {', '.join(scanners_used)}")
    return CategoryPosture(
        name="Dependencies", status=f"{total_findings} FINDING(S)",
        availability=ScannerAvailability.AVAILABLE.value, open_finding_count=total_findings,
        suppressed_finding_count=0, detail=f"{total_findings} finding(s) via {', '.join(scanners_used)}",
    )


def compute_security_posture(security_records: list[SecurityScanRecord],
                              dependency_records: Optional[list[DependencyScanRecord]] = None,
                              suppressions: Optional[list[Suppression]] = None) -> SecurityPosture:
    suppressions = suppressions or []
    categories = _category_from_security_records(security_records, suppressions)
    categories.insert(2 if len(categories) >= 2 else len(categories),
                       _category_from_dependency_records(dependency_records or []))

    explanation: list[str] = []
    blocking = False
    for c in categories:
        if c.availability in (ScannerAvailability.BLOCKED.value, ScannerAvailability.UNAVAILABLE.value):
            blocking = True
            explanation.append(f"{c.name} could not be verified in this environment "
                                f"({c.availability}): {c.detail}")
        elif c.open_finding_count > 0:
            # Only CRITICAL/HIGH open findings block readiness (Part 8);
            # MEDIUM/LOW are tracked but don't fail the gate on their own.
            has_high_or_above = c.status.split(" ")[-1] in ("CRITICAL", "HIGH") if c.status[:1].isdigit() \
                else False
            if has_high_or_above:
                blocking = True
                explanation.append(f"{c.name} has {c.status} open finding(s) that must be "
                                    f"remediated or explicitly suppressed with justification "
                                    f"before this counts as READY")
            else:
                explanation.append(f"{c.name} has {c.status} open finding(s), tracked but not "
                                    f"blocking readiness (below HIGH)")

    readiness = NOT_READY if blocking else READY
    if not blocking and not explanation:
        explanation.append("every required scanner is AVAILABLE, ran cleanly (or all findings are "
                            "explicitly suppressed with justification), and no CRITICAL/HIGH "
                            "finding is open")
    return SecurityPosture(categories=categories, readiness=readiness, explanation=explanation)
