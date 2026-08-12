"""Runs every applicable scanner against a project and returns normalized
records/findings (Phase 4 Part 1/2/3 steps 1-4: discover, scan, normalize).

Deliberately a plain function, not a method on `SecurityAgent` - exactly
the relationship `dependency/inventory.py::build_inventory` has to
`DependencyCVEAgent`. This keeps the scan logic directly unit-testable
(and reusable from the CLI for a security-posture check) without needing a
Task/Orchestrator in the loop.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .discovery import ALL_SCANNERS
from .models import SecurityFinding, SecurityScanRecord


@dataclass
class SecurityScanResult:
    records: list[SecurityScanRecord] = field(default_factory=list)

    @property
    def findings(self) -> list[SecurityFinding]:
        return [f for r in self.records for f in r.findings]

    def record_for(self, category: str) -> SecurityScanRecord | None:
        return next((r for r in self.records if r.category.value == category), None)


def run_security_scan(project_root: str, run_shell, categories: list[str] | None = None,
                       scanners=None) -> SecurityScanResult:
    """Runs every scanner in `scanners` (default: `ALL_SCANNERS`, i.e. every
    real adapter this platform ships) against `project_root`. A scanner
    whose category isn't in `categories` (when given) is skipped entirely -
    not run and not reported - which is different from a scanner that runs
    but is UNAVAILABLE/BLOCKED; callers that need "every category, honestly
    reported" should leave `categories=None`."""
    scanners = scanners if scanners is not None else ALL_SCANNERS
    records: list[SecurityScanRecord] = []
    for module in scanners:
        if categories is not None and module.CATEGORY.value not in categories:
            continue
        records.append(module.scan(project_root, run_shell))
    return SecurityScanResult(records=records)
