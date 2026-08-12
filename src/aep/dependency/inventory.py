"""Builds a real dependency + vulnerability inventory for a project: runs
every scanner whose ecosystem has at least one discovered manifest AND
whose tool is actually available in this environment. A manifest whose
scanner isn't available is recorded as `unscanned` with an explicit reason
- never silently dropped, never fabricated as "clean" (Phase 3 Part I's
core honesty rule, same discipline Phase 2 applied to "real vs mocked
GitHub transport").
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .manifests import discover_manifests
from .models import DependencyManifest, Ecosystem, ScanRecord, VulnerabilityFinding
from .scanners import govulncheck_scanner, npm_audit_scanner, pip_audit_scanner, trivy_scanner

_SCANNERS = {
    Ecosystem.PYTHON: pip_audit_scanner,
    Ecosystem.NODE: npm_audit_scanner,
    Ecosystem.GO: govulncheck_scanner,
    Ecosystem.CONTAINER: trivy_scanner,
}


@dataclass
class InventoryResult:
    manifests: list[DependencyManifest]
    scan_records: list[ScanRecord] = field(default_factory=list)  # only ecosystems actually scanned
    unscanned: list[dict] = field(default_factory=list)  # [{manifest, ecosystem, reason}]

    @property
    def findings(self) -> list[VulnerabilityFinding]:
        out: list[VulnerabilityFinding] = []
        for record in self.scan_records:
            out.extend(record.findings)
        return out


def build_inventory(project_root: str, run_shell, manifest_filter=None) -> InventoryResult:
    """`manifest_filter(manifest) -> bool` lets a caller (e.g. a rescan step
    that only cares about manifests touched by a specific remediation)
    narrow which discovered manifests actually get scanned, without
    changing discovery itself."""
    manifests = discover_manifests(project_root)
    if manifest_filter is not None:
        manifests = [m for m in manifests if manifest_filter(m)]

    scan_records: list[ScanRecord] = []
    unscanned: list[dict] = []
    for manifest in manifests:
        scanner = _SCANNERS.get(manifest.ecosystem)
        if scanner is None:
            unscanned.append({"manifest": manifest.path, "ecosystem": manifest.ecosystem.value,
                               "reason": "no scanner implemented for this ecosystem"})
            continue
        if not scanner.is_available(run_shell):
            unscanned.append({"manifest": manifest.path, "ecosystem": manifest.ecosystem.value,
                               "reason": f"{scanner.TOOL_NAME} is not available in this environment"})
            continue
        scan_records.append(scanner.scan(manifest, project_root, run_shell))
    return InventoryResult(manifests=manifests, scan_records=scan_records, unscanned=unscanned)
