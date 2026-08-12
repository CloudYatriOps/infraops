"""Runs the infrastructure scanner set (Phase 5).

Thin wrapper over Phase 4's `security/scan_runner.py::run_security_scan`
- it exists only to name the scanner set, NOT to reimplement scanning.
`run_infrastructure_scan()` deliberately includes Phase 4's own scanners
too: a Terraform repo's `checkov` (IaC) and `gitleaks` (secret) results
are part of its infrastructure security picture, and re-running them here
means the infra agent sees one consistent finding set rather than two
partial ones.
"""
from __future__ import annotations

from ..security.discovery import ALL_SCANNERS
from ..security.scan_runner import SecurityScanResult, run_security_scan
from .scanners import INFRA_SCANNERS

# Phase 4's four + Phase 5's three. Order matters only for display.
ALL_INFRA_AWARE_SCANNERS = ALL_SCANNERS + INFRA_SCANNERS


def run_infrastructure_scan(project_root: str, run_shell,
                             categories: list[str] | None = None,
                             include_phase4_scanners: bool = True) -> SecurityScanResult:
    scanners = ALL_INFRA_AWARE_SCANNERS if include_phase4_scanners else INFRA_SCANNERS
    return run_security_scan(project_root, run_shell, categories=categories, scanners=scanners)
