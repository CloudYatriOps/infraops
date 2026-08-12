"""Scanner discovery (Phase 4 Part 1 step "discover applicable scanners").

`ALL_SCANNERS` is the fixed, real set of adapters this platform ships -
one per category (secret/SAST/IaC/container), each conforming to
`scanners/base.py`'s contract. `discover_scanners()` calls every adapter's
`describe(run_shell)`, which itself calls `check_availability(run_shell)` -
so discovery is always a live check against the CURRENT environment, never
a cached/assumed capability list.
"""
from __future__ import annotations

from .models import ScannerDescriptor
from .scanners import checkov_scanner, gitleaks_scanner, semgrep_scanner, trivy_scanner

ALL_SCANNERS = (gitleaks_scanner, semgrep_scanner, checkov_scanner, trivy_scanner)


def discover_scanners(run_shell) -> list[ScannerDescriptor]:
    return [module.describe(run_shell) for module in ALL_SCANNERS]


def scanner_for_category(category: str):
    for module in ALL_SCANNERS:
        if module.CATEGORY.value == category:
            return module
    return None
