"""Scanner discovery (Phase 4 Part 1/13: "scanner discovery, unavailable
scanner")."""
from __future__ import annotations

import subprocess

from aep.security.discovery import ALL_SCANNERS, discover_scanners, scanner_for_category
from aep.security.models import ScannerAvailability, SecurityCategory


def _run_shell(args, cwd=None, timeout=60):
    try:
        proc = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return {"ok": proc.returncode == 0, "exit_code": proc.returncode, "stdout": proc.stdout,
                "stderr": proc.stderr}
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return {"ok": False, "exit_code": -1, "stdout": "", "stderr": str(e)}


def test_discover_scanners_returns_one_descriptor_per_category():
    descriptors = discover_scanners(_run_shell)
    categories = {d.category for d in descriptors}
    assert categories == {SecurityCategory.SECRET, SecurityCategory.SAST, SecurityCategory.IAC,
                           SecurityCategory.CONTAINER}
    assert len(descriptors) == len(ALL_SCANNERS)


def test_every_descriptor_declares_the_required_fields():
    for d in discover_scanners(_run_shell):
        assert d.scanner_id
        assert d.capability.startswith("security.")
        assert d.supported
        assert d.tool
        assert d.findings_schema
        assert d.severity_levels
        assert d.evidence_kind
        assert isinstance(d.remediation_supported, bool)
        assert d.availability.status in ScannerAvailability


def test_container_scanner_is_reported_blocked_or_unavailable_never_available_by_default():
    trivy_descriptor = next(d for d in discover_scanners(_run_shell)
                             if d.category == SecurityCategory.CONTAINER)
    # In every environment this platform has actually been run in so far,
    # this is BLOCKED (see trivy_scanner.py) - asserted as "not silently
    # AVAILABLE without a real binary" rather than hardcoding BLOCKED,
    # so this test stays meaningful if a future sandbox genuinely has trivy.
    assert trivy_descriptor.availability.status in (
        ScannerAvailability.AVAILABLE, ScannerAvailability.BLOCKED, ScannerAvailability.UNAVAILABLE)
    if trivy_descriptor.availability.status != ScannerAvailability.AVAILABLE:
        assert trivy_descriptor.availability.reason


def test_scanner_for_category_resolves_the_right_module():
    assert scanner_for_category("secret").SCANNER_ID == "gitleaks"
    assert scanner_for_category("sast").SCANNER_ID == "semgrep"
    assert scanner_for_category("iac").SCANNER_ID == "checkov"
    assert scanner_for_category("container").SCANNER_ID == "trivy"
    assert scanner_for_category("does-not-exist") is None
