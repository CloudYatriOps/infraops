"""Container image scanning via Trivy - Phase 4 Part 1/7.

CONFIRMED BLOCKED in this sandbox via two independent, now-exhausted paths
(verified directly during Phase 4 investigation, not assumed):

1. No `trivy` (or `grype`) binary is installable: not present in apt's
   package index (`apt-cache search trivy` finds nothing), and Trivy's
   GitHub release binaries are unreachable (`github.com`/release
   downloads return 403 through this sandbox's egress proxy - the same
   block pattern documented for `api.github.com` in Phase 2 and
   `proxy.golang.org` in Phase 3).
2. A container *runtime* alone doesn't help: `dockerd` can genuinely be
   started in this sandbox (`docker info` reports a healthy Docker Engine
   29.4.3, overlayfs storage driver) - but Docker Hub itself is blocked at
   the registry layer. `docker pull hello-world` and
   `docker pull aquasec/trivy:latest` both fail identically with
   `Forbidden` on the `registry-1.docker.io` manifest HEAD request. With
   no image ever pullable, there is no way to run Trivy as a container
   either, and no base image to scan even if Trivy itself were present.

This is therefore reported as BLOCKED (an environment/network constraint),
not UNAVAILABLE (a local tooling gap installing the binary would fix) -
see `ScannerAvailability`'s docstring in `security/models.py` for that
distinction. `scan()` is never called in this state; per this package's
`scanners/base.py` contract it would refuse to fabricate a result if it
were.
"""
from __future__ import annotations

from datetime import datetime, timezone

from ..models import (
    AvailabilityResult, ScannerAvailability, ScannerDescriptor, SecurityCategory,
    SecurityScanRecord, SecuritySeverity,
)

SCANNER_ID = "trivy"
CATEGORY = SecurityCategory.CONTAINER
SUPPORTED = ["Dockerfile", "container images"]
TOOL_NAME = "trivy"
REMEDIATION_SUPPORTED = False  # base-image upgrades are never auto-applied - Part 7

_BLOCKED_REASON = (
    "trivy is not installed (no apt package, GitHub releases return 403 through this "
    "sandbox's egress proxy) AND Docker Hub itself is blocked at the registry layer even "
    "though the Docker daemon can be started locally (docker pull returns 403 Forbidden on "
    "registry-1.docker.io) - two independent paths exhausted, not a single missing binary."
)


def check_availability(run_shell) -> AvailabilityResult:
    result = run_shell(["trivy", "--version"], timeout=5)
    if result.get("ok"):
        return AvailabilityResult(ScannerAvailability.AVAILABLE, "trivy binary responds to --version")
    return AvailabilityResult(ScannerAvailability.BLOCKED, _BLOCKED_REASON)


def describe(run_shell) -> ScannerDescriptor:
    return ScannerDescriptor(
        scanner_id=SCANNER_ID, capability="security.container_scan", category=CATEGORY,
        supported=SUPPORTED, tool=TOOL_NAME, findings_schema="SecurityFinding (security/models.py)",
        severity_levels=[s.value for s in SecuritySeverity],
        evidence_kind="CVE id / Dockerfile lint rule", remediation_supported=REMEDIATION_SUPPORTED,
        availability=check_availability(run_shell),
    )


def scan(project_root: str, run_shell) -> SecurityScanRecord:
    availability = check_availability(run_shell)
    scanned_at = datetime.now(timezone.utc).isoformat()
    if availability.status != ScannerAvailability.AVAILABLE:
        return SecurityScanRecord(
            scanner=SCANNER_ID, scanner_version="unknown", category=CATEGORY, scanned_at=scanned_at,
            target=project_root, availability=availability.status, exit_code=0, finding_count=0,
            findings=[], note=availability.reason,
        )
    raise RuntimeError("trivy is not available in this environment; call check_availability() "
                        "before scan()")
