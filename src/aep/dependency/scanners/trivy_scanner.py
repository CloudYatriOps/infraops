"""Container image scanning via Trivy - SPECIFIED, NOT VERIFIED in this
sandbox: no `trivy`/`grype` binary is present, and no container runtime is
available to build/pull an image against here either. `is_available()`
returns False, so a discovered `Dockerfile` is recorded as "discovered, not
scanned" with an explicit reason - see govulncheck_scanner.py's docstring
for the identical rationale applied to Go.
"""
from __future__ import annotations

from ..models import DependencyManifest, Ecosystem, ScanRecord

TOOL_NAME = "trivy"
ecosystem = Ecosystem.CONTAINER


def is_available(run_shell) -> bool:
    result = run_shell(["trivy", "--version"], timeout=5)
    return bool(result.get("ok"))


def scan(manifest: DependencyManifest, project_root: str, run_shell) -> ScanRecord:
    raise RuntimeError(
        "trivy is not available in this environment; call is_available() before scan()"
    )
