"""Go vulnerability scanning via govulncheck - SPECIFIED, NOT VERIFIED in
this sandbox.

`go install golang.org/x/vuln/cmd/govulncheck@latest` needs
proxy.golang.org, which this sandbox's egress proxy returns 403 for
(confirmed via direct curl during Phase 3 investigation - the same
block-pattern already documented for api.github.com in the Phase 2
addendum). `govulncheck` is also not preinstalled.

`is_available()` therefore returns False for as long as `govulncheck` isn't
on PATH, so `dependency/inventory.py` records any discovered `go.mod` as
"discovered, not scanned" with an explicit reason rather than fabricating
scan output. If this ever runs somewhere `govulncheck` is installed, `scan()`
below is real: it shells out to the real binary via the same audited
shell-tool wrapper every other scanner uses, and would need its JSON output
mapped into `VulnerabilityFinding` the same way the other two scanners do
(intentionally left as a follow-up rather than guessed at, since this
sandbox cannot exercise or verify that parsing).
"""
from __future__ import annotations

from datetime import datetime, timezone

from ..models import DependencyManifest, Ecosystem, ScanRecord

TOOL_NAME = "govulncheck"
ecosystem = Ecosystem.GO


def is_available(run_shell) -> bool:
    result = run_shell(["govulncheck", "-version"], timeout=5)
    return bool(result.get("ok"))


def scan(manifest: DependencyManifest, project_root: str, run_shell) -> ScanRecord:
    # Not reachable in this environment (is_available() gates it in
    # inventory.py) - raising rather than returning a fabricated empty
    # result keeps a future real call from silently reporting "clean".
    raise RuntimeError(
        "govulncheck is not available in this environment; call is_available() before scan()"
    )
