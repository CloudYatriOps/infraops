"""Scanner adapter shape (Phase 4 Part 1 - documentation, mirrors
`dependency/scanners/base.py`'s pattern). Every concrete scanner module in
this package exposes exactly this surface:

    SCANNER_ID: str
    CATEGORY: SecurityCategory
    SUPPORTED: list[str]      # languages/file globs this scanner covers
    TOOL_NAME: str            # the real binary invoked
    REMEDIATION_SUPPORTED: bool
    check_availability(run_shell) -> AvailabilityResult
    describe(run_shell) -> ScannerDescriptor
    scan(project_root, run_shell) -> SecurityScanRecord

`run_shell` is always the same small wrapper the caller (`SecurityAgent`,
or a test) builds around `ctx.tools.call("shell.run", ...)` - every
subprocess a scanner runs is routed through the existing capability-scoped,
audited shell tool. No scanner module here calls `subprocess` directly.
This is the same swappable-adapter shape as `AIProvider`,
`GitHubClient.transport`, and Phase 3's `dependency/scanners/*`.

"Do not fake scanner output when a tool is unavailable" (Part 1) is
enforced structurally: `scan()` must check availability itself and return
a `SecurityScanRecord` with `availability != AVAILABLE` and
`finding_count=0` rather than inventing findings - it must never raise to
signal unavailability from `scan()` (callers are expected to check
`check_availability()` first, exactly like Phase 3's `is_available()`
convention, but `scan()` re-checks defensively so a caller mistake fails
honestly instead of fabricating a clean scan).
"""
from __future__ import annotations

from typing import Callable

RunShell = Callable[..., dict]
