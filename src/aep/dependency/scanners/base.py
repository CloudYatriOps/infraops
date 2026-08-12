"""Scanner adapter shape (documentation only - Python doesn't need a
Protocol imported everywhere for two module-level functions to conform to
it). Every concrete scanner module below exposes exactly this surface:

    TOOL_NAME: str
    ecosystem: Ecosystem
    is_available(run_shell) -> bool
    scan(manifest, project_root, run_shell) -> ScanRecord

`run_shell` is always the same small wrapper the caller (DependencyCVEAgent)
builds around `ctx.tools.call("shell.run", ...)` - so every subprocess a
scanner runs is still routed through the existing capability-scoped,
audited shell tool. No scanner module calls `subprocess` directly. This is
the same swappable-adapter shape as `AIProvider` and `GitHubClient.transport`.
"""
from __future__ import annotations

from typing import Callable

RunShell = Callable[..., dict]
