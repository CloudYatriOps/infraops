"""Allowlisted shell execution.

This is deliberately the most restricted tool in the registry (risk=HIGH):
only an explicit set of binaries can be invoked, arguments are passed as a
list (never a shell string, so no injection via `; rm -rf` style payloads),
and every call is time-boxed. Per ARCHITECTURE.md §16, this is what stops a
malicious repository's README/CI-config from getting arbitrary code
execution just because an agent read it.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

from ..models import RiskLevel
from ..tool_registry import Tool

ALLOWED_BINARIES = {
    "pytest", "python3", "git",
    # Phase 3: real dependency/CVE scanners, invoked the same audited,
    # allowlisted way as every other binary here - see
    # src/aep/dependency/scanners/ for what actually calls these.
    "pip-audit", "npm",
    # Phase 4: real security scanners (secret/SAST/IaC) - see
    # src/aep/security/scanners/ for what actually calls these. `trivy` is
    # deliberately NOT added: it is BLOCKED in this sandbox (see
    # security/scanners/trivy_scanner.py) and this platform never invokes
    # a binary it has already determined is unavailable.
    "gitleaks", "semgrep", "checkov",
}


def _handler(capability: str, **kwargs) -> dict:
    if capability != "shell.run":
        raise ValueError(f"unsupported capability for shell tool: {capability}")

    args: list[str] = kwargs["args"]
    cwd: str = kwargs["cwd"]
    timeout: int = kwargs.get("timeout", 60)

    if not args:
        raise ValueError("empty command")
    if args[0] not in ALLOWED_BINARIES:
        raise PermissionError(
            f"binary '{args[0]}' is not in the shell tool allowlist {sorted(ALLOWED_BINARIES)}"
        )

    # BUG-0012: allowlisted binaries like "pytest" are console scripts
    # installed into the CURRENT interpreter's own bin/Scripts directory.
    # That directory is only on PATH if the venv was `activate`d - a step
    # the installed-CLI workflow does not require. Resolve the allowlisted
    # name (still checked by name above, never widened) against PATH plus
    # the interpreter's own bin/Scripts dir, and exec the resolved absolute
    # path - `subprocess`'s own executable search on Windows only consults
    # the real process `os.environ`, not an `env=` override, so passing an
    # augmented `env` alone (without this) silently keeps failing.
    # "python3" must mean THE INTERPRETER RUNNING AEP, never whatever a
    # bare `python3` happens to hit on PATH. On Windows that name is
    # typically either absent or the WindowsApps stub - a different
    # interpreter with none of AEP's dependencies - so resolving it via
    # PATH silently runs pip/pytest against the wrong environment
    # (BUG-0019). Callers keep passing the logical name, so
    # ALLOWED_BINARIES' exact-name check above is unaffected.
    if args[0] == "python3":
        resolved = sys.executable
    else:
        search_path = os.path.dirname(sys.executable) + os.pathsep + os.environ.get("PATH", "")
        resolved = shutil.which(args[0], path=search_path) or args[0]
    exec_args = [resolved] + args[1:]

    proc = subprocess.run(exec_args, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return {
        "ok": proc.returncode == 0,
        "exit_code": proc.returncode,
        # Phase 3 bug fix: this was `[-8000:]`, tuned for pytest's terse
        # `-q` output. A real pip-audit/npm-audit `-f/--json` run against
        # even a small number of vulnerable packages produces JSON well
        # over 8000 characters (observed ~16KB scanning a single vulnerable
        # package during Phase 3 development) - tail-truncating a JSON
        # document corrupts it, and `json.loads` failing was silently
        # swallowed by the scanner's `except json.JSONDecodeError` fallback
        # to `{}`, making a real scan silently report "0 findings" on a
        # known-vulnerable fixture. Caught by a manual end-to-end run, not
        # a unit test (nothing exercised >8000 chars of stdout before
        # Phase 3). Raised rather than removed so log/DB growth from a
        # runaway command still has *some* bound.
        "stdout": proc.stdout[-200_000:],
        "stderr": proc.stderr[-20_000:],
        "args": args,
    }


def build_shell_tool() -> Tool:
    return Tool(
        name="shell",
        capabilities={"shell.run"},
        risk=RiskLevel.HIGH,
        description="Allowlisted command execution (pytest/python3/git only), no shell interpolation.",
        handler=_handler,
    )
