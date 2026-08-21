"""CLI UX additions: curated top-level help, and the `security`/`infra`
positional-path aliases.

The behaviour worth pinning: `security`/`infra` must route through the
NEW capability-routed `aep scan` engine (builtin scanners, honest
SKIPPED/UNAVAILABLE/BLOCKED), never through the older `security-status`/
`infra-status` machinery that requires gitleaks/semgrep/checkov binaries
and tells the user to install them - reintroducing that under a
friendlier name would defeat the point of adding it. Every pre-existing
subcommand must keep working unchanged (backward compatibility is the
explicit requirement).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _run(*args, timeout=60):
    import os
    env = {**os.environ, "PYTHONPATH": "src"}
    return subprocess.run(
        [sys.executable, "-m", "aep.cli", *args],
        cwd=str(REPO_ROOT), env=env,
        capture_output=True, text=True, timeout=timeout,
    )


def test_bare_help_is_curated_and_short():
    result = _run("--help")
    assert result.returncode == 0
    assert "AEP - Autonomous Engineering Platform" in result.stdout
    assert "aep scan <path>" in result.stdout
    # Curated, not argparse's full alphabetical dump of every subcommand.
    assert len(result.stdout.splitlines()) < 40


def test_every_preexisting_subcommand_help_is_unaffected(tmp_path):
    """The curated help intercept must only fire for the BARE `--help` -
    `aep <command> --help` must still show that command's real, full,
    argparse-generated help exactly as before."""
    for command in ("tasks", "status", "security-status", "infra-status",
                     "demo", "skills"):
        result = _run(command, "--help")
        assert result.returncode == 0, command
        assert f"usage: aep {command}" in result.stdout, command


def test_security_alias_uses_capability_routed_scan_not_the_old_path(tmp_path):
    (tmp_path / "app.py").write_text("def f():\n    return 1\n")
    result = _run("security", str(tmp_path), "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    names = {a["analyzer"] for a in payload["analyzers"]}
    # These are aep.scan's analyzer names; the old security-status payload
    # shape has no "analyzer"/"SKIPPED" concept at all.
    assert "Secrets" in names
    assert "IaC" in names
    iac = next(a for a in payload["analyzers"] if a["analyzer"] == "IaC")
    assert iac["status"] == "SKIPPED", "a plain Python dir has no IaC to scan"


def test_infra_alias_uses_capability_routed_scan_not_the_old_path(tmp_path):
    (tmp_path / "main.tf").write_text('provider "aws" {}\n')
    result = _run("infra", str(tmp_path), "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    iac = next(a for a in payload["analyzers"] if a["analyzer"] == "IaC")
    # Must have actually run (not UNAVAILABLE for lack of checkov) since
    # the native Terraform scanner covers this without any external tool.
    assert iac["status"] in ("PASS", "FAIL"), iac
