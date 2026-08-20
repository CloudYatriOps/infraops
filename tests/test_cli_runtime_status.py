"""Phase 8 Part 9/12: `aep runtime-status` CLI (human + --json). Uses a
throwaway tmp_path StateStore, never the real repo's aep_state.db, and
never touches the progress/roadmap engine (this CLI surface is
operational status, not development progress - see runtime/status.py
module docstring) so there is no risk of the self-referential-roadmap
recursion `test_cli_status.py` guards against.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys


def _run(db_path, *args):
    # This file deliberately exercises the sqlite `StateStore` at a
    # throwaway tmp_path file (project id "clitest" is not a valid UUID,
    # so it cannot go through the Postgres facade anyway) - since Stage
    # A.5's default flip made Postgres the ambient default, that choice
    # must now be made explicit via AEP_DB_BACKEND rather than relying on
    # what used to be the implicit default.
    return subprocess.run(
        [sys.executable, "-m", "aep.cli", "--db", str(db_path), *args],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        env={"PYTHONPATH": "src", "PATH": "/usr/bin:/bin", "AEP_DB_BACKEND": "sqlite"},
        capture_output=True, text=True, timeout=60,
    )


def test_runtime_status_json_on_empty_db(tmp_path):
    db = tmp_path / "empty.db"
    result = _run(db, "runtime-status", "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["health"] == "STOPPED"  # no workers registered yet
    assert payload["workers"]["total"] == 0


def test_runtime_status_human_readable(tmp_path):
    db = tmp_path / "empty.db"
    result = _run(db, "runtime-status")
    assert result.returncode == 0, result.stderr
    assert "RUNTIME STATUS" in result.stdout
    assert "Health:" in result.stdout


def test_runtime_start_then_status_shows_registered_workers(tmp_path):
    db = tmp_path / "r.db"
    start = _run(db, "runtime-start", "--project", "clitest", "--repo", ".",
                 "--workers", "2", "--cycles", "1", "--interval", "5", "--json")
    assert start.returncode == 0, start.stderr
    payload = json.loads(start.stdout)
    assert payload["cycles_run"] == 1

    status = _run(db, "runtime-status", "--json")
    status_payload = json.loads(status.stdout)
    assert status_payload["workers"]["total"] == 2


def test_runtime_jobs_lists_registered_schedule(tmp_path):
    db = tmp_path / "r.db"
    _run(db, "runtime-start", "--project", "clitest", "--repo", ".", "--workers", "1",
         "--cycles", "1", "--interval", "5")
    jobs = _run(db, "runtime-jobs", "--json")
    assert jobs.returncode == 0, jobs.stderr
    payload = json.loads(jobs.stdout)
    assert len(payload) > 0
    assert all(j["project_id"] == "clitest" for j in payload)
