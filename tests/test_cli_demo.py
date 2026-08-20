"""Stage C: `aep providers`/`aep demo run`/`aep demo run --scenario
ambiguous`/`aep demo readiness`, exercised as real subprocess CLI
invocations (same pattern as tests/test_cli_skills.py)."""
from __future__ import annotations

import json
import os
import subprocess
import sys


def _run(*args, timeout=60):
    env = dict(os.environ)
    env["PYTHONPATH"] = "src"
    return subprocess.run(
        [sys.executable, "-m", "aep.cli", *args],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        env=env,
        capture_output=True, text=True, timeout=timeout,
    )


def test_providers_json_lists_fake_and_reports_omniroute_unavailable(monkeypatch):
    monkeypatch.delenv("AI_BASE_URL", raising=False)
    monkeypatch.delenv("AI_CREDENTIAL", raising=False)
    result = _run("providers", "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["default_provider_id"] == "fake"
    assert payload["omniroute"]["status"] == "unavailable"
    provider_ids = {p["provider_id"] for p in payload["providers"]}
    assert "fake" in provider_ids


def test_demo_readiness_prints_checklist_not_percentage():
    result = _run("demo", "readiness", timeout=120)
    assert result.returncode == 0, result.stderr
    assert "DEMO READINESS CHECKLIST" in result.stdout
    assert "%" not in result.stdout
    assert "READY" in result.stdout


def test_demo_run_ambiguous_refuses_and_asks_for_clarification():
    result = _run("demo", "run", "--scenario", "ambiguous")
    assert result.returncode == 0, result.stderr
    assert "REFUSED" in result.stdout
    assert "clarification" in result.stdout.lower()


def test_demo_run_happy_path_end_to_end(tmp_path):
    result = _run("demo", "run", "--work-dir", str(tmp_path), "--db-backend", "postgres",
                   timeout=120)
    assert result.returncode == 0, result.stderr
    assert "SUCCEEDED" in result.stdout
    assert "Security scan blocked on first pass (secret detected): True" in result.stdout
    assert "Security scan clean after fix: True" in result.stdout
