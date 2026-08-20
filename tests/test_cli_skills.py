"""Stage B Part 20: `aep skills list/show/versions/validate/project`,
following the exact `_build_X_payload`/`_print_X_human` + `--json` pattern
`test_cli_runtime_status.py` establishes. Uses `--backend fake` so these
tests have zero network/Postgres dependency and never touch the real
`aep_platform` database's skill rows."""
from __future__ import annotations

import json
import subprocess
import sys


def _run(*args):
    return subprocess.run(
        [sys.executable, "-m", "aep.cli", *args],
        cwd="/home/claude/aep-platform",
        env={"PYTHONPATH": "src", "PATH": "/usr/bin:/bin"},
        capture_output=True, text=True, timeout=60,
    )


def test_skills_list_json_with_seed():
    result = _run("skills", "list", "--backend", "fake", "--seed", "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    ids = {s["skill_id"] for s in payload["skills"]}
    assert ids == {
        "security", "sast", "dependency-cve", "secrets", "terraform", "kubernetes", "helm",
        "cicd", "deployment", "incident-response", "database", "postgresql", "git", "github",
        "architecture-review", "code-review", "testing", "cost-optimization",
    }
    for s in payload["skills"]:
        assert s["latest_published_version"] == "1.0.0"


def test_skills_list_human_readable():
    result = _run("skills", "list", "--backend", "fake", "--seed")
    assert result.returncode == 0, result.stderr
    assert "security" in result.stdout
    assert "latest=1.0.0" in result.stdout


def test_skills_show_json():
    result = _run("skills", "show", "security", "--backend", "fake", "--seed", "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["skill_id"] == "security"
    assert payload["lifecycle_state"] == "published"
    assert "gitleaks" in payload["required_checks"]
    assert payload["dependency_resolution"]["ok"] is True


def test_skills_versions_json():
    result = _run("skills", "versions", "security", "--backend", "fake", "--seed", "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["skill_id"] == "security"
    assert payload["versions"] == [{"version": "1.0.0", "lifecycle_state": "published"}]


def test_skills_validate_json_reports_clean():
    result = _run("skills", "validate", "--backend", "fake", "--seed", "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["clean"] is True
    assert payload["problems"] == {}


def test_skills_project_json_is_deterministic_projection():
    result1 = _run("skills", "project", "security", "--backend", "fake", "--seed", "--json")
    result2 = _run("skills", "project", "security", "--backend", "fake", "--seed", "--json")
    assert result1.returncode == 0, result1.stderr
    payload1 = json.loads(result1.stdout)
    payload2 = json.loads(result2.stdout)
    assert payload1 == payload2  # two independent processes, identical projection
    assert payload1["canonical_skill_id"] == "security"
    assert payload1["canonical_version"] == "1.0.0"


def test_skills_project_markdown():
    result = _run("skills", "project", "security", "--backend", "fake", "--seed", "--markdown")
    assert result.returncode == 0, result.stderr
    assert "canonical_skill_id: security" in result.stdout
    assert "# security (v1.0.0)" in result.stdout


def test_skills_show_missing_skill_fails_loudly():
    result = _run("skills", "show", "not-a-real-skill", "--backend", "fake", "--json")
    assert result.returncode != 0
