"""`aep status --json` structure (Phase 3 Part F): overall percentage,
phases, capabilities, tests, blockers, deployability, and (when --project
is given) task/evidence state.

Uses a small, temporary roadmap fixture (like test_progress_engine.py)
rather than this repo's real config/roadmap.yaml. This is deliberate, not
just for speed: if this test file both (a) is itself listed as a gating
test for a roadmap capability (`platform.status_cli`) AND (b) called
`_build_status_payload` against the REAL roadmap, every `aep status`
invocation would recursively spawn a full nested test run of itself inside
itself - caught during Phase 3 development as a real hang/timeout, not a
theoretical concern. `_build_status_payload`'s `repo_root`/`roadmap_path`
params exist specifically so this file can exercise the exact same code
path the CLI uses without that self-reference.
"""
from __future__ import annotations

import json
import textwrap
from pathlib import Path

from aep.cli import _build_status_payload


class _Args:
    def __init__(self, project=None, live_github_verified=False, live_cve_feed_unverified=False,
                 db="aep_state_test.db"):
        self.project = project
        self.live_github_verified = live_github_verified
        self.live_cve_feed_unverified = live_cve_feed_unverified
        self.db = db
        self.json = True


def _small_roadmap(tmp_path: Path) -> str:
    (tmp_path / "test_a.py").write_text("def test_ok():\n    assert True\n")
    roadmap_path = tmp_path / "roadmap.yaml"
    roadmap_path.write_text(textwrap.dedent("""\
        version: 1
        phases:
          - id: 1
            name: "P1"
            description: "d"
            capabilities:
              - id: cap.a
                description: "done"
                test_paths: ["test_a.py"]
          - id: 2
            name: "P2"
            description: "d"
            capabilities:
              - id: cap.b
                description: "not started"
                test_paths: []
        """))
    return str(roadmap_path)


def test_json_status_payload_has_required_top_level_keys(tmp_path):
    roadmap_path = _small_roadmap(tmp_path)
    payload = _build_status_payload(_Args(), repo_root=str(tmp_path), roadmap_path=roadmap_path)

    assert json.dumps(payload)  # fully JSON-serializable
    for key in ("overall_percent", "tests", "phases", "deployability"):
        assert key in payload
    assert isinstance(payload["overall_percent"], (int, float))
    assert isinstance(payload["phases"], list)
    assert len(payload["phases"]) == 2
    assert "level" in payload["deployability"]
    assert "blockers" in payload["deployability"]


def test_json_status_phase_entries_have_capability_detail(tmp_path):
    roadmap_path = _small_roadmap(tmp_path)
    payload = _build_status_payload(_Args(), repo_root=str(tmp_path), roadmap_path=roadmap_path)

    phase1 = next(p for p in payload["phases"] if p["id"] == 1)
    assert phase1["status"] == "COMPLETE"
    assert phase1["percent"] == 100.0
    assert len(phase1["capabilities"]) == 1
    for cap in phase1["capabilities"]:
        assert cap["status"] in ("COMPLETE", "IN_PROGRESS", "PENDING", "BLOCKED")

    phase2 = next(p for p in payload["phases"] if p["id"] == 2)
    assert phase2["status"] == "NOT_STARTED"
    assert phase2["percent"] == 0.0


def test_json_status_reflects_real_test_counts(tmp_path):
    roadmap_path = _small_roadmap(tmp_path)
    payload = _build_status_payload(_Args(), repo_root=str(tmp_path), roadmap_path=roadmap_path)
    assert payload["tests"]["passed"] == 1
    assert payload["tests"]["failed"] == 0


def test_json_status_with_project_includes_task_snapshot(tmp_path, monkeypatch):
    from aep.bootstrap import build_orchestrator
    from aep.models import ProjectConfig

    # `_build_status_payload` below reads through `db/factory.py` too, so
    # it must be told explicitly to use the same sqlite backend the
    # orchestrator above was built with (project id "clitest" is not a
    # valid UUID, so it cannot go through the Postgres facade).
    monkeypatch.setenv("AEP_DB_BACKEND", "sqlite")
    roadmap_path = _small_roadmap(tmp_path)
    project = ProjectConfig(id="clitest", name="clitest", repo_path=str(tmp_path),
                             policy_path="config/policy.yaml")
    db_path = str(tmp_path / "cli_state.db")
    orch = build_orchestrator(db_path=db_path, project=project, db_backend="sqlite")
    orch.plan_fix_bug(project_id="clitest", project_root=str(tmp_path),
                       target_file="app.py", bug_description="n/a")

    payload = _build_status_payload(_Args(project="clitest", db=db_path), repo_root=str(tmp_path),
                                     roadmap_path=roadmap_path)
    assert "tasks" in payload
    assert "by_status" in payload["tasks"]
    assert sum(payload["tasks"]["by_status"].values()) == 4  # recon/code_fix/security_scan/run_tests


# Deliberately NO test here calls `_build_status_payload()` against the
# REAL repo roadmap (i.e. with no `repo_root`/`roadmap_path` override): this
# file is itself one of `config/roadmap.yaml`'s gating tests
# (`platform.status_cli`), so doing so would make every `aep status`
# invocation recursively spawn another full nested test run of itself -
# see this module's docstring. `aep status`/`aep progress` are exercised
# manually end-to-end instead (see ARCHITECTURE.md's Phase 3 addendum).
