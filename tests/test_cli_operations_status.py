"""`aep operations-status`/`aep incident-status`/`aep status --project`
(Phase 7 Part 11). Same "never self-reference the real roadmap" discipline
as tests/test_cli_status.py/test_cli_cicd_status.py - these tests never
call `_build_status_payload` against this repo's real roadmap.yaml."""
from __future__ import annotations

import json
import textwrap
from pathlib import Path

from aep.cli import _build_operations_payload, _build_status_payload
from aep.operations.memory import IncidentMemoryRecord, record_incident
from aep.state_store import StateStore


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
        """))
    return str(roadmap_path)


class _Args:
    def __init__(self, project, db, roadmap=None):
        self.project = project
        self.db = db
        self.json = True
        self.live_github_verified = False
        self.live_cve_feed_unverified = False


def test_build_operations_payload_is_json_serializable_and_counts_incidents(
        tmp_path: Path, monkeypatch):
    # Stage A.5's default flip made Postgres the ambient default; this test
    # exercises the CLI's status-payload code (which now goes through
    # `db/factory.py::build_state_store`) against a plain sqlite fixture
    # file (with non-UUID ids like "p1"), so it must explicitly opt into
    # sqlite rather than silently relying on the old default.
    monkeypatch.setenv("AEP_DB_BACKEND", "sqlite")
    db_path = str(tmp_path / "state.db")
    store = StateStore(db_path)
    record_incident(store, "p1", IncidentMemoryRecord(
        fingerprint="fp1", incident_id="i1", root_cause="BAD_DEPLOYMENT",
        confidence="HIGH_CONFIDENCE", remediation_used="rollback_nonprod",
        remediation_succeeded=True, environment="development",
    ))
    payload = _build_operations_payload("p1", db_path)
    json.dumps(payload)  # must not raise
    assert payload["incident_count"] == 1
    assert payload["incidents"][0]["fingerprint"] == "fp1"


def test_operations_payload_empty_for_unknown_project(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AEP_DB_BACKEND", "sqlite")
    db_path = str(tmp_path / "state.db")
    StateStore(db_path)
    payload = _build_operations_payload("no-such-project", db_path)
    assert payload["incident_count"] == 0


def test_status_payload_folds_in_operations_incident_count(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AEP_DB_BACKEND", "sqlite")
    roadmap_path = _small_roadmap(tmp_path)
    db_path = str(tmp_path / "state.db")
    store = StateStore(db_path)
    record_incident(store, "p1", IncidentMemoryRecord(
        fingerprint="fp1", incident_id="i1", root_cause="x", confidence="LIKELY",
        remediation_used="a", remediation_succeeded=True, environment="dev",
    ))
    args = _Args(project="p1", db=db_path)
    payload = _build_status_payload(args, repo_root=str(tmp_path), roadmap_path=roadmap_path)
    assert payload["operations"]["incident_count"] == 1


def test_status_payload_recurring_fingerprint_detection(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AEP_DB_BACKEND", "sqlite")
    roadmap_path = _small_roadmap(tmp_path)
    db_path = str(tmp_path / "state.db")
    store = StateStore(db_path)
    for i in range(2):
        record_incident(store, "p1", IncidentMemoryRecord(
            fingerprint="fp-recurring", incident_id=f"i{i}", root_cause="x", confidence="LIKELY",
            remediation_used="a", remediation_succeeded=False, environment="dev",
        ))
    args = _Args(project="p1", db=db_path)
    payload = _build_status_payload(args, repo_root=str(tmp_path), roadmap_path=roadmap_path)
    assert "fp-recurring" in payload["operations"]["recurring_fingerprints"]
