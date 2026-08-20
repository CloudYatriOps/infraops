"""Phase 10 Wave 2 API test: `GET /intelligence/patterns` and
`GET /intelligence/health` must return the exact same data as calling
`detect_patterns()`/`compute_health_signals()` directly - thin wrappers,
no logic reimplemented. Real Postgres integration test, same conventions
as tests/test_api_prioritization.py."""
from __future__ import annotations

import os
import uuid

import pytest

from tests.db_pg_helper import local_postgres_available

os.environ.setdefault("AEP_PG_PASSWORD", "aep_local_dev_only")

pytestmark = pytest.mark.skipif(not local_postgres_available(),
                                 reason="local Postgres not reachable")


@pytest.fixture()
def dev_client(monkeypatch):
    monkeypatch.setenv("AEP_API_DEV_MODE", "1")
    from aep.api.app import create_app
    app = create_app()
    return app, app.test_client()


def _make_project(client, name):
    resp = client.post("/projects", json={"name": name, "repo_path": "/tmp"})
    assert resp.status_code == 201
    return resp.get_json()["id"]


def test_patterns_endpoint_matches_direct_call(dev_client):
    app, client = dev_client
    p1 = _make_project(client, f"pat-api-a-{uuid.uuid4().hex[:8]}")
    p2 = _make_project(client, f"pat-api-b-{uuid.uuid4().hex[:8]}")

    from aep.db.postgres import PostgresFindingRepository
    from aep.db.models import FindingRecord
    from aep.intelligence.incident_patterns import detect_patterns

    # A unique-per-run description guarantees this fingerprint cannot
    # collide with data left over from other tests sharing the same real
    # Postgres instance/full-suite run.
    unique_desc = f"api key committed to repo {uuid.uuid4().hex}"
    finding_repo = PostgresFindingRepository(app.config["AEP_POOL"])
    for pid in (p1, p2):
        finding_repo.save(FindingRecord(
            id=str(uuid.uuid4()), project_id=pid, category="secret", severity="critical",
            status="OPEN", description=unique_desc, evidence={"environment": "production"},
        ))

    resp = client.get("/intelligence/patterns")
    assert resp.status_code == 200
    payload = resp.get_json()

    direct = detect_patterns(finding_repo)
    direct_dicts = [d.to_dict() for d in direct]
    matching = [p for p in payload["patterns"] if {p1, p2} <= set(p["affected_project_ids"])]
    matching_direct = [p for p in direct_dicts if {p1, p2} <= set(p["affected_project_ids"])]
    assert matching and matching_direct
    assert matching[0]["fingerprint"] == matching_direct[0]["fingerprint"]
    assert matching[0]["occurrence_count"] == matching_direct[0]["occurrence_count"] == 2


def test_health_endpoint_scoped_by_project_id(dev_client):
    app, client = dev_client
    p1 = _make_project(client, f"health-api-{uuid.uuid4().hex[:8]}")

    from aep.db.postgres import PostgresFindingRepository
    from aep.db.models import FindingRecord

    finding_repo = PostgresFindingRepository(app.config["AEP_POOL"])
    finding_repo.save(FindingRecord(
        id=str(uuid.uuid4()), project_id=p1, category="iac", severity="critical",
        status="OPEN", description="old unresolved critical",
    ))

    resp = client.get(f"/intelligence/health?project_id={p1}")
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["count"] >= 1
    assert all(p1 in s["affected_projects"] for s in payload["signals"])
