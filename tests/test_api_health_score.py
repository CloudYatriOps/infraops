"""Phase 10 Wave 12 API test: `GET /intelligence/health-score` must call
the exact same `compute_engineering_health()` used by `aep intelligence
health-score` - thin wrapper, no logic reimplemented. Distinct from Wave
2's `/intelligence/patterns`-style output (discrete signal states); this
is the per-project aggregate summary."""
from __future__ import annotations

import os
import uuid

import pytest

from tests.db_pg_helper import local_postgres_available

# (AEP_PG_PASSWORD no longer set here: setting any AEP_PG_* var opts OUT
# of AEP's zero-config embedded local PostgreSQL - see tests/conftest.py.)

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


def test_health_score_endpoint_matches_direct_call(dev_client):
    app, client = dev_client
    p1 = _make_project(client, f"health-api-{uuid.uuid4().hex[:8]}")

    from aep.db.postgres import PostgresFindingRepository, PostgresProjectRepository
    from aep.db.models import FindingRecord
    from aep.intelligence.engineering_health_score import compute_engineering_health

    finding_repo = PostgresFindingRepository(app.config["AEP_POOL"])
    finding_repo.save(FindingRecord(
        id=str(uuid.uuid4()), project_id=p1, category="secret", severity="medium",
        description=f"issue {uuid.uuid4().hex}",
    ))

    resp = client.get(f"/intelligence/health-score?project_id={p1}")
    assert resp.status_code == 200
    payload = resp.get_json()

    project_repo = PostgresProjectRepository(app.config["AEP_POOL"])
    direct = compute_engineering_health(finding_repo, project_repo, project_ids=[p1])

    assert payload["count"] == len(direct)
    assert [i["overall_state"] for i in payload["items"]] == [d.overall_state for d in direct]
