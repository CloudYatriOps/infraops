"""Phase 10 Wave 9 API test: `GET /intelligence/cross-project` must call
the exact same `find_cross_project_insights()` used by `aep intelligence
cross-project` - thin wrapper, no logic reimplemented. Real Postgres
integration test, same conventions as tests/test_api_deployment_risk.py."""
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


def test_cross_project_endpoint_matches_direct_call(dev_client):
    app, client = dev_client
    p1 = _make_project(client, f"crossproj-api-{uuid.uuid4().hex[:8]}")
    p2 = _make_project(client, f"crossproj-api2-{uuid.uuid4().hex[:8]}")

    from aep.db.postgres import PostgresFindingRepository, PostgresMemoryRepository, PostgresProjectRepository
    from aep.db.models import FindingRecord
    from aep.intelligence.cross_project_learning import find_cross_project_insights

    finding_repo = PostgresFindingRepository(app.config["AEP_POOL"])
    desc = f"vulnerable package {uuid.uuid4().hex[:8]}"
    for pid in (p1, p2):
        finding_repo.save(FindingRecord(
            id=str(uuid.uuid4()), project_id=pid, category="dependency", severity="high",
            status="OPEN", description=desc,
        ))

    resp = client.get("/intelligence/cross-project")
    assert resp.status_code == 200
    payload = resp.get_json()

    project_repo = PostgresProjectRepository(app.config["AEP_POOL"])
    memory_repo = PostgresMemoryRepository(app.config["AEP_POOL"])
    direct = find_cross_project_insights(finding_repo, project_repo, memory_repo=memory_repo)
    direct_dicts = [d.to_dict() for d in direct]

    matches_payload = [i for i in payload["items"] if set(i["affected_project_ids"]) == {p1, p2}]
    matches_direct = [d for d in direct_dicts if set(d["affected_project_ids"]) == {p1, p2}]
    assert len(matches_payload) == len(matches_direct) == 1
    assert matches_payload[0]["fingerprint"] == matches_direct[0]["fingerprint"]
