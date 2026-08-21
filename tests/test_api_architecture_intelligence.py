"""Phase 10 Wave 4 API test: `GET /intelligence/architecture` must call
the exact same `analyze_architecture()` used by `aep intelligence
architecture` - thin wrapper, no logic reimplemented. Real Postgres
integration test, same conventions as tests/test_api_risk_prediction.py."""
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


def test_architecture_endpoint_matches_direct_call(dev_client):
    app, client = dev_client
    p1 = _make_project(client, f"arch-api-{uuid.uuid4().hex[:8]}")

    from aep.db.postgres import PostgresFindingRepository, PostgresProjectRepository
    from aep.db.models import FindingRecord
    from aep.intelligence.architecture import analyze_architecture

    finding_repo = PostgresFindingRepository(app.config["AEP_POOL"])
    resource = f"src/module_{uuid.uuid4().hex[:6]}.py"
    for i in range(3):
        finding_repo.save(FindingRecord(
            id=str(uuid.uuid4()), project_id=p1, category="iac", severity="medium",
            status="OPEN", resource=resource, description=f"issue {uuid.uuid4().hex}",
        ))

    resp = client.get(f"/intelligence/architecture?project_id={p1}")
    assert resp.status_code == 200
    payload = resp.get_json()

    project_repo = PostgresProjectRepository(app.config["AEP_POOL"])
    direct = analyze_architecture(finding_repo, project_repo, project_ids=[p1])
    direct_dicts = [d.to_dict() for d in direct]

    assert payload["count"] == len(direct_dicts)
    assert [i["risk_id"] for i in payload["items"]] == [d["risk_id"] for d in direct_dicts]
    assert any(i["risk_id"] == "RESOURCE_HOTSPOT" for i in payload["items"])


def test_architecture_endpoint_scoped_by_project_id(dev_client):
    app, client = dev_client
    p1 = _make_project(client, f"arch-api-scope-{uuid.uuid4().hex[:8]}")
    p2 = _make_project(client, f"arch-api-scope2-{uuid.uuid4().hex[:8]}")

    from aep.db.postgres import PostgresFindingRepository
    from aep.db.models import FindingRecord

    finding_repo = PostgresFindingRepository(app.config["AEP_POOL"])
    resource = f"src/module_{uuid.uuid4().hex[:6]}.py"
    for pid in (p1, p2):
        for i in range(3):
            finding_repo.save(FindingRecord(
                id=str(uuid.uuid4()), project_id=pid, category="iac", severity="medium",
                status="OPEN", resource=resource, description=f"issue {uuid.uuid4().hex}",
            ))

    resp = client.get(f"/intelligence/architecture?project_id={p1}")
    assert resp.status_code == 200
    payload = resp.get_json()
    assert all(item["affected_project_ids"] == [p1] for item in payload["items"])
