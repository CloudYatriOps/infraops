"""Phase 10 Wave 6 API test: `GET /intelligence/security-trends` must call
the exact same `analyze_security_trends()` used by `aep intelligence
security-trends` - thin wrapper, no logic reimplemented. Real Postgres
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


def test_security_trends_endpoint_matches_direct_call(dev_client):
    app, client = dev_client
    p1 = _make_project(client, f"sectrend-api-{uuid.uuid4().hex[:8]}")

    from aep.db.postgres import PostgresFindingRepository
    from aep.db.models import FindingRecord
    from aep.intelligence.security_trends import analyze_security_trends

    finding_repo = PostgresFindingRepository(app.config["AEP_POOL"])
    finding_repo.save(FindingRecord(
        id=str(uuid.uuid4()), project_id=p1, category="secret", severity="critical",
        status="OPEN", description=f"critical issue {uuid.uuid4().hex}",
    ))

    resp = client.get(f"/intelligence/security-trends?project_id={p1}")
    assert resp.status_code == 200
    payload = resp.get_json()

    direct = analyze_security_trends(finding_repo, project_ids=[p1])
    direct_dicts = [d.to_dict() for d in direct]

    assert payload["count"] == len(direct_dicts)
    assert [i["metric"] for i in payload["items"]] == [d["metric"] for d in direct_dicts]


def test_security_trends_endpoint_scoped_by_project_id(dev_client):
    app, client = dev_client
    p1 = _make_project(client, f"sectrend-api-scope-{uuid.uuid4().hex[:8]}")
    p2 = _make_project(client, f"sectrend-api-scope2-{uuid.uuid4().hex[:8]}")

    from aep.db.postgres import PostgresFindingRepository
    from aep.db.models import FindingRecord

    finding_repo = PostgresFindingRepository(app.config["AEP_POOL"])
    for pid in (p1, p2):
        finding_repo.save(FindingRecord(
            id=str(uuid.uuid4()), project_id=pid, category="secret", severity="high",
            status="OPEN", description=f"issue {uuid.uuid4().hex}",
        ))

    resp = client.get(f"/intelligence/security-trends?project_id={p1}")
    assert resp.status_code == 200
    payload = resp.get_json()
    assert all(item["project_id"] == p1 for item in payload["items"])
