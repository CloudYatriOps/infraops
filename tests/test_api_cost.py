"""Phase 10 Wave 5 API test: `GET /intelligence/cost` must call the exact
same `analyze_cost_intelligence()` used by `aep intelligence cost` - thin
wrapper, no logic reimplemented. Real Postgres integration test, same
conventions as tests/test_api_technical_debt.py."""
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


def test_cost_endpoint_matches_direct_call(dev_client):
    app, client = dev_client
    p1 = _make_project(client, f"cost-api-{uuid.uuid4().hex[:8]}")

    from aep.db.postgres import PostgresFindingRepository
    from aep.intelligence.cost_intelligence import analyze_cost_intelligence

    finding_repo = PostgresFindingRepository(app.config["AEP_POOL"])

    resp = client.get(f"/intelligence/cost?project_id={p1}")
    assert resp.status_code == 200
    payload = resp.get_json()

    direct = analyze_cost_intelligence(finding_repo, project_ids=[p1])
    assert [s["status"] for s in payload["signals"]] == [s.status for s in direct.signals]
    assert all(s["status"] == "BLOCKED" for s in payload["signals"])


def test_cost_endpoint_never_returns_a_dollar_figure(dev_client):
    app, client = dev_client
    p1 = _make_project(client, f"cost-api-nodollar-{uuid.uuid4().hex[:8]}")
    resp = client.get(f"/intelligence/cost?project_id={p1}")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "$" not in body
