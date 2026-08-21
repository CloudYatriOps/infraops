"""Phase 10 Wave 11 API test: `GET /intelligence/ci-clusters` must call
the exact same `analyze_ci_clusters()` used by `aep intelligence ci` -
thin wrapper, no logic reimplemented. Only needs dev-mode Flask app, no
real Postgres data required since the result is always NOT_IMPLEMENTED,
but still needs the app/DB wiring to boot, same as other API tests."""
from __future__ import annotations

import os

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


def test_ci_clusters_endpoint_matches_direct_call(dev_client):
    app, client = dev_client
    from aep.intelligence.ci_clustering import analyze_ci_clusters

    resp = client.get("/intelligence/ci-clusters")
    assert resp.status_code == 200
    payload = resp.get_json()

    direct = analyze_ci_clusters().to_dict()
    assert payload["status"] == direct["status"] == "NOT_IMPLEMENTED"
    assert payload["reason"] == direct["reason"]
    assert payload["clusters"] == direct["clusters"] == []


def test_ci_clusters_endpoint_with_project_id(dev_client):
    app, client = dev_client
    resp = client.get("/intelligence/ci-clusters?project_id=p1")
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["status"] == "NOT_IMPLEMENTED"
