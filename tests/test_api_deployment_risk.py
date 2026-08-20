"""Phase 10 Wave 7 API test: `GET /intelligence/dependency-risk` must call
the exact same `forecast_deployment_risk()` used by `aep intelligence
dependency-risk` - thin wrapper, no logic reimplemented. Real Postgres
integration test, same conventions as tests/test_api_risk_prediction.py."""
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


def test_dependency_risk_endpoint_matches_direct_call(dev_client):
    app, client = dev_client
    p1 = _make_project(client, f"deprisk-api-{uuid.uuid4().hex[:8]}")

    from aep.db.postgres import PostgresFindingRepository, PostgresProjectRepository
    from aep.db.models import FindingRecord
    from aep.deployment.evidence import list_deployment_evidence
    from aep.intelligence.deployment_risk import forecast_deployment_risk

    finding_repo = PostgresFindingRepository(app.config["AEP_POOL"])
    finding_repo.save(FindingRecord(
        id=str(uuid.uuid4()), project_id=p1, category="dependency", severity="high",
        status="OPEN", description=f"vulnerable dep {uuid.uuid4().hex}",
    ))

    resp = client.get(f"/intelligence/dependency-risk?project_id={p1}")
    assert resp.status_code == 200
    payload = resp.get_json()

    project_repo = PostgresProjectRepository(app.config["AEP_POOL"])
    store = app.config["AEP_STORE"]
    deployment_evidence_by_project = {p1: list_deployment_evidence(store, p1)}
    direct = forecast_deployment_risk(
        finding_repo, project_repo, project_ids=[p1],
        deployment_evidence_by_project=deployment_evidence_by_project,
    )
    direct_dicts = [d.to_dict() for d in direct]

    assert payload["count"] == len(direct_dicts)
    assert [i["risk_category"] for i in payload["items"]] == [d["risk_category"] for d in direct_dicts]


def test_dependency_risk_endpoint_scoped_by_project_id(dev_client):
    app, client = dev_client
    p1 = _make_project(client, f"deprisk-api-scope-{uuid.uuid4().hex[:8]}")
    p2 = _make_project(client, f"deprisk-api-scope2-{uuid.uuid4().hex[:8]}")

    from aep.db.postgres import PostgresFindingRepository
    from aep.db.models import FindingRecord

    finding_repo = PostgresFindingRepository(app.config["AEP_POOL"])
    for pid in (p1, p2):
        finding_repo.save(FindingRecord(
            id=str(uuid.uuid4()), project_id=pid, category="dependency", severity="high",
            status="OPEN", description=f"issue {uuid.uuid4().hex}",
        ))

    resp = client.get(f"/intelligence/dependency-risk?project_id={p1}")
    assert resp.status_code == 200
    payload = resp.get_json()
    assert all(item["project_id"] == p1 for item in payload["items"])
