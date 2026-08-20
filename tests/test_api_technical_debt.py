"""Phase 10 Wave 8 API test: `GET /intelligence/technical-debt` must call
the exact same `analyze_technical_debt()` used by `aep intelligence
technical-debt` - thin wrapper, no logic reimplemented. Real Postgres
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


def test_technical_debt_endpoint_matches_direct_call(dev_client):
    app, client = dev_client
    p1 = _make_project(client, f"debt-api-{uuid.uuid4().hex[:8]}")

    from aep.db.postgres import PostgresFindingRepository, PostgresProjectRepository
    from aep.db.models import FindingRecord
    from aep.intelligence.technical_debt import analyze_technical_debt

    finding_repo = PostgresFindingRepository(app.config["AEP_POOL"])
    for i in range(2):
        finding_repo.save(FindingRecord(
            id=str(uuid.uuid4()), project_id=p1, category="secret", severity="medium",
            status="SUPPRESSED", description=f"suppressed {uuid.uuid4().hex}",
        ))

    resp = client.get(f"/intelligence/technical-debt?project_id={p1}")
    assert resp.status_code == 200
    payload = resp.get_json()

    project_repo = PostgresProjectRepository(app.config["AEP_POOL"])
    direct = analyze_technical_debt(finding_repo, project_repo, project_ids=[p1])
    direct_dicts = [d.to_dict() for d in direct]

    assert payload["count"] == len(direct_dicts)
    assert [i["debt_signal"] for i in payload["items"]] == [d["debt_signal"] for d in direct_dicts]


def test_technical_debt_endpoint_scoped_by_project_id(dev_client):
    app, client = dev_client
    p1 = _make_project(client, f"debt-api-scope-{uuid.uuid4().hex[:8]}")
    p2 = _make_project(client, f"debt-api-scope2-{uuid.uuid4().hex[:8]}")

    from aep.db.postgres import PostgresFindingRepository
    from aep.db.models import FindingRecord

    finding_repo = PostgresFindingRepository(app.config["AEP_POOL"])
    for pid in (p1, p2):
        for i in range(2):
            finding_repo.save(FindingRecord(
                id=str(uuid.uuid4()), project_id=pid, category="secret", severity="medium",
                status="SUPPRESSED", description=f"issue {uuid.uuid4().hex}",
            ))

    resp = client.get(f"/intelligence/technical-debt?project_id={p1}")
    assert resp.status_code == 200
    payload = resp.get_json()
    scoped = [item for item in payload["items"] if item["affected_project_id"] is not None]
    assert all(item["affected_project_id"] == p1 for item in scoped)
