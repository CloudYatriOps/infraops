"""Phase 10 Wave 1 API test: `GET /intelligence/prioritization` must return
the exact same ranking as calling `rank_findings()` directly - the
handler is a thin wrapper, not a second ranking implementation. Real
Postgres integration test, same conventions as tests/test_api_app.py."""
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


def test_prioritization_endpoint_matches_direct_call(dev_client):
    app, client = dev_client
    project_id = _make_project(client, f"prio-api-{uuid.uuid4().hex[:8]}")

    from aep.db.postgres import PostgresFindingRepository, PostgresProjectRepository
    from aep.db.models import FindingRecord

    repo = PostgresFindingRepository(app.config["AEP_POOL"])
    repo.save(FindingRecord(
        id=str(uuid.uuid4()), project_id=project_id, category="secret",
        severity="critical", status="OPEN", resource="repo/secret.txt",
        description="test finding", evidence={"environment": "production"},
    ))
    repo.save(FindingRecord(
        id=str(uuid.uuid4()), project_id=project_id, category="sast",
        severity="low", status="OPEN", resource="scripts/x.py",
        description="test finding 2",
    ))

    resp = client.get(f"/intelligence/prioritization?project_id={project_id}")
    assert resp.status_code == 200
    api_payload = resp.get_json()

    from aep.intelligence.prioritization import prioritized_finding_to_dict, rank_findings
    project_repo = PostgresProjectRepository(app.config["AEP_POOL"])
    direct = rank_findings(repo, project_repo, project_ids=[project_id])
    direct_payload = {"count": len(direct), "items": [prioritized_finding_to_dict(r) for r in direct]}

    # Ages are computed independently a few milliseconds apart by the two
    # calls, so scores can differ by a sub-microsecond epsilon - compare
    # with a tolerance instead of exact equality, everything else exact.
    assert api_payload["count"] == direct_payload["count"] == 2
    for api_item, direct_item in zip(api_payload["items"], direct_payload["items"]):
        assert api_item["finding_id"] == direct_item["finding_id"]
        assert api_item["rank"] == direct_item["rank"]
        assert api_item["score"] == pytest.approx(direct_item["score"], abs=1e-6)
    assert api_payload["items"][0]["severity"] == "critical"


def test_prioritization_endpoint_scoped_key_pinned_to_own_project(dev_client):
    app, client = dev_client
    project_a = _make_project(client, f"prio-a-{uuid.uuid4().hex[:8]}")
    project_b = _make_project(client, f"prio-b-{uuid.uuid4().hex[:8]}")

    from aep.api import auth
    from aep.db.postgres import PostgresFindingRepository
    from aep.db.models import FindingRecord

    repo = PostgresFindingRepository(app.config["AEP_POOL"])
    repo.save(FindingRecord(id=str(uuid.uuid4()), project_id=project_b, category="secret",
                             severity="high", status="OPEN", description="b finding"))

    dev_mode = os.environ.pop("AEP_API_DEV_MODE", None)
    try:
        _key_id, raw_key = auth.issue_key(app.config["AEP_POOL"], label="scoped-prio",
                                           project_scope=project_a)
        headers = {"Authorization": f"Bearer {raw_key}"}
        resp = client.get("/intelligence/prioritization", headers=headers)
        assert resp.status_code == 200
        assert resp.get_json()["count"] == 0

        resp = client.get(f"/intelligence/prioritization?project_id={project_b}", headers=headers)
        assert resp.status_code == 403
    finally:
        if dev_mode is not None:
            os.environ["AEP_API_DEV_MODE"] = dev_mode
