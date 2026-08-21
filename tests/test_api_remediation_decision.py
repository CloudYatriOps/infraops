"""Phase 10 Wave 10 API test: `GET /intelligence/remediation-decision`
must call the exact same `classify_remediation_batch()` used by
`aep intelligence remediation-decision` - thin wrapper, no logic
reimplemented, and NEVER executes anything (classification only)."""
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


def test_remediation_decision_endpoint_matches_direct_call(dev_client):
    app, client = dev_client
    p1 = _make_project(client, f"remdec-api-{uuid.uuid4().hex[:8]}")

    from aep.db.postgres import PostgresFindingRepository
    from aep.db.models import FindingRecord
    from aep.intelligence.predictive_remediation import classify_remediation_batch
    from aep.policy import PolicyEngine

    finding_repo = PostgresFindingRepository(app.config["AEP_POOL"])
    finding_repo.save(FindingRecord(
        id=str(uuid.uuid4()), project_id=p1, category="secret", severity="critical",
        description=f"leaked key {uuid.uuid4().hex}",
    ))

    resp = client.get(f"/intelligence/remediation-decision?project_id={p1}")
    assert resp.status_code == 200
    payload = resp.get_json()

    all_findings = [f for f in finding_repo.list(None, None) if f.project_id == p1]
    try:
        policy = PolicyEngine.from_yaml("src/aep/config/policy.yaml")
    except Exception:
        policy = None
    direct = classify_remediation_batch(all_findings, finding_repo, policy=policy)

    assert payload["count"] == len(direct)
    assert [i["decision"] for i in payload["items"]] == [d.decision for d in direct]


def test_remediation_decision_never_safe_for_first_critical(dev_client):
    app, client = dev_client
    p1 = _make_project(client, f"remdec-critical-{uuid.uuid4().hex[:8]}")
    from aep.db.postgres import PostgresFindingRepository
    from aep.db.models import FindingRecord

    finding_repo = PostgresFindingRepository(app.config["AEP_POOL"])
    finding_repo.save(FindingRecord(
        id=str(uuid.uuid4()), project_id=p1, category="secret", severity="critical",
        description=f"one-off leaked key {uuid.uuid4().hex}",
    ))
    resp = client.get(f"/intelligence/remediation-decision?project_id={p1}")
    payload = resp.get_json()
    assert all(item["decision"] != "SAFE_TO_AUTOMATE" for item in payload["items"])
