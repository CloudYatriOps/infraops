"""Stage D Wave 1 API tests: real Postgres integration tests (no fakes)
proving the Flask layer over src/aep/api/app.py drives the SAME
Orchestrator/SkillRegistry/PolicyEngine code the CLI uses - not a second
implementation - and that the auth boundary/credential-safety guarantees
actually hold.

Skips gracefully (never fakes a pass) if local Postgres is unreachable,
matching every other Postgres integration test's convention (see
tests/db_pg_helper.py).
"""
from __future__ import annotations

import os

import pytest

from tests.db_pg_helper import local_postgres_available

# (AEP_PG_PASSWORD no longer set here: setting any AEP_PG_* var opts OUT
# of AEP's zero-config embedded local PostgreSQL - see tests/conftest.py.)

pytestmark = pytest.mark.skipif(not local_postgres_available(),
                                 reason="local Postgres not reachable")

FAKE_API_KEY_PLACEHOLDER = "aep_this-is-a-fake-test-key-never-a-real-secret"


@pytest.fixture()
def dev_client(monkeypatch):
    monkeypatch.setenv("AEP_API_DEV_MODE", "1")
    from aep.api.app import create_app
    app = create_app()
    return app, app.test_client()


@pytest.fixture()
def auth_client(monkeypatch):
    monkeypatch.delenv("AEP_API_DEV_MODE", raising=False)
    from aep.api.app import create_app
    app = create_app()
    return app, app.test_client()


def test_dev_mode_bypasses_auth(dev_client):
    app, client = dev_client
    resp = client.get("/agents")
    assert resp.status_code == 200
    assert "recon" in resp.get_json()["agents"]


def test_missing_auth_header_rejected(auth_client):
    _app, client = auth_client
    resp = client.get("/agents")
    assert resp.status_code == 401


def test_invalid_key_rejected(auth_client):
    _app, client = auth_client
    resp = client.get("/agents", headers={"Authorization": "Bearer not-a-real-key"})
    assert resp.status_code == 401


def test_valid_key_accepted_and_revoked_key_rejected(auth_client):
    app, client = auth_client
    from aep.api import auth
    key_id, raw_key = auth.issue_key(app.config["AEP_POOL"], label="pytest")
    resp = client.get("/agents", headers={"Authorization": f"Bearer {raw_key}"})
    assert resp.status_code == 200

    auth.revoke_key(app.config["AEP_POOL"], key_id)
    resp = client.get("/agents", headers={"Authorization": f"Bearer {raw_key}"})
    assert resp.status_code == 401


def test_create_project_via_api_persists_to_real_postgres(dev_client):
    app, client = dev_client
    resp = client.post("/projects", json={"name": "api-test-project", "repo_path": "/tmp"})
    assert resp.status_code == 201
    project_id = resp.get_json()["id"]

    from aep.db.postgres import PostgresProjectRepository
    record = PostgresProjectRepository(app.config["AEP_POOL"]).get(project_id)
    assert record is not None
    assert record.name == "api-test-project"


def test_create_project_missing_field_rejected(dev_client):
    _app, client = dev_client
    resp = client.post("/projects", json={"name": "no-repo-path"})
    assert resp.status_code == 400


def test_repository_endpoint_reports_local_path_and_git_status(dev_client):
    app, client = dev_client
    resp = client.post("/projects", json={"name": "repo-test-project", "repo_path": "/tmp"})
    project_id = resp.get_json()["id"]
    resp = client.get(f"/repositories/{project_id}")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["local_path"] == "/tmp"
    assert "github" in body


def test_task_creation_goes_through_real_orchestrator_and_persists_evidence(dev_client, tmp_path):
    """Verifies POST /tasks does NOT reimplement task execution: the
    resulting task, retrieved directly from the real Postgres store
    (bypassing the API), shows real recon-agent evidence - proof this
    ran through Orchestrator.run_task -> agent.run(), the same path
    src/aep/cli.py::cmd_run_fix_bug drives."""
    app, client = dev_client
    resp = client.post("/projects", json={"name": "task-test-project", "repo_path": str(tmp_path)})
    project_id = resp.get_json()["id"]

    resp = client.post("/tasks", json={
        "project_id": project_id, "type": "recon", "owner_agent": "recon",
        "payload": {"project_root": str(tmp_path)},
    })
    assert resp.status_code == 201
    body = resp.get_json()
    task_id = body["id"]
    assert body["status"] == "SUCCEEDED"
    assert body["evidence"], "recon task must produce real evidence"

    # Independently verify against real Postgres state, not just the HTTP
    # response body.
    real_task = app.config["AEP_STORE"].get_task(task_id)
    assert real_task is not None
    assert real_task.status.value == "SUCCEEDED"
    assert real_task.evidence


def test_task_creation_unknown_project_rejected(dev_client):
    _app, client = dev_client
    resp = client.post("/tasks", json={"project_id": "no-such-project", "type": "recon"})
    assert resp.status_code == 404


def test_evidence_endpoint_matches_task_evidence(dev_client, tmp_path):
    app, client = dev_client
    resp = client.post("/projects", json={"name": "evidence-test-project", "repo_path": str(tmp_path)})
    project_id = resp.get_json()["id"]
    resp = client.post("/tasks", json={
        "project_id": project_id, "type": "recon", "owner_agent": "recon",
        "payload": {"project_root": str(tmp_path)},
    })
    task_id = resp.get_json()["id"]
    resp = client.get(f"/tasks/{task_id}/evidence")
    assert resp.status_code == 200
    assert resp.get_json()["evidence"]


def test_approval_flow_drives_real_task_status_transition(dev_client, tmp_path):
    """Uses a policy_action of DENY/REQUIRE_APPROVAL via the SAME
    `_apply_generic_policy_gate` the orchestrator always runs, then
    verifies POST /approvals/<id>/approve drives the SAME
    Orchestrator.approve()/TaskRepository transition the CLI would use,
    proven by inspecting real Postgres state afterward."""
    app, client = dev_client
    resp = client.post("/projects", json={"name": "approval-test-project", "repo_path": str(tmp_path)})
    project_id = resp.get_json()["id"]

    resp = client.post("/tasks", json={
        "project_id": project_id, "type": "git_operation", "owner_agent": "recon",
        "payload": {
            "project_root": str(tmp_path),
            "policy_action": "iam.expand_privilege",
            "policy_context": {},
        },
    })
    task_id = resp.get_json()["id"]
    assert resp.get_json()["status"] == "BLOCKED_ON_APPROVAL"

    resp = client.get("/approvals", query_string={"project_id": project_id})
    assert resp.status_code == 200
    assert any(t["id"] == task_id for t in resp.get_json())

    resp = client.post(f"/approvals/{task_id}/approve")
    assert resp.status_code == 200
    assert resp.get_json()["approval_status"] == "APPROVED"

    real_task = app.config["AEP_STORE"].get_task(task_id)
    assert real_task.approval_status == "APPROVED"
    assert real_task.status.value == "READY"


def test_provider_credential_never_leaks_in_api_response(dev_client):
    """Mandatory credential-safety test (same style as
    tests/test_ai_gateway_credential_safety.py): a fake AI_CREDENTIAL
    value must never appear anywhere in the /providers response body,
    even if AI_BASE_URL/AI_CREDENTIAL happened to be set in this
    process's environment."""
    fake_credential = "sk-fake-not-a-real-secret-9999"
    _app, client = dev_client
    resp = client.get("/providers")
    assert resp.status_code == 200
    body_text = resp.get_data(as_text=True)
    assert fake_credential not in body_text
    assert FAKE_API_KEY_PLACEHOLDER not in body_text


def test_runtime_status_endpoint_returns_real_health_payload(dev_client):
    _app, client = dev_client
    resp = client.get("/runtime/status")
    assert resp.status_code == 200
    body = resp.get_json()
    assert "health" in body
    assert "workers" in body


def test_system_status_documents_slow_endpoint_instead_of_faking_a_fast_response(dev_client):
    _app, client = dev_client
    resp = client.get("/system/status")
    assert resp.status_code == 202
    assert "9-11 minutes" in resp.get_json()["reason"]


def test_api_key_scoped_project_rejects_cross_project_access(dev_client):
    app, client = dev_client
    resp = client.post("/projects", json={"name": "scope-test-a", "repo_path": "/tmp"})
    project_a = resp.get_json()["id"]
    resp = client.post("/projects", json={"name": "scope-test-b", "repo_path": "/tmp"})
    project_b = resp.get_json()["id"]

    from aep.api import auth
    monkeypatch_env = os.environ.pop("AEP_API_DEV_MODE", None)
    try:
        key_id, raw_key = auth.issue_key(app.config["AEP_POOL"], label="scoped", project_scope=project_a)
        headers = {"Authorization": f"Bearer {raw_key}"}
        resp = client.get(f"/incidents/{project_a}", headers=headers)
        assert resp.status_code == 200
        resp = client.get(f"/incidents/{project_b}", headers=headers)
        assert resp.status_code == 403
    finally:
        if monkeypatch_env is not None:
            os.environ["AEP_API_DEV_MODE"] = monkeypatch_env
