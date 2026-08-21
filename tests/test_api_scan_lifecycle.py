"""API surface for Project Analysis Productization: `POST /projects/<id>/scan`,
`GET /projects/<id>/scans[/<scan_id>]`, `GET /projects/<id>/report`,
`DELETE /projects/<id>`. Same real-Postgres-integration convention as
test_api_app.py - no fakes, skips gracefully if local Postgres is
unreachable.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.db_pg_helper import local_postgres_available

pytestmark = pytest.mark.skipif(not local_postgres_available(),
                                 reason="local Postgres not reachable")

FIXTURE_REPO = str(Path(__file__).resolve().parent / "fixtures" / "infra" / "terraform")


@pytest.fixture()
def dev_client(monkeypatch):
    monkeypatch.setenv("AEP_API_DEV_MODE", "1")
    from aep.api.app import create_app
    app = create_app()
    return app, app.test_client()


def _create_project(client, name: str, repo_path: str = FIXTURE_REPO) -> str:
    resp = client.post("/projects", json={"name": name, "repo_path": repo_path})
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()["id"]


def test_new_project_reports_never_scanned_with_detected_capabilities(dev_client):
    _app, client = dev_client
    resp = client.post("/projects", json={"name": "lifecycle-create-test", "repo_path": FIXTURE_REPO})
    body = resp.get_json()
    assert body["analysis_state"] == "NEVER_SCANNED"
    assert "TERRAFORM" in body["detected_capabilities"]
    assert body["last_scan_at"] is None


def test_scan_now_persists_and_matches_cli_scan_shape(dev_client):
    _app, client = dev_client
    pid = _create_project(client, "lifecycle-scan-test")
    resp = client.post(f"/projects/{pid}/scan")
    assert resp.status_code == 201, resp.get_json()
    body = resp.get_json()
    assert body["status"] == "SUCCEEDED"
    assert body["analysis_state"] == "COMPLETED_WITH_FINDINGS"
    report = body["report"]
    analyzer_names = {a["analyzer"] for a in report["analyzers"]}
    assert analyzer_names == {"Secrets", "SAST", "Dependencies", "IaC", "Containers"}
    iac = next(a for a in report["analyzers"] if a["analyzer"] == "IaC")
    assert iac["status"] == "FAIL"
    assert any(f["rule"] == "TF_STATE_LOCAL_BACKEND" for f in iac["findings"])


def test_scan_survives_a_fresh_app_instance(dev_client):
    """The actual product requirement: visible after restart, not just
    within the same process/request that ran the scan."""
    _app, client = dev_client
    pid = _create_project(client, "lifecycle-restart-test")
    scan_id = client.post(f"/projects/{pid}/scan").get_json()["task_id"]

    from aep.api.app import create_app
    fresh_app = create_app()
    fresh_client = fresh_app.test_client()
    resp = fresh_client.get(f"/projects/{pid}/scans/{scan_id}")
    assert resp.status_code == 200
    assert resp.get_json()["finding_count"] >= 1


def test_scans_list_and_detail_and_report_endpoints(dev_client):
    _app, client = dev_client
    pid = _create_project(client, "lifecycle-endpoints-test")
    scan_id = client.post(f"/projects/{pid}/scan").get_json()["task_id"]

    resp = client.get(f"/projects/{pid}/scans")
    assert len(resp.get_json()["scans"]) == 1
    assert resp.get_json()["comparison"] is None  # only one run so far

    resp = client.get(f"/projects/{pid}/scans/{scan_id}")
    assert resp.get_json()["scan_id"] == scan_id
    assert len(resp.get_json()["timeline"]) > 0

    resp = client.get(f"/projects/{pid}/report")
    assert resp.get_json()["scan_id"] == scan_id

    resp = client.get(f"/projects/{pid}/report?format=markdown")
    assert resp.content_type.startswith("text/markdown")
    assert "## Findings" in resp.get_data(as_text=True)


def test_report_before_any_scan_is_explicit_not_a_fake_clean_report(dev_client):
    _app, client = dev_client
    pid = _create_project(client, "lifecycle-noscan-test")
    resp = client.get(f"/projects/{pid}/report")
    assert resp.status_code == 404
    assert resp.get_json()["error"] == "NOT_YET_SCANNED"


def test_rerun_preserves_history_and_reports_comparison(dev_client):
    _app, client = dev_client
    pid = _create_project(client, "lifecycle-rerun-test")
    first_id = client.post(f"/projects/{pid}/scan").get_json()["task_id"]
    second_id = client.post(f"/projects/{pid}/scan").get_json()["task_id"]
    assert first_id != second_id

    resp = client.get(f"/projects/{pid}/scans")
    body = resp.get_json()
    assert len(body["scans"]) == 2
    assert body["comparison"]["new_findings"] == []
    assert body["comparison"]["resolved_findings"] == []

    # Old scan's own detail is untouched by the rerun.
    old = client.get(f"/projects/{pid}/scans/{first_id}").get_json()
    assert old["scan_id"] == first_id


def test_delete_archives_never_deletes_repo_files_or_scan_history(dev_client, tmp_path):
    _app, client = dev_client
    real_repo = tmp_path / "a-real-repo"
    real_repo.mkdir()
    (real_repo / "README.md").write_text("do not delete me\n")
    pid = _create_project(client, "lifecycle-delete-test", repo_path=str(real_repo))
    scan_id = client.post(f"/projects/{pid}/scan").get_json()["task_id"]

    resp = client.delete(f"/projects/{pid}")
    assert resp.status_code == 200
    assert resp.get_json()["archived"] is True

    assert not any(p["id"] == pid for p in client.get("/projects").get_json())
    # Filesystem and scan history both untouched.
    assert (real_repo / "README.md").read_text() == "do not delete me\n"
    resp = client.get(f"/projects/{pid}/scans/{scan_id}")
    assert resp.status_code == 200

    # Deleting an already-archived project is a clean conflict, not a crash.
    resp = client.delete(f"/projects/{pid}")
    assert resp.status_code == 409


def test_delete_nonexistent_project_is_404(dev_client):
    _app, client = dev_client
    # A random uuid, deliberately NOT the all-zeros sentinel project id
    # app.py auto-provisions for org-wide requests - that one genuinely
    # exists in every AEP instance and archiving it by accident here
    # would be a real, cross-test side effect, not a clean 404 case.
    resp = client.delete("/projects/ffffffff-ffff-ffff-ffff-ffffffffffff")
    assert resp.status_code == 404
