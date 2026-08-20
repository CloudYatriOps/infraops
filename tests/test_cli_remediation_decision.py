"""Phase 10 Wave 10 CLI test: `aep intelligence remediation-decision`
builds its payload via `_build_remediation_decision_payload()`, the exact
function `cmd_remediation_decision` calls."""
from __future__ import annotations

import argparse
import os
import uuid

import pytest

from tests.db_pg_helper import local_postgres_available

os.environ.setdefault("AEP_PG_PASSWORD", "aep_local_dev_only")

pytestmark = pytest.mark.skipif(not local_postgres_available(),
                                 reason="local Postgres not reachable")


def test_build_remediation_decision_payload_returns_items(tmp_path):
    from aep.cli import _build_remediation_decision_payload
    from aep.db.postgres import ConnectionPool, PostgresFindingRepository, PostgresProjectRepository
    from aep.db.state_store_postgres import dsn_from_env
    from aep.db.models import FindingRecord, ProjectRecord

    pool = ConnectionPool(dsn_from_env())
    project_repo = PostgresProjectRepository(pool)
    finding_repo = PostgresFindingRepository(pool)

    pid = str(uuid.uuid4())
    project_repo.save(ProjectRecord(id=pid, name=f"cli-remdec-{pid[:8]}", repo_path="/tmp/x",
                                     policy_path="config/policy.yaml"))
    finding_repo.save(FindingRecord(
        id=str(uuid.uuid4()), project_id=pid, category="secret", severity="critical",
        description=f"hardcoded key {uuid.uuid4().hex}",
    ))

    args = argparse.Namespace(project_filter=pid, json=True, db=str(tmp_path / "state.db"))
    payload = _build_remediation_decision_payload(args)
    assert payload["count"] >= 1
    decisions = {item["decision"] for item in payload["items"]}
    # a first-occurrence critical finding is never SAFE_TO_AUTOMATE
    assert "SAFE_TO_AUTOMATE" not in decisions or all(
        item["decision"] != "SAFE_TO_AUTOMATE" for item in payload["items"]
        if item["evidence"]["occurrence_count"] == 1
    )
    assert any(item["decision"] == "NOT_SAFE" for item in payload["items"])
