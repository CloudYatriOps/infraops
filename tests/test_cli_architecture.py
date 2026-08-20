"""Phase 10 Wave 4 CLI test: `aep intelligence architecture` builds its
payload via `_build_architecture_payload()`, the exact function
`cmd_architecture` calls - same convention as `tests/test_cli_risk.py`."""
from __future__ import annotations

import argparse
import os
import uuid

import pytest

from tests.db_pg_helper import local_postgres_available

os.environ.setdefault("AEP_PG_PASSWORD", "aep_local_dev_only")

pytestmark = pytest.mark.skipif(not local_postgres_available(),
                                 reason="local Postgres not reachable")


def test_build_architecture_payload_returns_items():
    from aep.cli import _build_architecture_payload
    from aep.db.postgres import ConnectionPool, PostgresFindingRepository, PostgresProjectRepository
    from aep.db.state_store_postgres import dsn_from_env
    from aep.db.models import FindingRecord, ProjectRecord

    pool = ConnectionPool(dsn_from_env())
    project_repo = PostgresProjectRepository(pool)
    finding_repo = PostgresFindingRepository(pool)

    pid = str(uuid.uuid4())
    project_repo.save(ProjectRecord(id=pid, name=f"cli-arch-{pid[:8]}", repo_path="/tmp/x",
                                     policy_path="config/policy.yaml"))
    resource = f"src/module_{uuid.uuid4().hex[:6]}.py"
    for i in range(3):
        finding_repo.save(FindingRecord(
            id=str(uuid.uuid4()), project_id=pid, category="iac", severity="medium",
            status="OPEN", resource=resource, description=f"issue {uuid.uuid4().hex}",
        ))

    args = argparse.Namespace(project_filter=pid, json=True)
    payload = _build_architecture_payload(args)
    assert payload["count"] >= 1
    risk_ids = {item["risk_id"] for item in payload["items"]}
    assert "RESOURCE_HOTSPOT" in risk_ids
    hotspot = next(item for item in payload["items"] if item["risk_id"] == "RESOURCE_HOTSPOT")
    assert hotspot["affected_project_ids"] == [pid]
