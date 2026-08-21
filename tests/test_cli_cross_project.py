"""Phase 10 Wave 9 CLI test: `aep intelligence cross-project` builds its
payload via `_build_cross_project_payload()`, the exact function
`cmd_cross_project` calls - same convention as `tests/test_cli_dependency_risk.py`."""
from __future__ import annotations

import argparse
import os
import uuid

import pytest

from tests.db_pg_helper import local_postgres_available

# (AEP_PG_PASSWORD no longer set here: setting any AEP_PG_* var opts OUT
# of AEP's zero-config embedded local PostgreSQL - see tests/conftest.py.)

pytestmark = pytest.mark.skipif(not local_postgres_available(),
                                 reason="local Postgres not reachable")


def test_build_cross_project_payload_returns_items(tmp_path):
    from aep.cli import _build_cross_project_payload
    from aep.db.postgres import ConnectionPool, PostgresFindingRepository, PostgresProjectRepository
    from aep.db.state_store_postgres import dsn_from_env
    from aep.db.models import FindingRecord, ProjectRecord

    pool = ConnectionPool(dsn_from_env())
    project_repo = PostgresProjectRepository(pool)
    finding_repo = PostgresFindingRepository(pool)

    p1, p2 = str(uuid.uuid4()), str(uuid.uuid4())
    for pid in (p1, p2):
        project_repo.save(ProjectRecord(id=pid, name=f"cli-crossproj-{pid[:8]}", repo_path="/tmp/x",
                                         policy_path="src/aep/config/policy.yaml"))
    desc = f"vulnerable package {uuid.uuid4().hex[:8]}"
    for pid in (p1, p2):
        finding_repo.save(FindingRecord(
            id=str(uuid.uuid4()), project_id=pid, category="dependency", severity="high",
            status="OPEN", description=desc,
        ))

    args = argparse.Namespace(project_filter=None, json=True, db=str(tmp_path / "state.db"))
    payload = _build_cross_project_payload(args)
    matches = [item for item in payload["items"] if set(item["affected_project_ids"]) == {p1, p2}]
    assert len(matches) == 1
