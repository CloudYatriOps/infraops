"""Phase 10 Wave 6 CLI test: `aep intelligence security-trends` builds its
payload via `_build_security_trends_payload()`, the exact function
`cmd_security_trends` calls - same convention as `tests/test_cli_risk.py`."""
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


def test_build_security_trends_payload_returns_items():
    from aep.cli import _build_security_trends_payload
    from aep.db.postgres import ConnectionPool, PostgresFindingRepository, PostgresProjectRepository
    from aep.db.state_store_postgres import dsn_from_env
    from aep.db.models import FindingRecord, ProjectRecord

    pool = ConnectionPool(dsn_from_env())
    project_repo = PostgresProjectRepository(pool)
    finding_repo = PostgresFindingRepository(pool)

    pid = str(uuid.uuid4())
    project_repo.save(ProjectRecord(id=pid, name=f"cli-sectrend-{pid[:8]}", repo_path="/tmp/x",
                                     policy_path="src/aep/config/policy.yaml"))
    finding_repo.save(FindingRecord(
        id=str(uuid.uuid4()), project_id=pid, category="secret", severity="critical",
        status="OPEN", description=f"issue {uuid.uuid4().hex}",
    ))

    args = argparse.Namespace(project_filter=pid, json=True)
    payload = _build_security_trends_payload(args)
    assert payload["count"] >= 1
    assert all(item["project_id"] == pid for item in payload["items"])
    metrics = {item["metric"] for item in payload["items"]}
    assert {"critical_findings", "secret_findings", "remediation_backlog"} <= metrics
