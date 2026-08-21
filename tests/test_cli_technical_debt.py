"""Phase 10 Wave 8 CLI test: `aep intelligence technical-debt` builds its
payload via `_build_technical_debt_payload()`, the exact function
`cmd_technical_debt` calls - same convention as `tests/test_cli_dependency_risk.py`."""
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


def test_build_technical_debt_payload_returns_items(tmp_path):
    from aep.cli import _build_technical_debt_payload
    from aep.db.postgres import ConnectionPool, PostgresFindingRepository, PostgresProjectRepository
    from aep.db.state_store_postgres import dsn_from_env
    from aep.db.models import FindingRecord, ProjectRecord

    pool = ConnectionPool(dsn_from_env())
    project_repo = PostgresProjectRepository(pool)
    finding_repo = PostgresFindingRepository(pool)

    pid = str(uuid.uuid4())
    project_repo.save(ProjectRecord(id=pid, name=f"cli-debt-{pid[:8]}", repo_path="/tmp/x",
                                     policy_path="src/aep/config/policy.yaml"))
    for i in range(2):
        finding_repo.save(FindingRecord(
            id=str(uuid.uuid4()), project_id=pid, category="secret", severity="medium",
            status="SUPPRESSED", description=f"suppressed issue {uuid.uuid4().hex}",
        ))

    args = argparse.Namespace(project_filter=pid, json=True, db=str(tmp_path / "state.db"))
    payload = _build_technical_debt_payload(args)
    assert payload["count"] >= 1
    debt_signals = {item["debt_signal"] for item in payload["items"]}
    assert "CI_FAILURE_HISTORY_UNAVAILABLE" in debt_signals
    assert "REPEATED_SUPPRESSED_FINDINGS" in debt_signals
