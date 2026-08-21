"""Phase 10 Wave 5 CLI test: `aep intelligence cost` builds its payload via
`_build_cost_payload()`, the exact function `cmd_cost` calls - same
convention as `tests/test_cli_technical_debt.py`."""
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


def test_build_cost_payload_all_providers_blocked(tmp_path):
    from aep.cli import _build_cost_payload

    args = argparse.Namespace(project_filter=None, json=True, db=str(tmp_path / "state.db"))
    payload = _build_cost_payload(args)
    assert payload["signals"]
    assert all(s["status"] == "BLOCKED" for s in payload["signals"])


def test_build_cost_payload_waste_signal_from_real_finding(tmp_path):
    from aep.cli import _build_cost_payload
    from aep.db.postgres import ConnectionPool, PostgresFindingRepository, PostgresProjectRepository
    from aep.db.state_store_postgres import dsn_from_env
    from aep.db.models import FindingRecord, ProjectRecord

    pool = ConnectionPool(dsn_from_env())
    project_repo = PostgresProjectRepository(pool)
    finding_repo = PostgresFindingRepository(pool)

    pid = str(uuid.uuid4())
    project_repo.save(ProjectRecord(id=pid, name=f"cli-cost-{pid[:8]}", repo_path="/tmp/x",
                                     policy_path="src/aep/config/policy.yaml"))
    finding_repo.save(FindingRecord(
        id=str(uuid.uuid4()), project_id=pid, category="infrastructure", severity="low",
        description=f"idle instance {uuid.uuid4().hex}",
    ))

    args = argparse.Namespace(project_filter=pid, json=True, db=str(tmp_path / "state.db"))
    payload = _build_cost_payload(args)
    assert len(payload["waste_signal_findings"]) == 1
    assert payload["waste_signal_findings"][0]["project_id"] == pid
