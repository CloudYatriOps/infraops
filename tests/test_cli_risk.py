"""Phase 10 Wave 3 CLI test: `aep intelligence risk` builds its payload
via `_build_risk_payload()`, the exact function `cmd_risk` calls - same
convention as exercising `_build_prioritize_payload`/`_build_patterns_payload`
directly (no existing dedicated CLI test module for those either; this
avoids a slow real-subprocess+Postgres round trip while still exercising
the real code path end to end against real Postgres)."""
from __future__ import annotations

import argparse
import os
import uuid

import pytest

from tests.db_pg_helper import local_postgres_available

os.environ.setdefault("AEP_PG_PASSWORD", "aep_local_dev_only")

pytestmark = pytest.mark.skipif(not local_postgres_available(),
                                 reason="local Postgres not reachable")


def test_build_risk_payload_returns_items(tmp_path):
    from aep.cli import _build_risk_payload
    from aep.db.postgres import ConnectionPool, PostgresFindingRepository, PostgresProjectRepository
    from aep.db.state_store_postgres import dsn_from_env
    from aep.db.models import FindingRecord, ProjectRecord

    pool = ConnectionPool(dsn_from_env())
    project_repo = PostgresProjectRepository(pool)
    finding_repo = PostgresFindingRepository(pool)

    pid = str(uuid.uuid4())
    project_repo.save(ProjectRecord(id=pid, name=f"cli-risk-{pid[:8]}", repo_path="/tmp/x",
                                     policy_path="config/policy.yaml"))
    finding_repo.save(FindingRecord(
        id=str(uuid.uuid4()), project_id=pid, category="secret", severity="critical",
        status="OPEN", description=f"issue {uuid.uuid4().hex}",
    ))

    args = argparse.Namespace(project_filter=pid, json=True, db=str(tmp_path / "state.db"))
    payload = _build_risk_payload(args)
    assert payload["count"] == 1
    assert payload["items"][0]["project_id"] == pid
    assert "breakdown" in payload["items"][0]
    assert sum(v["weight"] for v in payload["items"][0]["breakdown"].values()) == pytest.approx(1.0)
