"""Phase 10 Wave 12 CLI test: `aep intelligence health-score` builds its
payload via `_build_health_score_payload()`, the exact function
`cmd_health_score` calls. Distinct from Wave 2's `aep intelligence
patterns` command - this is the per-project aggregate summary."""
from __future__ import annotations

import argparse
import os
import uuid

import pytest

from tests.db_pg_helper import local_postgres_available

os.environ.setdefault("AEP_PG_PASSWORD", "aep_local_dev_only")

pytestmark = pytest.mark.skipif(not local_postgres_available(),
                                 reason="local Postgres not reachable")


def test_build_health_score_payload_returns_summary(tmp_path):
    from aep.cli import _build_health_score_payload
    from aep.db.postgres import ConnectionPool, PostgresFindingRepository, PostgresProjectRepository
    from aep.db.state_store_postgres import dsn_from_env
    from aep.db.models import FindingRecord, ProjectRecord

    pool = ConnectionPool(dsn_from_env())
    project_repo = PostgresProjectRepository(pool)
    finding_repo = PostgresFindingRepository(pool)

    pid = str(uuid.uuid4())
    project_repo.save(ProjectRecord(id=pid, name=f"cli-health-{pid[:8]}", repo_path="/tmp/x",
                                     policy_path="config/policy.yaml"))
    for i in range(3):
        finding_repo.save(FindingRecord(
            id=str(uuid.uuid4()), project_id=pid, category="secret", severity="critical",
            description=f"same leaked key across runs {i % 1}",
        ))

    args = argparse.Namespace(project_filter=pid, json=True, db=str(tmp_path / "state.db"))
    payload = _build_health_score_payload(args)
    assert payload["count"] == 1
    item = payload["items"][0]
    assert item["project_id"] == pid
    assert item["overall_state"] in ("HEALTHY", "AT_RISK", "CRITICAL", "UNKNOWN")
    assert set(item["subsystem_states"]) == {
        "security_posture", "risk_prediction", "incident_patterns", "technical_debt",
        "architecture", "deployment_risk", "cost_intelligence", "ci_clustering",
    }
