"""Mandatory migration mechanism tests (spec item 8): a real out-of-band
schema mutation must be genuinely detected, not just asserted via a
policy string. Runs against the real local Postgres; skips if
unreachable."""
from __future__ import annotations

import uuid

import pytest

from aep.db import migrations

from db_pg_helper import drop_test_schema, fresh_test_schema_connection, local_postgres_available

pytestmark = pytest.mark.skipif(
    not local_postgres_available(),
    reason="local PostgreSQL (aep_platform db) is not reachable in this environment",
)


@pytest.fixture
def schema_conn():
    schema = f"aep_test_{uuid.uuid4().hex[:12]}"
    conn = fresh_test_schema_connection(schema)
    try:
        yield conn
    finally:
        conn.close()
        drop_test_schema(schema)


def test_out_of_band_alter_table_is_flagged_as_drift(schema_conn):
    """Applies migrations normally (clean state), then intentionally
    mutates the schema OUTSIDE the migration runner via a raw psycopg2
    execute(), and asserts the drift-detection tool actually reports
    DRIFT afterward - proving detection works, not asserting a policy
    string exists."""
    migrations.apply_pending(schema_conn)

    before = migrations.drift_report(schema_conn)
    assert before.status == "MATCH", before.details

    # Intentional, unauthorized schema mutation - never done via the runner.
    with schema_conn.cursor() as cur:
        cur.execute("ALTER TABLE tasks ADD COLUMN foo text")
    schema_conn.commit()

    after = migrations.drift_report(schema_conn)
    assert after.status == "DRIFT"
    assert any("foo" in d for d in after.details), after.details
