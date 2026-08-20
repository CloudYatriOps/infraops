"""Real-Postgres integration tests for the Stage A migration runner
(src/aep/db/migrations.py). Uses the local `aep_platform` database in a
throwaway schema per test so runs don't collide; skips gracefully if the
local Postgres server isn't reachable (never fakes a pass)."""
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


def test_status_reports_all_migrations_pending_on_fresh_schema(schema_conn):
    statuses = migrations.status(schema_conn)
    assert len(statuses) >= 1
    assert all(not s.applied for s in statuses)


def test_apply_pending_applies_all_migrations_and_records_them(schema_conn):
    applied = migrations.apply_pending(schema_conn)
    assert "0001_initial_schema" in applied
    statuses = migrations.status(schema_conn)
    assert all(s.applied for s in statuses)

    with schema_conn.cursor() as cur:
        cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema()")
        tables = {r[0] for r in cur.fetchall()}
    for expected in ("projects", "tasks", "events", "memory_records", "findings", "deployments"):
        assert expected in tables


def test_validate_reports_no_problems_immediately_after_apply(schema_conn):
    migrations.apply_pending(schema_conn)
    assert migrations.validate(schema_conn) == []


def test_apply_pending_is_idempotent_second_call_applies_nothing(schema_conn):
    first = migrations.apply_pending(schema_conn)
    assert len(first) >= 1
    second = migrations.apply_pending(schema_conn)
    assert second == []


def test_checksum_drift_is_detected_and_apply_refuses(schema_conn):
    migrations.apply_pending(schema_conn)
    # Simulate tampering: mutate the recorded checksum for an applied migration.
    with schema_conn.cursor() as cur:
        cur.execute("UPDATE schema_migrations SET checksum = 'tampered' WHERE id = '0001_initial_schema'")
    schema_conn.commit()

    problems = migrations.validate(schema_conn)
    assert any("0001_initial_schema" in p for p in problems)

    with pytest.raises(migrations.ChecksumMismatch):
        migrations.apply_pending(schema_conn)


def test_full_migration_lifecycle_write_validate_apply_verify(schema_conn):
    """Mandatory pairing test: a migration written -> checksum computed ->
    applied via the runner -> schema verified as matching -> passes cleanly."""
    statuses_before = migrations.status(schema_conn)
    assert all(not s.applied for s in statuses_before)

    applied = migrations.apply_pending(schema_conn)
    assert applied

    statuses_after = migrations.status(schema_conn)
    assert all(s.applied and s.checksum == s.recorded_checksum for s in statuses_after)

    report = migrations.drift_report(schema_conn)
    assert report.status == "MATCH", report.details
