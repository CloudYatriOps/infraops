"""Stage A.5 runtime cutover: proves the PostgreSQL startup gate for real
(spec item 5) - normal/outage/drift cases - plus that AEP_DB_BACKEND=postgres
never silently falls back to SQLite when Postgres is unavailable (spec
item 6). All tests use a throwaway schema (see db_pg_helper) except the
outage case, which necessarily talks to the real server process, and are
skipped if local PostgreSQL is unreachable rather than faking a result.
"""
from __future__ import annotations

import subprocess
import uuid

import psycopg2
import pytest

from aep.db import migrations
from aep.db.startup import DatabaseUnavailableError, SchemaDriftError, verify_database
from aep.db.state_store_postgres import PostgresStateStore

from db_pg_helper import LOCAL_DSN, drop_test_schema, fresh_test_schema_connection, local_postgres_available

pytestmark = pytest.mark.skipif(
    not local_postgres_available(),
    reason="local PostgreSQL (aep_platform db) is not reachable in this environment",
)


def _dsn_for_schema(schema: str) -> str:
    # options=-csearch_path=... makes new connections (e.g. the one
    # verify_database opens internally) resolve to the same throwaway
    # schema as the fixture's own connection.
    return f"{LOCAL_DSN} options='-c search_path={schema},public'"


@pytest.fixture
def migrated_schema():
    schema = f"aep_test_{uuid.uuid4().hex[:12]}"
    conn = fresh_test_schema_connection(schema)
    migrations.apply_pending(conn)
    conn.close()
    try:
        yield schema
    finally:
        drop_test_schema(schema)


# ---- 5a: normal case ---------------------------------------------------

def test_startup_gate_succeeds_against_healthy_migrated_db(migrated_schema):
    dsn = _dsn_for_schema(migrated_schema)
    verify_database(dsn)  # must not raise

    store = PostgresStateStore(dsn=dsn)
    try:
        store.ensure_project("11111111-1111-1111-1111-111111111111", name="p")
    finally:
        store.close()


# ---- 5b: outage case ----------------------------------------------------

def test_startup_gate_raises_when_postgres_is_down():
    """Stops the real local postgresql service, confirms construction
    raises DatabaseUnavailableError (not a silent SQLite fallback or a
    bare psycopg2 exception), then restarts the service immediately so
    the rest of the suite is not blocked."""
    subprocess.run(["service", "postgresql", "stop"], check=True)
    try:
        with pytest.raises(DatabaseUnavailableError):
            verify_database(LOCAL_DSN, connect_timeout=2)
        with pytest.raises(DatabaseUnavailableError):
            PostgresStateStore(dsn=LOCAL_DSN)
    finally:
        subprocess.run(["service", "postgresql", "start"], check=True)
        _wait_for_postgres()


def _wait_for_postgres(timeout: float = 15.0) -> None:
    import time
    deadline = time.time() + timeout
    last_exc = None
    while time.time() < deadline:
        try:
            conn = psycopg2.connect(LOCAL_DSN, connect_timeout=2)
            conn.close()
            return
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            time.sleep(0.5)
    raise RuntimeError(f"postgresql did not come back up in time: {last_exc}")


# ---- 5c: drift case -----------------------------------------------------

def test_startup_gate_raises_on_schema_drift(migrated_schema):
    dsn = _dsn_for_schema(migrated_schema)

    # Sanity: clean state passes first.
    verify_database(dsn)

    # Real out-of-band schema change, bypassing the migration runner
    # entirely - same technique as tests/test_db_schema_drift.py.
    conn = psycopg2.connect(dsn)
    try:
        with conn.cursor() as cur:
            cur.execute("ALTER TABLE tasks ADD COLUMN verification_drift_col text")
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(SchemaDriftError):
        verify_database(dsn)
    with pytest.raises(SchemaDriftError):
        PostgresStateStore(dsn=dsn)

    # Clean up the drift via a proper mechanism: it was never a real
    # migration, so the correct fix is reverting the raw ALTER directly
    # (there is nothing to "migrate away" - no migration file ever
    # declared this column), then confirming normal construction
    # succeeds again afterward.
    conn = psycopg2.connect(dsn)
    try:
        with conn.cursor() as cur:
            cur.execute("ALTER TABLE tasks DROP COLUMN verification_drift_col")
        conn.commit()
    finally:
        conn.close()

    verify_database(dsn)  # must not raise anymore
    store = PostgresStateStore(dsn=dsn)
    store.close()


# ---- 6: no silent SQLite fallback ----------------------------------------

def test_no_silent_sqlite_fallback_when_backend_is_postgres_and_unreachable(monkeypatch, tmp_path):
    """AEP_DB_BACKEND=postgres with an unreachable Postgres must raise,
    never quietly hand back a working SQLite StateStore instead."""
    from aep import bootstrap
    from aep.models import ProjectConfig

    bad_dsn = "host=127.0.0.1 port=1 user=aep password=x dbname=aep_platform connect_timeout=1"
    monkeypatch.setenv("AEP_DB_BACKEND", "postgres")
    monkeypatch.setenv("AEP_POSTGRES_DSN", bad_dsn)

    project = ProjectConfig(
        id="11111111-1111-1111-1111-111111111111", name="p",
        repo_path=str(tmp_path), policy_path=str(tmp_path / "policy.yaml"),
    )
    (tmp_path / "policy.yaml").write_text("rules: []\n")

    with pytest.raises(DatabaseUnavailableError):
        bootstrap.build_orchestrator(db_path=str(tmp_path / "state.db"), project=project)

    # And confirm the *sqlite* opt-out path (as opposed to the default) is
    # completely unaffected by any of this - still plain SQLite, still
    # succeeds, exactly as before the Stage A.5 default flip.
    monkeypatch.delenv("AEP_DB_BACKEND")
    monkeypatch.delenv("AEP_POSTGRES_DSN")
    orch = bootstrap.build_orchestrator(
        db_path=str(tmp_path / "state2.db"), project=project, db_backend="sqlite")
    assert orch.store is not None


# ---- Stage A.5 default flip: Postgres is now the ambient default --------

def test_default_backend_is_postgres_with_no_explicit_choice(monkeypatch, tmp_path):
    """The single most important proof in this stage: with NO `db_backend`
    argument and NO `AEP_DB_BACKEND` override, both the factory directly
    and `build_orchestrator` on top of it must resolve to a real
    `PostgresStateStore` - not `StateStore` - because the production
    default flipped."""
    from aep import bootstrap
    from aep.db.factory import build_state_store, resolve_backend
    from aep.db.state_store_postgres import PostgresStateStore
    from aep.models import ProjectConfig

    monkeypatch.delenv("AEP_DB_BACKEND", raising=False)
    monkeypatch.delenv("AEP_POSTGRES_DSN", raising=False)

    assert resolve_backend() == "postgres"

    store = build_state_store(str(tmp_path / "unused.db"))
    try:
        assert isinstance(store, PostgresStateStore)
    finally:
        store.close()

    project = ProjectConfig(
        id="22222222-2222-2222-2222-222222222222", name="p",
        repo_path=str(tmp_path), policy_path=str(tmp_path / "policy.yaml"),
    )
    (tmp_path / "policy.yaml").write_text("rules: []\n")
    orch = bootstrap.build_orchestrator(db_path=str(tmp_path / "state.db"), project=project)
    try:
        assert isinstance(orch.store, PostgresStateStore)
    finally:
        orch.store.close()


def test_default_still_raises_dbunavailable_when_postgres_down_not_silent_fallback(
        monkeypatch, tmp_path):
    """Re-proves spec item 6 under the NEW default: stop the real local
    PostgreSQL server, confirm the *default* (no explicit db_backend, no
    AEP_DB_BACKEND override) construction path raises
    `DatabaseUnavailableError` - it must NOT quietly hand back a working
    SQLite store just because SQLite happens to be sitting right there as
    a possibility. Always restarts PostgreSQL in `finally`."""
    from aep.db.factory import build_state_store

    monkeypatch.delenv("AEP_DB_BACKEND", raising=False)
    monkeypatch.delenv("AEP_POSTGRES_DSN", raising=False)

    subprocess.run(["service", "postgresql", "stop"], check=True)
    try:
        with pytest.raises(DatabaseUnavailableError):
            build_state_store(str(tmp_path / "unused.db"))
    finally:
        subprocess.run(["service", "postgresql", "start"], check=True)
        _wait_for_postgres()
