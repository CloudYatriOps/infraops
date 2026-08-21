"""Real, live test of the zero-config local PostgreSQL path (no mocks):
starts an actual embedded `pgserver` instance, proves data persists
across a second `ensure_local_postgres()` call (simulating a process
restart), and confirms `dsn_from_env()` only takes this path when
nothing explicit is configured."""
from __future__ import annotations

import os
import textwrap
import time

import psycopg2
import pytest

from aep.db import local_postgres
from aep.db.state_store_postgres import dsn_from_env


@pytest.fixture
def isolated_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("AEP_DATA_DIR", str(tmp_path))
    for var in ("AEP_POSTGRES_DSN", "AEP_PG_HOST", "AEP_PG_PORT", "AEP_PG_USER",
                "AEP_PG_PASSWORD", "AEP_PG_DBNAME", "AEP_PG_SSLMODE"):
        monkeypatch.delenv(var, raising=False)
    local_postgres._cached_uri = None
    yield tmp_path
    local_postgres._cached_uri = None


def test_ensure_local_postgres_provisions_and_persists(isolated_data_dir):
    uri = local_postgres.ensure_local_postgres()
    assert uri.startswith("postgresql://")

    conn = psycopg2.connect(uri)
    try:
        cur = conn.cursor()
        cur.execute("create table if not exists zc_test(x int)")
        cur.execute("insert into zc_test values (42)")
        conn.commit()
    finally:
        conn.close()

    # Simulate a fresh process: clear the in-process memo and re-resolve.
    local_postgres._cached_uri = None
    uri2 = local_postgres.ensure_local_postgres()
    conn2 = psycopg2.connect(uri2)
    try:
        cur2 = conn2.cursor()
        cur2.execute("select x from zc_test")
        assert cur2.fetchone() == (42,)
        cur2.execute("select extname from pg_extension where extname = 'vector'")
        assert cur2.fetchone() is not None
    finally:
        conn2.close()


def test_dsn_from_env_uses_local_postgres_only_when_nothing_explicit(isolated_data_dir):
    assert dsn_from_env() == local_postgres.ensure_local_postgres()


def test_dsn_from_env_prefers_explicit_config_over_local(isolated_data_dir, monkeypatch):
    monkeypatch.setenv("AEP_POSTGRES_DSN", "postgresql://explicit-not-local/db")
    assert dsn_from_env() == "postgresql://explicit-not-local/db"


def test_start_failure_reports_recovery_and_never_deletes_data(tmp_path, monkeypatch):
    """BUG-0020: a failed start must raise a deterministic, explanatory
    error and leave the data directory completely untouched. Auto-deleting
    a user's database to make startup succeed is never acceptable."""
    data_dir = tmp_path / "postgres"
    data_dir.mkdir()
    canary = data_dir / "PG_VERSION"
    canary.write_text("16")

    class _AlwaysFails:
        @staticmethod
        def get_server(path):
            raise RuntimeError("simulated stale-state start failure")

    with pytest.raises(local_postgres.DatabaseRecoveryRequired) as excinfo:
        local_postgres._start_server(_AlwaysFails, data_dir)

    message = str(excinfo.value)
    assert "Data preserved" in message
    assert str(data_dir) in message
    # The whole point: nothing was removed.
    assert canary.exists() and canary.read_text() == "16"


def test_start_retries_a_transient_failure_before_giving_up(tmp_path):
    """The observed real-world failure was a transient `pg_ctl` start
    timeout that succeeded on retry - so one retry must actually happen."""
    calls = []

    class _Handle:
        @staticmethod
        def get_uri():
            return "postgresql://ok"

    class _FailsOnceThenWorks:
        @staticmethod
        def get_server(path):
            calls.append(path)
            if len(calls) == 1:
                raise RuntimeError("simulated transient pg_ctl timeout")
            return _Handle

    assert local_postgres._start_server(_FailsOnceThenWorks, tmp_path) == "postgresql://ok"
    assert len(calls) == 2, "a transient first failure must be retried exactly once"


def test_waiter_reports_recovery_without_deleting_when_server_never_becomes_ready(tmp_path):
    """If the server genuinely never accepts connections, the waiter must
    give a deterministic recovery message - and still not touch data."""
    data_dir = tmp_path / "postgres"
    data_dir.mkdir()
    canary = data_dir / "PG_VERSION"
    canary.write_text("16")

    with pytest.raises(local_postgres.DatabaseRecoveryRequired) as excinfo:
        # Port 1 is never listening; a tiny timeout keeps the test fast.
        local_postgres._wait_until_accepting_connections(
            "postgresql://postgres:@127.0.0.1:1/postgres", data_dir, timeout_seconds=2.0)

    message = str(excinfo.value)
    assert "Data preserved" in message
    assert "never delete this directory" in message
    assert canary.exists() and canary.read_text() == "16"


# NOTE on unclean-shutdown recovery (BUG-0020): there is deliberately NO
# automated end-to-end "kill -9 the postmaster, restart, check the data"
# test here. Three attempts at one all failed for HARNESS reasons rather
# than product reasons: `pgserver` caches its server handle per data
# directory in module state (so re-resolving in-process returns the dead
# handle), holds a cross-process lock, and registers an atexit cleanup
# that turns a killed helper process into a *clean* fast-shutdown - so the
# scenario under test kept not being the scenario being simulated. A test
# that passes for the wrong reason is worse than no test.
#
# The recovery path IS covered, two ways:
#   * the unit tests above pin both non-destructive failure paths (a start
#     that never succeeds, and a server that never accepts connections) -
#     including the guarantee that the data directory is left untouched;
#   * the real scenario was verified manually and is reproducible: start
#     AEP, write a row, `taskkill /F /IM postgres.exe`, then resolve again
#     from a FRESH process. Before the fix this raised
#     "the database system is starting up"; after it, AEP waits out WAL
#     recovery and returns the row. See BUGFIX.md BUG-0020.
