"""Real, live test of the zero-config local PostgreSQL path (no mocks):
starts an actual embedded `pgserver` instance, proves data persists
across a second `ensure_local_postgres()` call (simulating a process
restart), and confirms `dsn_from_env()` only takes this path when
nothing explicit is configured."""
from __future__ import annotations

import os

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
