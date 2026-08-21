"""Shared helper for Stage A Postgres integration tests: connect to the
real local `aep_platform` database, or report unreachable so tests can
skip gracefully - never fake a passing result."""
from __future__ import annotations

import psycopg2

from aep.db.state_store_postgres import dsn_from_env


def _dsn() -> str:
    """Resolve exactly the way the product does: an explicitly-configured
    `AEP_POSTGRES_DSN`/`AEP_PG_*` if the environment sets one, otherwise
    AEP's own zero-config embedded local PostgreSQL. Previously this was a
    hardcoded `host=localhost port=5432 ... password=aep_local_dev_only`
    DSN, which meant these tests only ran on a machine with a separately
    installed Postgres listening on 5432 with that exact credential - and
    errored everywhere else, even though the product itself now ships a
    working local database."""
    return dsn_from_env()


def __getattr__(name):
    """`LOCAL_DSN` stays importable for the modules that use it as a
    string, but is resolved LAZILY (PEP 562) rather than at import time -
    so merely importing this helper never starts the embedded database,
    and modules that skip on `local_postgres_available()` never pay for
    it at all."""
    if name == "LOCAL_DSN":
        return _dsn()
    raise AttributeError(name)


def local_postgres_available() -> bool:
    try:
        conn = psycopg2.connect(_dsn(), connect_timeout=10)
        conn.close()
        return True
    except Exception:
        return False


def fresh_test_schema_connection(schema: str):
    """Connects to the local test DB and creates+uses a throwaway schema
    so migration tests don't collide with each other or with any other
    use of `aep_platform`."""
    conn = psycopg2.connect(_dsn())
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        cur.execute(f'CREATE SCHEMA "{schema}"')
        cur.execute(f'SET search_path TO "{schema}", public')
    conn.autocommit = False
    return conn


def drop_test_schema(schema: str) -> None:
    conn = psycopg2.connect(_dsn())
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
    conn.close()


def dsn_with_schema(schema: str) -> str:
    """Return the resolved DSN with `search_path` pinned to `schema`.

    The old hardcoded DSN was keyword-style (`host=... port=...`), so
    callers appended ` options='-c search_path=...'` directly. The
    zero-config embedded server hands back a URI
    (`postgresql://user@host:port/db`), where that suffix is a syntax
    error - hence this helper, which formats correctly for either shape.
    """
    from urllib.parse import quote

    dsn = _dsn()
    if dsn.startswith("postgresql://") or dsn.startswith("postgres://"):
        sep = "&" if "?" in dsn else "?"
        return f"{dsn}{sep}options={quote(f'-c search_path={schema},public')}"
    return f"{dsn} options='-c search_path={schema},public'"
