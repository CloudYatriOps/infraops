"""Shared helper for Stage A Postgres integration tests: connect to the
real local `aep_platform` database, or report unreachable so tests can
skip gracefully - never fake a passing result."""
from __future__ import annotations

import psycopg2

LOCAL_DSN = "host=localhost port=5432 user=aep password=aep_local_dev_only dbname=aep_platform"


def local_postgres_available() -> bool:
    try:
        conn = psycopg2.connect(LOCAL_DSN, connect_timeout=3)
        conn.close()
        return True
    except Exception:
        return False


def fresh_test_schema_connection(schema: str):
    """Connects to the local test DB and creates+uses a throwaway schema
    so migration tests don't collide with each other or with any other
    use of `aep_platform`."""
    conn = psycopg2.connect(LOCAL_DSN)
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        cur.execute(f'CREATE SCHEMA "{schema}"')
        cur.execute(f'SET search_path TO "{schema}", public')
    conn.autocommit = False
    return conn


def drop_test_schema(schema: str) -> None:
    conn = psycopg2.connect(LOCAL_DSN)
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
    conn.close()
