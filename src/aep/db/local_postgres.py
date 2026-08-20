"""Zero-config local PostgreSQL: AEP's default runtime database.

The product requirement this module exists for: `pip install aep-platform`
then `aep` must work with NO PostgreSQL install, NO Supabase project, NO
remote database URL, and no password the user has to know. This is done
via `pgserver` (https://pypi.org/project/pgserver/) - a pip-installable
package that bundles real PostgreSQL 16.2 binaries (+ pgvector) for
Windows/macOS/Linux and manages the server process for us; no other
database engine is introduced (SQLite remains forbidden as a runtime
backend - see BUGFIX.md / ARCHITECTURE.md).

This is used ONLY when the caller hasn't explicitly configured a database
via `AEP_POSTGRES_DSN`/`AEP_PG_HOST`/`AEP_PG_PORT`/`AEP_PG_PASSWORD` - see
`dsn_from_env()` in `state_store_postgres.py`, the one place that decides
whether to take this path. An operator pointing AEP at their own/a remote
Postgres (Supabase or otherwise) via those env vars is unaffected by this
module entirely.

Known current constraint: `pgserver` ships wheels for CPython 3.9-3.12
only (verified against PyPI's published file list for pgserver 0.1.4) -
there is no 3.13 wheel yet. `pyproject.toml`'s `requires-python` reflects
this.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

_cached_uri: Optional[str] = None


def get_data_dir() -> Path:
    """Platform-aware AEP data directory - never inside the source repo,
    never hardcoded to one OS. `AEP_DATA_DIR` overrides everything (used
    by tests and by anyone who wants a non-default location)."""
    override = os.environ.get("AEP_DATA_DIR")
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "AEP"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "AEP"
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "aep"


def ensure_local_postgres() -> str:
    """Starts (or reuses, if already running against this data dir) a
    local, embedded PostgreSQL instance and returns its connection URI.

    Memoized per-process: repeated calls (e.g. the API process and a CLI
    command both resolving a DSN) return the same URI without paying
    `pgserver.get_server`'s startup cost twice. `pgserver` itself
    reference-counts across independent OS processes pointed at the same
    data directory (see its own docs) - it does not start a second
    cluster against data another process already owns, and does not
    touch any *other* PostgreSQL server that might happen to be running
    on this machine (own isolated data dir, own ephemeral port - never
    the system default 5432 unless nothing else claims it).

    Never asks the user for a password: `pgserver` provisions a local,
    passwordless (trust-auth, loopback-only) `postgres` role - that is
    the "internal local credential" the architecture requires never be
    surfaced to the user, never logged, never committed.
    """
    global _cached_uri
    if _cached_uri is not None:
        return _cached_uri

    try:
        import pgserver
    except ImportError as exc:  # pragma: no cover - core dependency, should always be present
        raise RuntimeError(
            "pgserver is not installed - it is a required (non-optional) dependency "
            "for AEP's zero-config local database. Reinstall with `pip install aep-platform`."
        ) from exc

    data_dir = get_data_dir() / "postgres"
    data_dir.mkdir(parents=True, exist_ok=True)
    server = pgserver.get_server(str(data_dir))
    server.psql("create extension if not exists vector;")

    from . import migrations
    import psycopg2
    conn = psycopg2.connect(server.get_uri(), connect_timeout=5)
    try:
        migrations.apply_pending(conn)
    finally:
        conn.close()

    _cached_uri = server.get_uri()
    return _cached_uri
