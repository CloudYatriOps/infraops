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

import logging
import os
import time
import sys
from pathlib import Path
from typing import Optional

_cached_uri: Optional[str] = None

# BUG-0020: `pgserver` already handles a stale `postmaster.pid` left by an
# ungraceful kill. What it does NOT absorb is its own fixed 10s `pg_ctl -w`
# start timeout: after an unclean shutdown PostgreSQL replays its
# write-ahead log before accepting connections, and that routinely takes
# longer than 10s. pg_ctl then reports "Timeout starting server" even
# though recovery is progressing perfectly normally underneath.
#
# So retry with a real waiting envelope rather than once: the database is
# busy protecting the user's data, and the only correct response is
# patience. Never a wipe.
_START_ATTEMPTS = 5
_START_RETRY_SLEEP_SECONDS = 5.0


class DatabaseRecoveryRequired(RuntimeError):
    """AEP's local PostgreSQL could not be started.

    Raised INSTEAD of ever deleting or reinitializing the data directory:
    a failed start is not evidence that the data is bad, and silently
    discarding a user's history to make a startup succeed would be a far
    worse outcome than stopping with an explanation. The message always
    states that data is preserved and names the manual recovery step.
    """


def _running_server_uri(pgserver, data_dir: Path) -> Optional[str]:
    """Return the URI of a postmaster that is genuinely up for this data
    directory, or None. Reads the on-disk postmaster info rather than
    trusting a handle, so it stays correct when `pg_ctl` reported a
    timeout for a server that then finished starting."""
    try:
        from pgserver.utils import PostmasterInfo

        info = PostmasterInfo.read_from_pgdata(data_dir)
        if info is not None and info.is_running() and info.status == "ready":
            return info.get_uri()
    except Exception:  # noqa: BLE001 - best-effort probe, never the failure path
        return None
    return None


def _start_server(pgserver, data_dir: Path) -> str:
    """Start (or attach to) the local server and return a usable URI.

    Retries a transient failure, then fails loudly and non-destructively.
    The URI is fetched INSIDE the retry on purpose: after an unclean kill
    `get_server()` can return a handle whose postmaster info was never
    populated, and `get_uri()` then raises `AssertionError` from deep
    inside the dependency. Treating that as a failed attempt (rather than
    trusting the handle) is what makes the retry actually cover the
    crash-recovery case.

    Real-user-reported UX defect this also fixes: `pgserver` itself logs
    a raw `_logger.error("Timeout starting server...")` (Python logging,
    handler-of-last-resort straight to stderr) on EVERY attempt this loop
    exists specifically to retry through - WAL crash recovery routinely
    exceeds its fixed 10s `pg_ctl` timeout. That line reaches the user's
    terminal with zero framing, reading as a fatal crash moments before
    the real PostgreSQL log says "database system is ready to accept
    connections" - unacceptable UX for a condition this loop already
    handles correctly underneath. `pgserver`'s logger is muted only for
    the duration of this retry loop (never its behavior, never the
    recovery logic) so only AEP's own framed progress messages reach the
    console; a genuine final failure still raises `DatabaseRecoveryRequired`
    below with the real underlying error and the on-disk log path named.
    """
    last_exc: Optional[BaseException] = None
    pgserver_logger = logging.getLogger("pgserver")
    previous_level = pgserver_logger.level
    pgserver_logger.setLevel(logging.CRITICAL)
    try:
        for attempt in range(_START_ATTEMPTS):
            try:
                server = pgserver.get_server(str(data_dir))
                return server.get_uri()
            except Exception as exc:  # noqa: BLE001 - re-raised as a typed error below
                last_exc = exc
                print(f"Waiting for PostgreSQL readiness... "
                      f"(WAL recovery can take longer than a fresh start; "
                      f"attempt {attempt + 1}/{_START_ATTEMPTS})", flush=True)
                time.sleep(_START_RETRY_SLEEP_SECONDS)
                # `pg_ctl -w` timing out does NOT mean the server failed to
                # start - after an unclean shutdown it is usually just still
                # replaying WAL, and it finishes and starts listening moments
                # later. Before spending another start attempt (or giving up),
                # check whether a postmaster is now actually up and use it.
                uri = _running_server_uri(pgserver, data_dir)
                if uri is not None:
                    return uri
    finally:
        pgserver_logger.setLevel(previous_level)
    raise DatabaseRecoveryRequired(
        "AEP database requires recovery. Data preserved - nothing was deleted.\n"
        f"  data directory: {data_dir}\n"
        f"  underlying error: {type(last_exc).__name__}: {last_exc}\n"
        "\n"
        "This usually means a previous AEP process (or the machine) was killed\n"
        "ungracefully and a PostgreSQL process is still holding the directory.\n"
        "Recovery, in order:\n"
        "  1. Make sure no stray postgres process is running for this data\n"
        "     directory, then run `aep start` again - a stale postmaster.pid\n"
        "     alone is handled automatically.\n"
        f"  2. Inspect the PostgreSQL log at {data_dir / 'log'} for the real cause.\n"
        "  3. Only if you have decided the local database is expendable, delete\n"
        f"     {data_dir} by hand. AEP will never do this for you, because it\n"
        "     destroys all local task/evidence/memory history.\n"
        "See BUGFIX.md BUG-0020."
    ) from last_exc


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
    print("Starting local database...", flush=True)
    uri = _start_server(pgserver, data_dir)

    # BUG-0020: `pg_ctl -w` returning does NOT mean the database is ready
    # to accept queries. After an unclean shutdown PostgreSQL performs
    # normal WAL crash recovery first and rejects connections with
    # "the database system is starting up" until it finishes. Waiting for
    # that is the correct, non-destructive recovery - the data is fine and
    # Postgres is in the middle of protecting it.
    _wait_until_accepting_connections(uri, data_dir)
    print("PostgreSQL READY", flush=True)

    from . import migrations
    import psycopg2
    # `create extension` runs over psycopg2 rather than pgserver's `psql`
    # binary wrapper: one connection path to reason about, and it is the
    # one we just confirmed is ready.
    conn = psycopg2.connect(uri, connect_timeout=10)
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("create extension if not exists vector;")
        conn.autocommit = False
        migrations.apply_pending(conn)
    finally:
        conn.close()

    _cached_uri = uri
    return _cached_uri


def _wait_until_accepting_connections(uri: str, data_dir: Path,
                                       timeout_seconds: float = 120.0) -> None:
    """Block until the freshly-started server actually accepts a
    connection, or fail with the non-destructive recovery message.

    The timeout is generous on purpose: crash recovery replays the write-
    ahead log, and how long that takes scales with how much work was in
    flight when the process died. Giving up early here - or worse,
    "recovering" by wiping the directory - would destroy exactly the data
    PostgreSQL is in the middle of restoring.
    """
    import psycopg2

    deadline = time.monotonic() + timeout_seconds
    last_exc: Optional[BaseException] = None
    last_notice = 0.0
    while time.monotonic() < deadline:
        try:
            psycopg2.connect(uri, connect_timeout=5).close()
            return
        except Exception as exc:  # noqa: BLE001 - retried, then reported below
            last_exc = exc
            # A silent multi-second wait reads as a hang, not progress -
            # a periodic reassurance (not per-second noise) is what turns
            # "is this stuck?" into "it's still recovering, as expected".
            now = time.monotonic()
            if now - last_notice >= 5.0:
                print("Waiting for PostgreSQL readiness... "
                      "(replaying write-ahead log after an unclean shutdown is normal)",
                      flush=True)
                last_notice = now
            time.sleep(1.0)

    raise DatabaseRecoveryRequired(
        "AEP database requires recovery. Data preserved - nothing was deleted.\n"
        f"  data directory: {data_dir}\n"
        f"  last connection error: {last_exc}\n"
        "\n"
        f"The local PostgreSQL server started but did not begin accepting\n"
        f"connections within {timeout_seconds:.0f}s. If it reported \"the database\n"
        "system is starting up\", it is replaying its write-ahead log after an\n"
        "unclean shutdown - that is normal recovery and it protects your data;\n"
        "simply run `aep start` again and allow it more time.\n"
        f"Otherwise inspect the PostgreSQL log at {data_dir / 'log'}.\n"
        "AEP will never delete this directory for you - doing so would destroy\n"
        "all local task/evidence/memory history. See BUGFIX.md BUG-0020."
    ) from last_exc
