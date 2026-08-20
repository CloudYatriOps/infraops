"""Startup verification gate for the PostgreSQL-backed state store.

Called from `PostgresStateStore.__init__`/`connect()` (see
`state_store_postgres.py`) BEFORE any repository is constructed, so it is
not possible to end up "running" against a database that is unreachable
or whose schema has drifted from what the migration files on disk
declare - it raises a typed, specific exception instead of proceeding
silently.

No raw schema-mutating DDL lives here (this module only ever calls
`migrations.status/validate/drift_report`, which run read-only queries
plus, in `apply_pending`, execute the migration *files* themselves - not
a literal here), so it is not subject to (and does not need an exemption
from) the migration-only-enforcement lint test.
"""
from __future__ import annotations

import psycopg2

from . import migrations


class DatabaseUnavailableError(RuntimeError):
    """Raised when a real TCP/auth connection to PostgreSQL cannot be
    established. Never caught-and-ignored anywhere in this platform -
    the caller must handle it explicitly (e.g. fail fast at process
    startup)."""


class SchemaDriftError(RuntimeError):
    """Raised when the live schema does not match what the migration
    files on disk declare - either pending migrations were never applied,
    an applied migration's on-disk content has been tampered with, or an
    out-of-band DDL statement (bypassing the migration runner) mutated
    the live schema. Proceeding in this state risks silently reading/
    writing a schema the code doesn't actually match."""


def verify_database(dsn: str, connect_timeout: int = 5) -> None:
    """Real connection + real migration-state check. Raises
    `DatabaseUnavailableError` or `SchemaDriftError` instead of returning
    anything when the database is not safe to use; returns None (success)
    otherwise."""
    try:
        conn = psycopg2.connect(dsn, connect_timeout=connect_timeout)
    except Exception as exc:  # noqa: BLE001 - re-raised as our typed error
        raise DatabaseUnavailableError(
            f"could not connect to PostgreSQL: {exc}"
        ) from exc

    try:
        try:
            mig_status = migrations.status(conn)
        except Exception as exc:  # noqa: BLE001
            raise DatabaseUnavailableError(
                f"connected, but failed to query migration status: {exc}"
            ) from exc

        pending = [m.id for m in mig_status if not m.applied]
        if pending:
            raise SchemaDriftError(
                f"pending migrations have not been applied: {pending}. "
                "Run the migration runner's apply_pending() before starting."
            )

        checksum_problems = migrations.validate(conn)
        if checksum_problems:
            raise SchemaDriftError(
                "applied-migration checksum mismatch (on-disk migration file(s) "
                f"tampered with since being applied): {checksum_problems}"
            )

        report = migrations.drift_report(conn)
        if report.status != "MATCH":
            raise SchemaDriftError(
                f"live schema has drifted from migration files: {report.details}"
            )
    finally:
        conn.close()
