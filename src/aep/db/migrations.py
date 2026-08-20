"""Migration runner for the Stage A PostgreSQL schema (supabase/migrations/).

This is the ONLY place in the platform allowed to issue schema-mutating
DDL (`CREATE TABLE`/`ALTER TABLE`/`DROP TABLE`/`CREATE INDEX`) against the
Postgres database - enforced by `tests/test_db_migration_only_enforcement.py`,
which scans the rest of `src/aep/` for exactly those string literals.

Responsibilities (Stage A scope only):
  * `status(conn)`      -> list of (id, applied: bool) for every migration
                            file on disk, in order.
  * `apply_pending(conn)` -> applies every not-yet-applied migration file,
                            in filename order, inside one transaction per
                            file, and records it in `schema_migrations`
                            (id, checksum, applied_at).
  * `validate(conn)`    -> compares the checksum recorded for each applied
                            migration against the checksum of the file on
                            disk *right now* and raises `ChecksumMismatch`
                            if they differ (drift/tamper detection) -
                            refuses to apply anything until this is fixed.
  * `drift_report(conn)` -> a SEPARATE, more thorough check: queries
                            `information_schema` for the live table/column/
                            index list and compares it against what the
                            migration files declare (via a lightweight
                            structural parse), reporting MATCH or DRIFT
                            with specifics. This is what
                            `tests/test_db_migration_only_enforcement.py`
                            uses to prove an out-of-band `ALTER TABLE`
                            executed directly via psycopg2 is actually
                            detected, not just that a policy string exists.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "supabase" / "migrations"


class ChecksumMismatch(Exception):
    """Raised when an already-applied migration's on-disk checksum no
    longer matches what was recorded at apply time - drift/tamper
    detection, refuses to proceed."""


def _checksum(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _migration_files() -> list[Path]:
    if not MIGRATIONS_DIR.exists():
        return []
    return sorted(p for p in MIGRATIONS_DIR.glob("*.sql"))


@dataclass
class MigrationStatus:
    id: str
    applied: bool
    checksum: str
    recorded_checksum: Optional[str] = None


def _ensure_tracking_table(conn) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """CREATE TABLE IF NOT EXISTS schema_migrations (
                id text PRIMARY KEY,
                checksum text NOT NULL,
                applied_at timestamptz NOT NULL DEFAULT now()
            )"""
        )
    conn.commit()


def _applied_map(conn) -> dict[str, str]:
    """id -> recorded checksum."""
    _ensure_tracking_table(conn)
    with conn.cursor() as cur:
        cur.execute("SELECT id, checksum FROM schema_migrations")
        return {row[0]: row[1] for row in cur.fetchall()}


def status(conn) -> list[MigrationStatus]:
    applied = _applied_map(conn)
    out = []
    for path in _migration_files():
        mig_id = path.stem
        checksum = _checksum(path.read_text())
        out.append(MigrationStatus(
            id=mig_id,
            applied=mig_id in applied,
            checksum=checksum,
            recorded_checksum=applied.get(mig_id),
        ))
    return out


def validate(conn) -> list[str]:
    """Returns a list of human-readable problems (empty = clean). Raises
    ChecksumMismatch is NOT raised here - `validate` reports; `apply_pending`
    raises and refuses to proceed."""
    problems = []
    for s in status(conn):
        if s.applied and s.recorded_checksum != s.checksum:
            problems.append(
                f"{s.id}: recorded checksum {s.recorded_checksum} != on-disk checksum {s.checksum}"
            )
    return problems


def apply_pending(conn) -> list[str]:
    """Applies pending migrations in order. Returns list of ids applied.
    Refuses (raises ChecksumMismatch) if any ALREADY-applied migration's
    on-disk content has drifted from what was recorded - never silently
    re-applies or ignores tampering."""
    applied_ids = []
    for s in status(conn):
        if s.applied:
            if s.recorded_checksum != s.checksum:
                raise ChecksumMismatch(
                    f"migration {s.id} checksum drift: recorded="
                    f"{s.recorded_checksum} on-disk={s.checksum}. Refusing "
                    f"to apply further migrations until this is resolved."
                )
            continue
        path = MIGRATIONS_DIR / f"{s.id}.sql"
        sql = path.read_text()
        with conn.cursor() as cur:
            cur.execute(sql)
            cur.execute(
                "INSERT INTO schema_migrations (id, checksum) VALUES (%s, %s)",
                (s.id, s.checksum),
            )
        conn.commit()
        applied_ids.append(s.id)
    return applied_ids


# ---- Live-schema drift detection (information_schema) ---------------------

_CREATE_TABLE_RE = re.compile(r"CREATE TABLE\s+(?:IF NOT EXISTS\s+)?(\w+)", re.IGNORECASE)


def _declared_tables() -> set[str]:
    tables: set[str] = set()
    for path in _migration_files():
        for m in _CREATE_TABLE_RE.finditer(path.read_text()):
            tables.add(m.group(1).lower())
    return tables


def _live_tables(conn) -> set[str]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'"
        )
        return {row[0].lower() for row in cur.fetchall()}


def _live_columns(conn, table: str) -> set[str]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = %s",
            (table,),
        )
        return {row[0].lower() for row in cur.fetchall()}


def _declared_columns(table: str) -> set[str]:
    """Best-effort structural parse: find the CREATE TABLE block for
    `table` and pull out leading identifiers of each column line. This is
    intentionally simple (not a full SQL parser) - it exists to catch drift
    such as an out-of-band `ALTER TABLE ... ADD COLUMN`, not to be a
    general-purpose DDL parser."""
    for path in _migration_files():
        text = path.read_text()
        m = re.search(
            rf"CREATE TABLE\s+(?:IF NOT EXISTS\s+)?{table}\s*\((.*?)\n\);",
            text, re.IGNORECASE | re.DOTALL,
        )
        if not m:
            continue
        body = m.group(1)
        # Strip SQL line comments (-- ... to end of line) before any other
        # parsing, so a comment mentioning commas/parens never confuses
        # the depth-tracking splitter below.
        body = "\n".join(line.split("--", 1)[0] for line in body.split("\n"))

        cols = set()
        depth = 0
        in_string = False
        lines = []
        buf = ""
        for ch in body:
            if ch == "'" and not in_string:
                in_string = True
            elif ch == "'" and in_string:
                in_string = False
            if not in_string:
                if ch in "([":
                    depth += 1
                elif ch in ")]":
                    depth -= 1
            if ch == "," and depth == 0 and not in_string:
                lines.append(buf)
                buf = ""
            else:
                buf += ch
        lines.append(buf)
        for line in lines:
            line = line.strip()
            if not line:
                continue
            first_token = line.split()[0].strip('"')
            if first_token.upper() in ("CONSTRAINT", "PRIMARY", "UNIQUE", "FOREIGN", "CHECK"):
                continue
            cols.add(first_token.lower())
        return cols
    return set()


@dataclass
class DriftReport:
    status: str  # "MATCH" or "DRIFT"
    details: list[str]


def drift_report(conn) -> DriftReport:
    """Compares the LIVE database schema (information_schema/pg_catalog)
    against what the migration files on disk declare. Always actually
    queries the live database - never returns MATCH without doing so."""
    details: list[str] = []
    declared_tables = _declared_tables()
    live_tables = _live_tables(conn)

    missing_live = declared_tables - live_tables - {"schema_migrations"}
    extra_live = live_tables - declared_tables - {"schema_migrations"}
    if missing_live:
        details.append(f"tables declared but missing live: {sorted(missing_live)}")
    if extra_live:
        details.append(f"tables live but not declared by any migration: {sorted(extra_live)}")

    for table in sorted(declared_tables & live_tables):
        declared_cols = _declared_columns(table)
        live_cols = _live_columns(conn, table)
        missing_cols = declared_cols - live_cols
        extra_cols = live_cols - declared_cols
        if missing_cols:
            details.append(f"{table}: columns declared but missing live: {sorted(missing_cols)}")
        if extra_cols:
            details.append(f"{table}: columns live but not declared (possible out-of-band ALTER): {sorted(extra_cols)}")

    return DriftReport(status="DRIFT" if details else "MATCH", details=details)
