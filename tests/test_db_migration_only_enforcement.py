"""Lint-style structural assertions (same convention as
tests/test_infra_threat_model.py / tests/test_operations_threat_model.py /
tests/test_runtime_threat_model.py): application/runtime code in
src/aep/ must never issue schema-mutating DDL directly - the ONLY place
allowed to do that is the migration runner (src/aep/db/migrations.py,
which itself only ever executes the contents of supabase/migrations/*.sql
files, never a DDL string literal of its own) and the migration files
themselves.
"""
from __future__ import annotations

import re
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "aep"
MIGRATIONS_RUNNER = SRC / "db" / "migrations.py"

# Phase 1-8's SQLite StateStore (src/aep/state_store.py) predates this
# Stage A migration discipline and is explicitly out of scope: this task
# does not touch Phase 1-8 behavior, and that module's `CREATE TABLE IF
# NOT EXISTS ...` schema is its own long-standing, already-tested
# mechanism for a DIFFERENT database (SQLite, not the new PostgreSQL
# schema this enforcement test protects). Migration-only enforcement
# applies to the NEW `src/aep/db/` package and everything else in
# src/aep/ that might one day talk to PostgreSQL - not retroactively to
# the pre-existing SQLite path.
_EXEMPT = {MIGRATIONS_RUNNER, SRC / "state_store.py"}

_DDL_PATTERN = re.compile(
    r"""(CREATE\s+TABLE|ALTER\s+TABLE|DROP\s+TABLE|CREATE\s+INDEX)""",
    re.IGNORECASE,
)


def _all_py_files_except_runner():
    for p in sorted(SRC.rglob("*.py")):
        if p in _EXEMPT:
            continue
        yield p


def test_no_schema_mutating_ddl_literal_outside_migration_runner():
    offenders = []
    for path in _all_py_files_except_runner():
        text = path.read_text()
        for m in _DDL_PATTERN.finditer(text):
            offenders.append(f"{path.relative_to(SRC)}: {m.group(0)!r}")
    assert offenders == [], (
        "Found schema-mutating DDL string literals outside the migration "
        f"runner: {offenders}"
    )


def test_migration_runner_itself_never_hardcodes_ddl_it_only_executes_files_on_disk():
    """The runner module's OWN source may reference these words only in
    the tracking-table bootstrap (schema_migrations) and in comments/
    docstrings/regex used for drift detection - it must never contain a
    literal CREATE/ALTER/DROP TABLE for any of the *domain* tables (tasks,
    projects, events, findings, deployments, memory_records, ...). The one
    allowed exception is `CREATE TABLE IF NOT EXISTS schema_migrations`,
    the bookkeeping table itself, which every migration tool needs before
    it can track anything."""
    text = MIGRATIONS_RUNNER.read_text()
    domain_tables = [
        "tasks", "projects", "events", "findings", "deployments",
        "memory_records", "runtime_workers", "runtime_leases",
        "incidents", "artifacts", "release_gates",
    ]
    for m in _DDL_PATTERN.finditer(text):
        # Grab a short window after the match to see which table (if any) it names.
        window = text[m.end():m.end() + 60]
        for table in domain_tables:
            assert table not in window, (
                f"migrations.py contains a hardcoded DDL statement referencing "
                f"domain table {table!r} - all domain DDL must live only in "
                f"supabase/migrations/*.sql"
            )


def test_every_migration_file_has_a_sequential_id_and_header_comment_block():
    migrations_dir = SRC.parent.parent / "supabase" / "migrations"
    files = sorted(migrations_dir.glob("*.sql"))
    assert files, "expected at least one migration file"
    for f in files:
        assert re.match(r"^\d{4}_\w+\.sql$", f.name), f"{f.name} does not follow NNNN_name.sql convention"
        text = f.read_text()
        assert "-- Migration:" in text
        assert "Purpose" in text
        assert "Backward-compatibility" in text
        assert "Rollback" in text
