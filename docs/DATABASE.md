# Database & Migrations (Phase 9 Stage A)

This document describes the PostgreSQL persistence foundation added in
Phase 9 Stage A. It does **not** describe a completed cutover: the
existing SQLite `StateStore` (`src/aep/state_store.py`) remains Phase
1-8's tested, default production path. This document is about the new,
parallel, real-and-tested canonical schema built as the foundation for a
future cutover - see ARCHITECTURE.md Section 30 for the full design
discussion.

## Layout

- `supabase/migrations/` - the single source of truth for the PostgreSQL
  schema. Each file is `NNNN_name.sql` with a header comment block
  (purpose, affected tables, backward-compatibility notes, rollback
  notes).
- `src/aep/db/migrations.py` - the migration runner. Applies pending
  migrations, tracks them in a `schema_migrations` table (id, checksum,
  applied_at), refuses to proceed if an already-applied migration's
  on-disk content no longer matches its recorded checksum (drift/tamper
  detection), and can report live-schema drift by querying
  `information_schema`.
- `src/aep/db/models.py` - Postgres-API-agnostic domain dataclasses.
- `src/aep/db/repositories.py` - repository interfaces (ABCs) per
  aggregate (Project/Task/Event/Lease/Finding/Memory).
- `src/aep/db/postgres.py` - the real psycopg2-backed implementation. This
  is the **only** module in the platform allowed to hold raw SQL for these
  aggregates.
- `src/aep/db/fake.py` - an in-memory test double implementing the same
  interfaces, used by fast unit tests with zero network dependency.

## Running migrations locally

```python
import psycopg2
from aep.db import migrations

conn = psycopg2.connect(
    "host=localhost port=5432 user=aep password=aep_local_dev_only dbname=aep_platform"
)
migrations.apply_pending(conn)          # applies every pending migration
print(migrations.status(conn))          # what's applied/pending
print(migrations.validate(conn))        # [] if clean, else checksum-drift problems
print(migrations.drift_report(conn))    # compares live schema vs. migration files
```

A local PostgreSQL 16 server with the `vector` (pgvector) extension is
expected at `localhost:5432`, database `aep_platform`, role `aep`. This is
the same real, locally-running Postgres the Stage A integration tests use
(`tests/test_db_migrations.py`, `tests/test_db_repositories_postgres.py`,
`tests/test_db_schema_drift.py`) - they skip gracefully (with an explicit
reason) if it isn't reachable, never fake a pass.

## Migration-only enforcement

Application/runtime code may never issue `CREATE TABLE`/`ALTER TABLE`/
`DROP TABLE`/`CREATE INDEX` directly - only the migration runner (which
itself only ever executes the contents of files in
`supabase/migrations/`) is allowed to mutate schema. This is enforced by
a lint-style scan (`tests/test_db_migration_only_enforcement.py`, same
convention as `tests/test_infra_threat_model.py` etc.) that fails the
build if such a literal appears anywhere else in `src/aep/`. A
`database.schema_change` policy action was added to `config/policy.yaml`
as `REQUIRE_APPROVAL`, so any future agent-facing workflow that wraps
migration application is gated like every other structurally significant
action - it is not wired to anything yet in Stage A.

## Schema drift detection

`migrations.drift_report(conn)` queries the live database's
`information_schema.tables`/`information_schema.columns` and compares
them against a lightweight structural parse of the migration files on
disk, returning `MATCH` or `DRIFT` with specifics (missing/extra tables,
missing/extra columns per table). This was verified for real: applying
migrations cleanly reports `MATCH`; then running a raw, out-of-band
`ALTER TABLE tasks ADD COLUMN foo text` via `psycopg2.execute()` (bypassing
the runner entirely) causes the very next `drift_report()` call to report
`DRIFT`, naming the `foo` column specifically
(`tests/test_db_schema_drift.py::test_out_of_band_alter_table_is_flagged_as_drift`).

## Schema overview

See `supabase/migrations/0001_initial_schema.sql` for the authoritative,
fully-commented definition. Summary:

| Table | Purpose |
|---|---|
| `schema_migrations` | Migration bookkeeping (id, checksum, applied_at). |
| `projects` | Generalizes `ProjectConfig`. |
| `tasks` | Generalizes `Task`/`TaskStatus`. |
| `events` | Append-only audit/evidence log (generalizes SQLite `events`; covers both task-scoped and general audit events - Phase 1-8 never distinguished the two). |
| `runtime_workers` / `runtime_leases` / `runtime_project_locks` / `runtime_schedules` | Phase 8 runtime concepts. |
| `incidents` / `incident_events` | Phase 7 operations/incident memory concepts. |
| `findings` | Normalized findings across Phase 3/4/5 categories (secret/sast/iac/container/kubernetes/helm/dependency/infrastructure), via a `category` column rather than one table per category. |
| `deployments` / `release_gates` / `artifacts` | Phase 6 CI/CD & deployment concepts. |
| `memory_records` | Stage A memory architecture - see `docs/MEMORY.md`. |

## Connecting to Supabase (once network access exists)

A dedicated Supabase project for AEP exists (`SUPABASE_URL` /
`SUPABASE_DB_PASSWORD` stored only in `/home/claude/.secrets/aep_supabase.env`,
never in this repo). As of this writing, this sandbox's egress proxy
returns `403 Forbidden` on the HTTPS CONNECT tunnel to
`*.supabase.co:443`, and raw TCP connections to the Postgres/pooler
hostnames time out - a network-policy block, not a credentials problem.
`tests/test_db_supabase_real.py` contains a real (not mocked) connection
attempt using those credentials; it is expected to skip with that exact
reason in this environment. Once network access is available, pointing
the same `src/aep/db/postgres.py` adapter at Supabase requires only
constructing a DSN from `SUPABASE_URL`'s host plus `SUPABASE_DB_PASSWORD`
and passing `sslmode=require` - no code change is needed, only
configuration, because the persistence layer was written against the
`ProjectRepository`/`TaskRepository`/etc. interfaces, not against "local
Postgres" specifically.

## What Stage A deliberately does NOT do

- It does **not** migrate any existing local SQLite `aep_state.db` data
  into Postgres. This is treated as a foundation/dev environment, not a
  customer production system with real data to preserve - stated
  explicitly rather than silently decided.
- It does **not** cut the orchestrator's default `StateStore` over from
  SQLite to this Postgres layer. That is a separate, larger, riskier
  refactor named explicitly as the next stage's first item of work (see
  ARCHITECTURE.md Section 30, "Cutover tension").
- It does **not** implement organizations/users/skills/skill_versions/
  model_providers/model_runs/model_costs tables - those belong to Stages
  B/C/D.
- It does **not** implement full Row-Level-Security policies. `org_scope`
  on `memory_records` is nullable and unused (no organizations table
  exists yet); RLS is a documented foundation/plan, not fully built out -
  see ARCHITECTURE.md Section 30's RLS discussion.

## Independent verification pass

Stage A's migration/drift/checksum/repository/memory mechanisms were
re-run and independently confirmed end-to-end against a real local
Postgres in a follow-up session, including a full deliberate
MATCH→DRIFT→restore-via-migration→MATCH cycle and a live checksum-tamper
demonstration. See ARCHITECTURE.md Section 30a for the complete evidence
log. No regressions.

## Stage A.5: PostgreSQL Runtime Cutover (opt-in)

Stage A.5 adds an actual runtime path on top of Stage A's foundation:
`src/aep/db/state_store_postgres.py`'s `PostgresStateStore`, a facade
implementing the exact same public method surface as
`src/aep/state_store.py`'s SQLite `StateStore` (`save_task`, `get_task`,
`list_tasks`, `acquire_lease`, `append_event`, etc. - the complete
runtime contract). It is built on the full Project/Task/Event/Lease/
Finding/Memory/ProjectLock/Worker/Schedule/FailureCounter repositories in
`src/aep/db/postgres.py`, backed by migrations `0001`-`0005` (`0005` was
added during the Stage A.5 final acceptance audit to repair an
intentional out-of-band drift test, following the same
migration-only-repair discipline as `0002`/`0004`). See
ARCHITECTURE.md Section 31 for the full design writeup, including the
facade's three documented limitations (UUID-only ids, Python-side
multi-status filtering, and FK provisioning requirements), the
concurrency bug found and fixed (`BUGFIX.md` BUG-0001), this pass's
crash/recovery and concurrent-facade-instance proofs, and Section 31b
for the independent final acceptance audit (STAGE_A5_COMPLETE).

### Enabling it (and the default, as of the current pass)

**As of the current pass, PostgreSQL is the default backend.** Every
caller - `cli.py` (all 14 former direct `StateStore(...)` sites),
`build_orchestrator` in `bootstrap.py`, and anything else that
constructs a durable store - goes through the single canonical
`src/aep/db/factory.py::build_state_store(db_path, db_backend=None)`,
which resolves the backend as: explicit `db_backend` argument wins;
else the `AEP_DB_BACKEND` env var; else **`"postgres"`**.

SQLite is used only when something explicitly asks for it:

- Pass `db_backend="sqlite"` to `build_state_store`/`build_orchestrator`, or
- Set `AEP_DB_BACKEND=sqlite`.

Both selections (Postgres and SQLite) fail loudly rather than silently
falling back - choosing Postgres and having it be unreachable raises
`DatabaseUnavailableError`/`SchemaDriftError`, it never quietly hands
back a working SQLite store instead, even now that SQLite is sitting
right there as a possibility (proven in
`tests/test_db_startup_gate.py::test_default_still_raises_dbunavailable_when_postgres_down_not_silent_fallback`).

Connection is configured via env vars, read by
`state_store_postgres.dsn_from_env()`:

- `AEP_POSTGRES_DSN` - a full DSN string, used verbatim if set (takes
  priority over everything below).
- Otherwise, built from parts: `AEP_PG_HOST` (default `localhost`),
  `AEP_PG_PORT` (default `5432`), `AEP_PG_USER` (default `aep`),
  `AEP_PG_PASSWORD` (default empty - always supply this explicitly in
  any real environment), `AEP_PG_DBNAME` (default `aep_platform`),
  `AEP_PG_SSLMODE` (unset by default; set to `require` for Supabase or
  any TLS-required Postgres).

### Startup gate

Every `PostgresStateStore()` construction runs
`src/aep/db/startup.py`'s `verify_database()` first - before any
repository is built - which:

1. Attempts a real connection; raises `DatabaseUnavailableError` if it
   cannot connect (wrong host/port/credentials, network down, Postgres
   not running).
2. Checks migration status and live-schema drift; raises
   `SchemaDriftError` if pending migrations exist, an applied
   migration's on-disk content has been tampered with, or the live
   schema doesn't match the migration files on disk.

There is **no silent fallback**: if `AEP_DB_BACKEND=postgres` is set and
either check fails, construction raises and the process should fail to
start, not quietly run against SQLite or a broken/undermigrated schema.
Three real proofs exist in `tests/test_db_startup_gate.py`: a normal
healthy-DB pass, a simulated outage (`DatabaseUnavailableError`), and a
simulated drift scenario (`SchemaDriftError`) - all run against real
local Postgres, not mocks.

### SQLite's remaining role (explicit opt-in only)

`StateStore` (SQLite) still exists in `src/aep/state_store.py` as a
fully supported, explicit opt-in (`db_backend="sqlite"` /
`AEP_DB_BACKEND=sqlite`) - it was never deleted, only removed from the
*default, unrequested* path. It remains genuinely useful for tests and
fixtures that rely on SQLite-specific looseness Postgres does not
replicate for free (schema-less ids, including non-UUID strings, and no
foreign-key provisioning requirement on tasks/leases/locks) - 17 test
files now pass `db_backend="sqlite"` explicitly for exactly this reason,
plus 5 CLI-status test files that set `AEP_DB_BACKEND=sqlite` at the
process/env boundary. See ARCHITECTURE.md §31a for the full accounting,
including the classification of every remaining `sqlite3`/direct-
`StateStore` reference left anywhere in `src/aep/`.

### Backup and recovery (Postgres path)

Once running on `AEP_DB_BACKEND=postgres`, standard PostgreSQL backup
and recovery practices apply unchanged - this is real Postgres, not a
bespoke store:

- **Logical backups**: `pg_dump`/`pg_dumpall` for point-in-time
  snapshots and portable restore.
- **Physical/continuous backups + PITR**: WAL archiving (`archive_mode`,
  `archive_command`) plus a base backup (`pg_basebackup`) enables
  point-in-time recovery to any moment covered by the WAL archive - the
  standard approach for a runtime state store where losing recent task/
  lease/event history matters.
- **Managed-provider equivalents** (e.g. Supabase's built-in daily
  backups + PITR add-on) satisfy the same requirement without
  operating WAL archiving directly, once Supabase network access is
  available (see "Connecting to Supabase" above).

None of this has been built or exercised in this repository - it is
documented here as an expectation/requirement for whoever operates the
Postgres path in a real environment, not as new work completed in
Stage A.5.

### Crash/recovery proof

`tests/test_db_crash_recovery.py` proves state survives a full
in-process "crash": a task is saved, a lease acquired, and an event
appended through one `PostgresStateStore` instance; every Python object
involved is then discarded (connection pool closed, references `del`ed,
`gc.collect()` forced) and a brand-new `PostgresStateStore` is
constructed against the same DSN, as a fresh process would. The new
instance reads back the identical task/lease/event state - no loss, no
duplication. The same file also proves the facade-level concurrent-
lease-acquisition guarantee: two threads, each with its own
`PostgresStateStore` (own connection pool), race `acquire_lease` for
the same task_id; exactly one gets `True` back through the facade, the
other cleanly gets `False` (no exception either way).
