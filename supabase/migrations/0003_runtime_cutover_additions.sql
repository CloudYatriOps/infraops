-- Migration: 0003_runtime_cutover_additions
-- Purpose: Stage A.5 (PostgreSQL Runtime Cutover) audit found that
--          `state_store.py`'s `failure_counters` table (circuit-breaker
--          consecutive-failure/quarantine bookkeeping used by
--          `src/aep/failure.py` via the orchestrator) has NO equivalent
--          table in the Postgres schema declared by 0001/0002. Every
--          other SQLite table used by the runtime (tasks, events,
--          runtime_workers, runtime_leases, runtime_project_locks,
--          runtime_schedules) already has a 0001 Postgres counterpart;
--          this was the one genuine gap the audit turned up. Phase 6
--          (deployment evidence) and Phase 7 (incident memory) persist
--          exclusively through StateStore today (tasks/events tables),
--          so no additional tables are needed for those.
-- Affected tables: adds `failure_counters` only.
-- Backward-compatibility notes: purely additive; no existing table or
--   column is touched. Safe to apply on a live database with zero
--   downtime.
-- Rollback: `DROP TABLE IF EXISTS failure_counters;` (no other object
--   depends on it).

CREATE TABLE failure_counters (
    project_id uuid NOT NULL REFERENCES projects(id),
    task_type text NOT NULL,
    consecutive_failures integer NOT NULL DEFAULT 0,
    quarantined boolean NOT NULL DEFAULT false,
    PRIMARY KEY (project_id, task_type)
);
