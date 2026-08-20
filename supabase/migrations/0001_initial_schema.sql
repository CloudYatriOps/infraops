-- Migration: 0001_initial_schema
-- Purpose: Stage A (Phase 9 "Product Foundation & Governance", subphase
--   "PostgreSQL Foundation") canonical schema. This is the FIRST versioned
--   migration for the platform's new PostgreSQL persistence layer -
--   NOT a replacement for the existing SQLite `StateStore`
--   (src/aep/state_store.py), which remains Phase 1-8's tested production
--   path. See ARCHITECTURE.md Section 30 for the full existing-state
--   inventory -> PostgreSQL mapping and the reasoning behind every choice
--   below.
--
-- Affected tables (all new - this is the first migration, nothing to ALTER):
--   schema_migrations, projects, tasks, events, runtime_workers,
--   runtime_leases, runtime_project_locks, runtime_schedules, incidents,
--   incident_events, findings, deployments, release_gates, artifacts,
--   memory_records.
--
-- Design conventions (apply to every table in this file):
--   * Primary keys are `uuid`, generated application-side with Python's
--     `uuid.uuid4()` (never `gen_random_uuid()`/`uuid-ossp`) - this matches
--     the ID-generation convention already used everywhere in
--     src/aep/state_store.py and src/aep/models.py (str(uuid.uuid4())),
--     so there is exactly one place in the whole platform that mints IDs,
--     not two different mechanisms for two different stores.
--   * Timestamps are `timestamptz`, always written as UTC from
--     Python's `datetime.now(timezone.utc)` - same as `now_iso()` today.
--   * Free-form/variable-shape data (evidence, metadata, JSON payloads)
--     is `jsonb`, matching the "serialize the dataclass as JSON" pattern
--     `Task.to_json()`/`Event.to_json()` already use for SQLite's TEXT
--     columns - moving to jsonb keeps the exact same data shape but makes
--     it queryable/indexable natively.
--   * Enum-like fields use `text` + a `CHECK (... IN (...))` constraint
--     rather than a native Postgres `ENUM` type. Reason: Postgres ENUMs
--     require `ALTER TYPE ... ADD VALUE` (which cannot run inside a
--     transaction in older Postgres and is awkward to migrate/rollback)
--     every time a phase adds a new enum member - and this platform adds
--     enum members almost every phase (see FailureClass/EventCategory
--     growing across Phases 1-8 in src/aep/models.py). A CHECK constraint
--     is dropped/recreated by a normal, transactional, rollback-safe
--     migration instead. This is a deliberate, documented choice, not an
--     oversight.
--
-- Backward-compatibility notes:
--   * This schema does not read, write, or migrate any existing local
--     SQLite `aep_state.db` file. Stage A treats this as a foundation/dev
--     environment, not a customer production system with real data to
--     preserve yet - no automatic SQLite -> Postgres data migration exists
--     or is planned. This assumption is stated explicitly here and in
--     ARCHITECTURE.md/docs/DATABASE.md rather than silently decided.
--   * No existing src/aep/*.py runtime code path is changed by this
--     migration. The orchestrator's default StateStore is still SQLite;
--     wiring Phase 1-8 call sites over to this Postgres schema is
--     explicitly OUT of Stage A's scope (see ARCHITECTURE.md Section 30,
--     "Cutover tension").
--
-- Rollback notes:
--   * Rollback = `DROP TABLE IF EXISTS <name> CASCADE;` for every table
--     below, in reverse dependency order (memory_records, artifacts,
--     release_gates, deployments, findings, incident_events, incidents,
--     runtime_schedules, runtime_project_locks, runtime_leases,
--     runtime_workers, events, tasks, projects), followed by
--     `DELETE FROM schema_migrations WHERE id = '0001_initial_schema';`.
--     No data-preserving rollback is provided/needed - Stage A has no
--     production data in this schema yet (see compatibility note above).
--     The migration runner does not automate rollback execution; this is
--     a documented manual procedure, consistent with the runner's stated
--     scope (apply/status/validate only - see src/aep/db/migrations.py).

-- Migration bookkeeping table. The runner itself also knows how to create
-- this (so `status`/`validate` work before any migration has run), but it
-- is declared here too so a fresh database's schema is fully described by
-- the migration files alone.
CREATE TABLE IF NOT EXISTS schema_migrations (
    id text PRIMARY KEY,
    checksum text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);

-- Generalizes the existing `ProjectConfig` dataclass (src/aep/models.py).
CREATE TABLE projects (
    id uuid PRIMARY KEY,
    name text NOT NULL,
    repo_path text NOT NULL,
    policy_path text NOT NULL,
    default_posture text NOT NULL DEFAULT 'deny' CHECK (default_posture IN ('allow', 'deny')),
    protected_branches jsonb NOT NULL DEFAULT '["main", "master"]'::jsonb,
    token_budget bigint,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Generalizes the existing `Task`/`TaskStatus` dataclasses and the SQLite
-- `tasks` table's (project_id, status) hot query path.
CREATE TABLE tasks (
    id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(id),
    type text NOT NULL,
    status text NOT NULL CHECK (status IN (
        'PENDING', 'READY', 'RUNNING', 'SUCCEEDED', 'FAILED',
        'RETRY_SCHEDULED', 'BLOCKED_ON_APPROVAL', 'CANCELLED', 'QUARANTINED'
    )),
    priority integer NOT NULL DEFAULT 5,
    risk text NOT NULL DEFAULT 'low' CHECK (risk IN ('low', 'medium', 'high')),
    dependencies jsonb NOT NULL DEFAULT '[]'::jsonb,
    owner_agent text,
    attempts integer NOT NULL DEFAULT 0,
    max_attempts integer NOT NULL DEFAULT 3,
    evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
    artifacts jsonb NOT NULL DEFAULT '[]'::jsonb,
    approval_status text,
    parent_task_id uuid REFERENCES tasks(id),
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_tasks_project_status ON tasks(project_id, status);
CREATE INDEX idx_tasks_parent ON tasks(parent_task_id);

-- Generalizes the existing SQLite `events` table - the single append-only
-- audit/evidence log every phase already writes durable facts to
-- (StateStore.append_event / Event dataclass). Deliberately NOT split into
-- a separate "task_events" table: Phase 1-8 never distinguished "a task
-- event" from "an audit event" - a task_id is simply nullable on the same
-- row today, and duplicating that as two tables would just require a
-- UNION for every existing query (e.g. "all events for project X").
CREATE TABLE events (
    id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(id),
    task_id uuid REFERENCES tasks(id),
    actor text NOT NULL,
    action text NOT NULL,
    decision text,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    "timestamp" timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_events_project ON events(project_id);
CREATE INDEX idx_events_task ON events(task_id);
CREATE INDEX idx_events_timestamp ON events("timestamp");

-- Phase 8 runtime concepts - worker registrations.
CREATE TABLE runtime_workers (
    worker_id text PRIMARY KEY,
    supervisor_id text NOT NULL,
    status text NOT NULL CHECK (status IN ('IDLE', 'BUSY', 'STOPPED')),
    last_heartbeat timestamptz NOT NULL,
    started_at timestamptz NOT NULL,
    restart_count integer NOT NULL DEFAULT 0
);

-- Phase 8: durable exclusive task leases. UNIQUE task_id (one lease per
-- task, same invariant runtime_leases.task_id PRIMARY KEY enforces in
-- SQLite today).
CREATE TABLE runtime_leases (
    task_id uuid PRIMARY KEY REFERENCES tasks(id),
    project_id uuid NOT NULL REFERENCES projects(id),
    worker_id text NOT NULL REFERENCES runtime_workers(worker_id),
    acquired_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX idx_runtime_leases_expires ON runtime_leases(expires_at);

-- Phase 8: per-project mutating-work lock.
CREATE TABLE runtime_project_locks (
    project_id uuid PRIMARY KEY REFERENCES projects(id),
    worker_id text NOT NULL REFERENCES runtime_workers(worker_id),
    task_id uuid NOT NULL REFERENCES tasks(id),
    acquired_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);

-- Phase 8: durable recurring-job scheduler.
CREATE TABLE runtime_schedules (
    job_id text PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(id),
    job_type text NOT NULL,
    interval_seconds double precision NOT NULL,
    next_run_at timestamptz NOT NULL,
    last_run_at timestamptz,
    last_status text CHECK (last_status IN ('OK', 'FAILED') OR last_status IS NULL),
    consecutive_failures integer NOT NULL DEFAULT 0
);
CREATE INDEX idx_runtime_schedules_due ON runtime_schedules(next_run_at);

-- Generalizes Phase 7's operations/incident memory concepts
-- (src/aep/operations/models.py OperationalEvent + the incident grouping
-- operations/memory.py builds on top of it).
CREATE TABLE incidents (
    id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(id),
    category text NOT NULL,
    severity text NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    environment text,
    service text,
    status text NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'MITIGATED', 'CLOSED', 'ESCALATED')),
    root_cause_category text,
    root_cause_confidence text CHECK (root_cause_confidence IN (
        'CONFIRMED', 'HIGH_CONFIDENCE', 'LIKELY', 'POSSIBLE', 'UNKNOWN'
    ) OR root_cause_confidence IS NULL),
    evidence_ref text,
    summary text NOT NULL DEFAULT '',
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    opened_at timestamptz NOT NULL DEFAULT now(),
    closed_at timestamptz
);
CREATE INDEX idx_incidents_project_status ON incidents(project_id, status);

-- Individual correlated operational events belonging to an incident.
CREATE TABLE incident_events (
    id uuid PRIMARY KEY,
    incident_id uuid REFERENCES incidents(id),
    project_id uuid NOT NULL REFERENCES projects(id),
    category text NOT NULL,
    severity text NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    environment text,
    service text,
    detail text NOT NULL DEFAULT '',
    correlation_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    evidence_ref text,
    "timestamp" timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_incident_events_incident ON incident_events(incident_id);

-- Normalized findings table. Phase 4's SecurityFinding (security/models.py)
-- and Phase 3's VulnerabilityFinding (dependency/models.py) both map here
-- via a shared `category` column (secret/sast/iac/container/kubernetes/
-- helm from Phase 4-5, plus 'dependency' and 'infrastructure' added for
-- Phase 3/5's own finding shapes) rather than one table per category:
-- every one of these findings is queried/filtered/prioritized the exact
-- same way today (severity, status, project, task linkage - see
-- runtime/priority.py::score() treating "severity" uniformly regardless
-- of which phase produced the finding). Splitting them into 7 tables
-- would mean every future cross-category query (e.g. "all CRITICAL
-- findings for project X regardless of scanner") needs a 7-way UNION for
-- no benefit - the fields that differ between categories (e.g. a CVE id
-- vs a Terraform resource path) already live inside the existing
-- dataclasses' free-form fields and map cleanly to this table's `resource`
-- text field / `evidence` jsonb blob.
CREATE TABLE findings (
    id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(id),
    category text NOT NULL CHECK (category IN (
        'secret', 'sast', 'iac', 'container', 'kubernetes', 'helm',
        'dependency', 'infrastructure'
    )),
    severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    status text NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'REMEDIATED', 'SUPPRESSED', 'FALSE_POSITIVE')),
    resource text,
    description text NOT NULL DEFAULT '',
    confidence text,
    false_positive boolean NOT NULL DEFAULT false,
    task_id uuid REFERENCES tasks(id),
    evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
    discovered_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_findings_project_severity ON findings(project_id, severity);
CREATE INDEX idx_findings_project_category_status ON findings(project_id, category, status);

-- Generalizes Phase 6's DeploymentRecord (deployment/models.py).
CREATE TABLE deployments (
    id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(id),
    task_id uuid REFERENCES tasks(id),
    commit_sha text NOT NULL,
    artifact_id text,
    environment text NOT NULL,
    release_gates_passed boolean NOT NULL DEFAULT false,
    approval_status text NOT NULL DEFAULT 'not_required' CHECK (approval_status IN (
        'not_required', 'pending', 'granted', 'denied'
    )),
    provider text NOT NULL,
    provider_status text NOT NULL CHECK (provider_status IN ('REAL', 'MOCKED', 'UNAVAILABLE', 'BLOCKED')),
    rollout_status text NOT NULL DEFAULT 'NOT_STARTED',
    rollback_status text NOT NULL DEFAULT 'NOT_ATTEMPTED',
    final_state text NOT NULL DEFAULT 'PLANNED' CHECK (final_state IN (
        'PLANNED', 'APPROVAL_PENDING', 'DEPLOYED', 'VERIFIED', 'FAILED', 'ROLLED_BACK', 'BLOCKED'
    )),
    notes jsonb NOT NULL DEFAULT '[]'::jsonb,
    started_at timestamptz NOT NULL DEFAULT now(),
    ended_at timestamptz
);
CREATE INDEX idx_deployments_project_environment ON deployments(project_id, environment);

-- Release gate results for a deployment (Phase 6 cicd/release_gates.py).
CREATE TABLE release_gates (
    id uuid PRIMARY KEY,
    deployment_id uuid NOT NULL REFERENCES deployments(id),
    name text NOT NULL,
    passed boolean NOT NULL,
    detail text NOT NULL DEFAULT '',
    evaluated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_release_gates_deployment ON release_gates(deployment_id);

-- Build artifacts referenced by a deployment (Phase 6 cicd/artifact.py).
CREATE TABLE artifacts (
    id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(id),
    deployment_id uuid REFERENCES deployments(id),
    artifact_ref text NOT NULL,
    kind text NOT NULL,
    commit_sha text,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_artifacts_project ON artifacts(project_id);

-- Stage A memory architecture slice: ONE table with a `memory_class`
-- column for all 6 memory classes (PROJECT/ENGINEERING/SECURITY/
-- OPERATIONAL/ARCHITECTURAL/USER_ORG), not 6 tables. Justification: every
-- memory class needs the exact same operations (structured metadata
-- lookup, semantic ANN search, exact fingerprint lookup, supersession,
-- advisory retrieval) - the only thing that varies is a label used to
-- scope a query, which is one indexed column, not a schema difference.
-- Splitting now would also pre-judge Stage B/C/D governance design before
-- it exists. `org_scope` is nullable and unused by Stage A (no
-- organizations table exists yet - see ARCHITECTURE.md Section 30) -
-- explicitly deferred, not silently omitted.
CREATE TABLE memory_records (
    id uuid PRIMARY KEY,
    memory_class text NOT NULL CHECK (memory_class IN (
        'PROJECT_MEMORY', 'ENGINEERING_MEMORY', 'SECURITY_MEMORY',
        'OPERATIONAL_MEMORY', 'ARCHITECTURAL_MEMORY', 'USER_ORG_MEMORY'
    )),
    project_scope uuid REFERENCES projects(id),
    org_scope uuid,  -- deferred: no organizations table in Stage A
    content jsonb NOT NULL DEFAULT '{}'::jsonb,
    embedding vector(8),  -- Stage A proves the column/ANN query works;
                          -- real embedding generation is NOT_IMPLEMENTED
                          -- (see docs/MEMORY.md). Dimension 8 is a
                          -- deliberately small placeholder for this
                          -- stage's test vectors, not a production model
                          -- dimension - changing it later is an additive
                          -- migration.
    fingerprint text,     -- exact-match retrieval key (e.g. a content hash)
    evidence_ref text,
    confidence double precision NOT NULL DEFAULT 0.5,
    source text NOT NULL,
    lifecycle_state text NOT NULL DEFAULT 'ACTIVE' CHECK (lifecycle_state IN (
        'ACTIVE', 'SUPERSEDED', 'ARCHIVED', 'RETRACTED'
    )),
    superseded_by uuid REFERENCES memory_records(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_memory_class_scope ON memory_records(memory_class, project_scope);
CREATE INDEX idx_memory_fingerprint ON memory_records(fingerprint);
-- ANN index for cosine-similarity search. ivfflat (not hnsw) is used
-- because pgvector 0.6.0 (confirmed installed in this sandbox) supports
-- ivfflat unconditionally; hnsw requires >=0.5.0 build options that were
-- not verified here - ivfflat is the safe, portable choice for Stage A.
CREATE INDEX idx_memory_embedding_ann ON memory_records
    USING ivfflat (embedding vector_cosine_ops) WITH (lists = 10);
