-- Migration: 0006_skill_registry
-- Purpose: Phase 9 Stage B ("Canonical AEP Skill Registry & Claude Skill
--   Adapter") persistence. Adds the minimum tables genuinely justified by
--   the domain model: `skills` (stable identity), `skill_versions`
--   (immutable published content snapshots), and `skill_dependencies`
--   (one skill version's dependency edges on other skills). Deliberately
--   does NOT add separate `skill_capabilities`/`skill_tool_permissions`/
--   `skill_policies` tables - capabilities/allowed_tools/prohibited_actions/
--   required_checks/verification_rules/escalation_rules/
--   approval_requirements/input_contract/output_contract/examples/
--   compatibility_metadata all live as jsonb array/object columns on
--   `skill_versions` itself, following this schema's own established
--   convention (see 0001's module docstring: "free-form/variable-shape
--   data ... is jsonb"). None of these fields is ever queried/filtered on
--   independently of its owning skill_versions row in this stage - there
--   is no normalization benefit to splitting them into join tables, only
--   cost. `skill_dependencies` IS a separate table because dependency
--   edges are genuinely relational (many-to-many between skill versions
--   and skills) and Part 14's dependency-graph resolution needs to query
--   them independently of any one skill_versions row's jsonb blob.
--
-- Affected tables (all new): skills, skill_versions, skill_dependencies.
--
-- Design conventions (matches 0001-0005):
--   * Primary keys are `uuid` for skill_versions/skill_dependencies
--     (application-side `uuid.uuid4()`, same as every other table).
--     `skills.skill_id` is `text PRIMARY KEY` (not a uuid) because a
--     skill's identity is a short, stable, human-chosen slug
--     ("security", "postgresql", "kubernetes", ...) that other tables
--     and the canonical skill definitions in
--     `src/aep/skills/definitions.py` reference directly - inventing a
--     surrogate uuid for it would only add an indirection with no
--     benefit, the same reasoning `runtime_workers.worker_id text PRIMARY
--     KEY` and `runtime_schedules.job_id text PRIMARY KEY` already use
--     in 0001.
--   * Timestamps are `timestamptz`.
--   * jsonb for free-form/variable-shape fields.
--   * Enum-like fields (`risk_level`, `lifecycle_state`) use `text` +
--     `CHECK (... IN (...))`, not native Postgres ENUM - same reasoning
--     as 0001 (this platform adds enum members across phases; a CHECK
--     constraint is a normal transactional migration, `ALTER TYPE ...
--     ADD VALUE` is not).
--
-- Immutability enforcement (Stage B Part 4): a published skill_versions
--   row must never be mutated - publishing a correction is always a NEW
--   row (new `version` string), never an UPDATE of an existing one. This
--   is enforced at TWO layers, deliberately, not just one:
--     1. Application layer: `SkillRegistry.publish()` raises
--        `SkillImmutabilityError` if the (skill_id, version) pair already
--        exists, and `PostgresSkillVersionRepository.save()` uses
--        `INSERT ... ON CONFLICT (skill_id, version) DO NOTHING` + a
--        rowcount check (the same concurrency-safety discipline BUG-0001
--        established - never a bare INSERT), raising if the row already
--        existed.
--     2. Database layer (this migration): a BEFORE UPDATE trigger,
--        `skill_versions_prevent_mutation()`, rejects any UPDATE that
--        changes CONTENT on a row whose OLD.lifecycle_state was already
--        'published' - the only mutation a published row may ever
--        receive is the one-way transition to 'deprecated'
--        (lifecycle_state + deprecated_at). This exists so immutability
--        holds even against a caller that bypasses the Python repository
--        layer entirely (e.g. a raw psycopg2 UPDATE) - matching this
--        platform's "prove it at the layer an attacker/bug could actually
--        reach" discipline used elsewhere (see the migration-only
--        enforcement lint, tests/test_db_migration_only_enforcement.py).
--
-- Backward-compatibility notes: purely additive - no existing table is
--   altered, no existing code path changes behavior. Nothing in Phase 1-8
--   or Stage A/A.5 reads or writes these tables.
--
-- Rollback notes: `DROP TABLE IF EXISTS skill_dependencies, skill_versions
--   CASCADE; DROP FUNCTION IF EXISTS skill_versions_prevent_mutation()
--   CASCADE; DROP TABLE IF EXISTS skills CASCADE;` followed by
--   `DELETE FROM schema_migrations WHERE id = '0006_skill_registry';`. No
--   data-preserving rollback is provided/needed - Stage B has no
--   production data in this schema yet, same rationale as 0001-0005.

CREATE TABLE skills (
    skill_id text PRIMARY KEY,
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    purpose text NOT NULL DEFAULT '',
    scope text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE skill_versions (
    id uuid PRIMARY KEY,
    skill_id text NOT NULL REFERENCES skills(skill_id),
    version text NOT NULL,
    risk_level text NOT NULL DEFAULT 'low' CHECK (risk_level IN ('low', 'medium', 'high')),
    description text NOT NULL DEFAULT '',
    purpose text NOT NULL DEFAULT '',
    scope text NOT NULL DEFAULT '',
    capabilities jsonb NOT NULL DEFAULT '[]'::jsonb,
    allowed_tools jsonb NOT NULL DEFAULT '[]'::jsonb,
    prohibited_actions jsonb NOT NULL DEFAULT '[]'::jsonb,
    required_checks jsonb NOT NULL DEFAULT '[]'::jsonb,
    verification_rules jsonb NOT NULL DEFAULT '[]'::jsonb,
    escalation_rules jsonb NOT NULL DEFAULT '[]'::jsonb,
    approval_requirements jsonb NOT NULL DEFAULT '[]'::jsonb,
    input_contract jsonb NOT NULL DEFAULT '{}'::jsonb,
    output_contract jsonb NOT NULL DEFAULT '{}'::jsonb,
    examples jsonb NOT NULL DEFAULT '[]'::jsonb,
    lifecycle_state text NOT NULL DEFAULT 'draft' CHECK (lifecycle_state IN (
        'draft', 'published', 'deprecated'
    )),
    compatibility_metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    published_at timestamptz,
    deprecated_at timestamptz,
    UNIQUE (skill_id, version)
);
CREATE INDEX idx_skill_versions_skill ON skill_versions(skill_id);
CREATE INDEX idx_skill_versions_lifecycle ON skill_versions(skill_id, lifecycle_state);

-- Dependency edges: which OTHER skill (by stable skill_id, not a specific
-- version) a given skill_versions row depends on, plus a simple version
-- constraint string ("*", "==1.0.0", ">=1.0.0"). See Part 14 /
-- src/aep/skills/registry.py::resolve_dependencies for how these are
-- walked to detect missing/conflicting/cyclical dependencies.
CREATE TABLE skill_dependencies (
    id uuid PRIMARY KEY,
    skill_version_id uuid NOT NULL REFERENCES skill_versions(id),
    depends_on_skill_id text NOT NULL REFERENCES skills(skill_id),
    version_constraint text NOT NULL DEFAULT '*',
    UNIQUE (skill_version_id, depends_on_skill_id)
);
CREATE INDEX idx_skill_dependencies_version ON skill_dependencies(skill_version_id);

CREATE OR REPLACE FUNCTION skill_versions_prevent_mutation() RETURNS trigger AS $$
BEGIN
    IF OLD.lifecycle_state = 'published' THEN
        IF NEW.lifecycle_state NOT IN ('published', 'deprecated') THEN
            RAISE EXCEPTION 'skill_versions: cannot move a published version (%: %) to lifecycle_state %',
                OLD.skill_id, OLD.version, NEW.lifecycle_state;
        END IF;
        IF (to_jsonb(NEW) - 'lifecycle_state' - 'deprecated_at')
           IS DISTINCT FROM (to_jsonb(OLD) - 'lifecycle_state' - 'deprecated_at') THEN
            RAISE EXCEPTION 'skill_versions: published version content is immutable (skill_id=%, version=%)',
                OLD.skill_id, OLD.version;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_skill_versions_immutable
    BEFORE UPDATE ON skill_versions
    FOR EACH ROW EXECUTE FUNCTION skill_versions_prevent_mutation();
