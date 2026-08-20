-- Migration: 0007_api_auth
-- Purpose: Phase 9 Stage D (product API layer, Wave 1) minimal per-request
--   API-key authentication. Adds exactly one new table, `api_keys`, so the
--   thin HTTP API layer (src/aep/api/) can check a bearer key against a
--   durable, hashed record instead of any in-memory/hardcoded list.
--   Never stores the raw key - only a sha256 hash of it, so a leaked
--   database dump does not itself leak usable credentials.
-- Affected tables (new): api_keys.
-- Design conventions (matches 0001-0006): `key_id` is a `uuid` primary key
--   (application-side uuid.uuid4(), same as every other table).
--   `project_scope` is nullable and REFERENCES projects(id): NULL means
--   org-wide (any project), non-null scopes the key to exactly one
--   project - this is the minimal seed of the "organization/project
--   isolation" the production architecture is expected to grow into a
--   real org/user model later (see docs/API.md); this migration does not
--   attempt to build that model now, only the smallest real primitive it
--   needs today.
-- Backward-compatibility notes: purely additive, no existing table is
--   touched.
-- Rollback: `DROP TABLE IF EXISTS api_keys;` (a fresh migration, never a
--   hand rollback of this file).

CREATE TABLE IF NOT EXISTS api_keys (
    key_id        uuid PRIMARY KEY,
    key_hash      text NOT NULL UNIQUE,
    project_scope uuid REFERENCES projects(id) ON DELETE CASCADE,
    label         text NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now(),
    revoked_at    timestamptz
);

CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys (key_hash);
