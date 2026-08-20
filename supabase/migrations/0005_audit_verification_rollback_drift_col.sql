-- Migration: 0005_audit_verification_rollback_drift_col
-- Purpose: Repair an INTENTIONAL out-of-band drift introduced during the
--          Stage A.5 Final Acceptance Audit (a raw `ALTER TABLE tasks ADD
--          COLUMN audit_drift_col text` was run directly, bypassing the
--          migration runner on purpose, to prove startup's schema-drift
--          gate actually blocks it). This migration is the sanctioned
--          way to restore the schema - a manual DROP COLUMN would itself
--          be another out-of-band mutation.
-- Affected tables: tasks (drops the test-only audit_drift_col)
-- Backward-compatibility notes: safe - audit_drift_col was never part of
--   the declared schema, carried no application data, no code reads it.
-- Rollback: not applicable; there is no legitimate reason to re-add it.

ALTER TABLE tasks DROP COLUMN IF EXISTS audit_drift_col;
