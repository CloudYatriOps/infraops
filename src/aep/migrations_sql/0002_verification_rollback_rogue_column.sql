-- Migration: 0002_verification_rollback_rogue_column
-- Purpose: Restore schema after an INTENTIONAL out-of-band drift test.
--          During Stage A verification, a raw `ALTER TABLE incidents ADD
--          COLUMN rogue_column text` was executed directly against
--          Postgres (bypassing the migration mechanism on purpose) to
--          prove drift detection actually catches unauthorized schema
--          changes. This migration is the ONLY sanctioned way to restore
--          the schema afterward - a manual DROP COLUMN would itself be
--          another out-of-band mutation and would defeat the point of
--          the test.
-- Affected tables: incidents (drops the test-only rogue_column)
-- Backward-compatibility notes: safe - rogue_column was never part of the
--   declared schema, carried no application data, and no code reads it.
-- Rollback: re-running 0001 is not applicable; to reverse this specific
--   migration, re-add the column via a new forward migration if ever
--   needed (there is no legitimate reason to).

ALTER TABLE incidents DROP COLUMN IF EXISTS rogue_column;
