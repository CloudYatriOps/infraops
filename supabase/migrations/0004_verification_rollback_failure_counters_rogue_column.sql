-- Migration: 0004_verification_rollback_failure_counters_rogue_column
-- Purpose: Restore schema after an INTENTIONAL out-of-band drift test run
--          during Stage A.5 verification of the new `failure_counters`
--          table added in 0003. A raw `ALTER TABLE failure_counters ADD
--          COLUMN rogue_test_col text` was executed directly against
--          Postgres (bypassing the migration mechanism on purpose) to
--          prove drift_report() catches unauthorized schema changes on
--          the newly-added table, mirroring the 0002 proof against
--          `incidents`. This migration is the sanctioned way to restore
--          the schema - a manual DROP COLUMN would itself be another
--          out-of-band mutation and would defeat the point of the test.
-- Affected tables: failure_counters (drops the test-only rogue_test_col)
-- Backward-compatibility notes: safe - rogue_test_col was never part of
--   the declared schema, carried no application data, and no code reads it.
-- Rollback: not applicable; re-add via a new forward migration if ever needed.

ALTER TABLE failure_counters DROP COLUMN IF EXISTS rogue_test_col;
