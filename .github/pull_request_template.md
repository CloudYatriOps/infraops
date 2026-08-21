<!--
Keep this concise - a reviewer should understand the change without
reading the diff first. Delete a section only if it is genuinely N/A
(state that explicitly rather than leaving it blank).
-->

## Summary

<!-- One or two sentences: what changed. -->

## Why

<!-- The problem or requirement this addresses. Link an issue if one exists. -->

## Scope

<!-- What this PR touches, and - just as important - what it deliberately does NOT touch. -->

## Tests

<!-- Exact commands run and their result (e.g. `pytest -q tests/test_x.py` -> N passed).
     A change with no test evidence should say why none applies. -->

## Security impact

<!-- Does this touch auth, secrets, the policy engine, scan/redaction logic,
     or anything read-only-vs-mutating? "None" is a valid answer if true. -->

## Migration impact

<!-- REQUIRED if this touches src/aep/migrations_sql/: migration file name,
     confirmation it only ADDS (never edits an existing applied migration),
     and that `python -m pytest tests/test_db_migrations.py
     tests/test_db_schema_drift.py` passes. "N/A" if no migration. -->

## Rollback / recovery

<!-- How to revert this safely if it causes a problem in production. -->

## Evidence

<!-- Command output, screenshots, or a description of manual verification. -->

## Breaking changes

<!-- Any change to a public CLI flag, API route/response shape, or documented
     behavior. "None" is a valid answer. -->
