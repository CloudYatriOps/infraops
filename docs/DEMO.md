# AEP Demo (Stage C)

A literal, reproducible command sequence for the CEO demo. Every step
below runs real code against real local PostgreSQL - nothing here is a
canned transcript.

## Prerequisites

```
service postgresql start   # if not already running
export AEP_PG_PASSWORD=aep_local_dev_only
```

## Command sequence

```
aep demo readiness
aep demo run
aep demo run --scenario ambiguous
aep providers
```

## What each step demonstrates

### 1. `aep demo readiness`

Prints a deterministic checklist (explicitly not a percentage) of
concrete, checkable preconditions: orchestrator skill gate wired, AI
gateway/OmniRoute adapter importable, `src/aep/demo_template/` fixture
present, the real end-to-end demo test passes, PostgreSQL is the
resolved default backend, and the `Evidence` model records what it must.
Expected shape:

```
=== DEMO READINESS CHECKLIST ===
(a checklist, not a percentage - every line is a concrete, checkable condition)
[OK] orchestrator skill gate wired (_apply_skill_gate)
[OK] AI Gateway importable
[OK] OmniRoute adapter importable
[OK] src/aep/demo_template/ fixture present
[OK] tests/test_end_to_end_demo.py passes - 4 passed in ...s
[OK] PostgreSQL is the default persistence backend - resolved backend='postgres'
[OK] Evidence model records source/exit_code/summary

READY
```

Exits non-zero if any check fails, so it is safe to run as a pre-demo
gate in a script.

### 2. `aep demo run`

The full happy-path flow: materializes `src/aep/demo_template/` into a
real git repo, seeds/resolves canonical skills, routes one AI call
through `AIGateway` (honestly to `FakeAIProvider` - OmniRoute is
unavailable in this sandbox, and the output says so explicitly), plans
and runs the real `recon -> code_fix -> security_scan -> run_tests`
graph against real PostgreSQL, and shows the real secret-scanner
block-then-fix-then-clean cycle. Expected shape:

```
=== AEP DEMO (happy_path) ===
  - materialized src/aep/demo_template/ into real git repo at /tmp/...
  - seeded 18 canonical skills into skill registry (why-this-skill: ...)
  - AIGateway routed a 'classification' call to provider=fake (...)
  - persistence: postgres (which-policy-checks: src/aep/config/policy.yaml, which-provider: fake)
  - real security scanner ran against the fixture repo (what-changed: none yet; ...)
  - applied fix (removed placeholder secret from config.py), operator approved, re-scanned: security_scan now SUCCEEDED (...)
  - what-changed: app.py's add() was rewritten ...
  - what-verification-proved: real `pytest` run against the fixed repo ...
AI provider used: fake (...)
Persistence backend: postgres
Security scan blocked on first pass (secret detected): True
Security scan clean after fix: True
Task outcomes:
  recon            SUCCEEDED
  code_fix         SUCCEEDED
  security_scan    SUCCEEDED
  run_tests        SUCCEEDED
```

Optional flags: `--work-dir <path>` (default `/tmp/aep_demo_run`),
`--db-backend {postgres,sqlite}` (default `postgres`).

### 3. `aep demo run --scenario ambiguous`

Demonstrates refusal/clarification-request on an under-specified request
("make the database faster") rather than guessing at scope or executing
anything. Expected shape:

```
=== AEP DEMO (ambiguous) ===
REFUSED - clarification required, nothing executed.
  reason: Request 'make the database faster' does not name a target ...
```

### 4. `aep providers`

Lists every registered AI provider/model, which is default, which is
fallback, the deterministic routing table, and OmniRoute's real (not
faked) reachability - `unavailable` in this sandbox, with the exact
missing env var names named.

## Notes

- `aep demo run` uses `db_backend="postgres"` by default (project ids are
  real UUIDs - the documented Stage A.5 interface gap). Pass
  `--db-backend sqlite` to run entirely without PostgreSQL.
- All CLI commands call the exact same `src/aep/demo.py`/
  `src/aep/progress/demo_readiness.py` functions
  `tests/test_end_to_end_demo.py`/`tests/test_cli_demo.py` exercise - no
  duplicated logic between the CLI and the tests.
