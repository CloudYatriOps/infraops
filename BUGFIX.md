# Bug Fixes

## BUG-0009: `.gitignore` missing `node_modules/`, `.venv/`, `.env`

- **Date:** 2026-08-20
- **Component:** `.gitignore`, discovered during final release-packaging git-safety audit.

### Symptom
`.gitignore` only excluded Python build/cache artifacts (`__pycache__/`,
`*.pyc`, `.pytest_cache/`, `*.db*`, `build/`, `dist/`). It had no entry for
`node_modules/` (present at `ui/node_modules`, restorable via `npm ci`),
`.venv/`/`venv/` (a local Python virtualenv), `.env` (the real, filled-in
copy of `.env.example` a developer creates locally per the README), or
stray `*.log`/`.DS_Store` files.

### Impact
Not a code defect, but a real release-hygiene risk: a plain `git add .`
in this repo, as-is, would have staged tens of thousands of files under
`ui/node_modules` and, worse, a developer's actual `.env` (potentially
containing a real Postgres password, API keys, or credentials) into the
very first commit pushed to the destination repo. This is exactly the
class of mistake the standing release-packaging instruction ("no
secrets/artifacts committed") is meant to prevent.

### Detection
`ls -la` at repo root during the pre-push hygiene audit showed
`ui/node_modules`, `src/aep/__pycache__`, `tests/__pycache__`, and
`.pytest_cache` all present and un-ignored beyond the Python-cache
entries; cross-checked against `.gitignore`'s actual contents.

### Fix
Added `node_modules/`, `.venv/`, `venv/`, `.env`, `*.log`, `.DS_Store` to
`.gitignore`. No code changed; existing ignored patterns untouched.

### Tests
No test applies to a `.gitignore` file; verified by re-running `git
status`-equivalent reasoning (there is no `.git` yet in this workspace —
see `handoff.md`/final release report) and by confirming the newly-added
patterns match the actual untracked directories found above.

### Lesson
A `.gitignore` written early in a Python-only project needs a follow-up
pass once a Node/UI subtree and a real `.env` convention exist — file
hygiene should be re-audited at every point a new artifact-producing
toolchain is added, not just at project init.

## BUG-0008: 5 real functional dependencies were never declared in `pyproject.toml`

- **Date:** 2026-08-20
- **Component:** `pyproject.toml`, discovered during final release-packaging/dependency-reproducibility audit.

### Symptom
An AST walk of every `import`/`from ... import` statement under `src/`
(catching module- and function-level imports alike) found 5 third-party
modules actually imported by real code with no corresponding entry
anywhere in `pyproject.toml`: `boto3` (AWS cloud adapter),
`hcl2`/`bc-python-hcl2` (Terraform HCL2 parsing, used by 3 files),
`kubernetes_validate` (K8s manifest schema validation), `cyclonedx`/
`cyclonedx-python-lib` (SBOM generation), and `requests` (GitHub API
client). This dev sandbox happened to already have all 5 installed, so no
crash was ever observed here - but nothing in `pyproject.toml` would have
installed them on a genuinely clean machine.

### Impact
Not a crash bug: every one of the 5 imports is already deliberately
local/lazy (inside the function that needs it, never at module import
time), and each site already has a graceful "not installed" fallback
path (`validator="hcl2-structural", ran=False, ...`, etc.) rather than an
unguarded `ImportError` propagating up. So `import aep`, the CLI, and the
API all still work with none of the 5 present. The real impact is
silent capability loss on a clean install: AWS cloud discovery,
Terraform/K8s structural validation, SBOM generation, and the live
GitHub client would each quietly report themselves unavailable on a
fresh machine, with no `pyproject.toml` extra a user could even install
to fix it - the dependency was simply undocumented.

### Detection
AST-based import audit (`ast.walk` over every `.py` file under `src/`,
collecting all `Import`/`ImportFrom` module names) cross-checked against
`pyproject.toml`'s declared `dependencies`/`optional-dependencies`, done
as part of the final release-packaging reproducibility pass - not
previously run in this project.

### Root cause
These 5 capabilities were each added in earlier phases (Phase 3/4/5
infra/security scanners, Phase 2 GitHub client, cicd SBOM artifact) with
their own lazy-import-and-degrade-gracefully pattern, but the
corresponding `pyproject.toml` optional-dependency entry was never added
alongside any of them - each was reviewed/tested in an environment where
the package happened to already be present.

### Fix
Added 3 new optional-dependency extras to `pyproject.toml`:
`infra` (`boto3`, `bc-python-hcl2`, `kubernetes-validate`),
`sbom` (`cyclonedx-python-lib`), `github` (`requests`) - grouped by the
capability area that needs them, matching the existing `api`/
`dependency-scanning` extra convention. No code changed - this is a
dependency-declaration fix only.

### Tests
No new test file - this is a metadata-only fix with no behavior change
to verify beyond "the package that was already installed is now also
declared." Verified by re-running the full existing test suite (which
exercises all 5 capabilities' real and graceful-fallback code paths)
with zero change in pass count.

### Verification
`python3 -m py_compile` on every file that imports one of the 5 modules -
clean (no syntax change was made to any of them). Full regression suite
re-run after this change - see `handoff.md` for the exact count, unchanged
from before this fix (a declaration-only change cannot change test
behavior in an environment where the packages were already present).

### Lesson
"It works in this sandbox" is not evidence of a complete dependency
declaration - lazy/guarded imports that degrade gracefully are the right
design (never crash the whole platform for one missing optional
capability), but graceful degradation must not become an excuse to skip
declaring the dependency at all. An AST-based import audit against
`pyproject.toml` should be part of any future release-packaging pass,
not just this one.

## BUG-0007: the Stage D web UI has never actually been able to fetch from the live API in a browser — no CORS headers, ever

- **Date:** 2026-08-18
- **Component:** `src/aep/api/app.py`, discovered during the Phase 10 UI/browser-validation batch.

### Symptom
Every browser-originated `fetch()` call from the Vite UI (`http://localhost:5173`)
to the Flask API (`http://localhost:5000`) was silently blocked by the
browser's CORS preflight check: `Access to fetch at 'http://localhost:5000/...'
from origin 'http://localhost:5173' has been blocked by CORS policy: Response
to preflight request doesn't pass access control check: No
'Access-Control-Allow-Origin' header is present`. Every page that calls the
API (Dashboard's system-status, and now the new intelligence panels) showed
"Failed to fetch" instead of real data.

### Impact
This was not a regression introduced by this session's changes — it is a
**pre-existing gap that has been there since Stage D first built the UI**.
Nothing in Stage D's own verification actually opened the UI in a real
browser against a live API (verification there was `npm run build`
compiling cleanly plus separate CLI-driven checks) — the browser-level
integration was simply never exercised until this session's real Playwright
inspection. It would have silently blocked 100% of live browser usage of
the product UI, not just the 3 new intelligence panels added this batch.

### Detection
Found via genuine browser inspection with Playwright (`playwright.sync_api`,
real Chromium) navigating the actual running UI+API pair, not by reading
code or trusting a prior report — `page.on('console', ...)` surfaced the
exact CORS error text.

### Root cause
`src/aep/api/app.py`'s `create_app()` never set any `Access-Control-*`
response header anywhere, and no route declared `OPTIONS`, so a browser's
CORS preflight (triggered here because the UI sends
`Content-Type: application/json`, which is not a CORS-safelisted content
type) received a 404/405 with no CORS headers and the browser refused the
real request.

### Fix
One root-cause fix in the single place all requests already pass through
(`app.py`'s existing `@app.before_request`/`@app.after_request` hooks — no
per-route change, no second code path):
- `_authenticate()` (before_request) now short-circuits `OPTIONS` requests
  with an empty `200` before the existing auth/dev-mode logic runs.
- A new `_dev_cors()` after_request hook stamps
  `Access-Control-Allow-Origin/Headers/Methods` onto every response, but
  **only when `AEP_API_DEV_MODE=1`** — the exact same local-dev posture
  that already disables the auth check right above it. A real
  (non-dev-mode) deployment gets no new CORS header at all; that
  configuration is left for a real deployment/reverse-proxy decision, not
  silently opened up here.

### Tests
No new dedicated CORS test file — this is exercised by real usage:
independently re-verified live with real Playwright browser navigation
(zero console errors across Dashboard/Projects/Task Execution/Findings/
Incidents/Approvals/Runtime/Providers, and the new intelligence panels
actually rendering real fetched data) rather than a unit test asserting a
header string. Confirmed the pre-existing `tests/test_api_threat_model.py`
and full API test set (32 tests across all Phase 10 intelligence routes)
still pass unchanged — the `OPTIONS` short-circuit and dev-mode-gated
header addition touch no authenticated-path behavior.

### Verification
`curl -X OPTIONS http://localhost:5000/intelligence/health-score` →
`200` with the three `Access-Control-*` headers present; a real Chromium
browser (Playwright) loading the UI against the live API now shows zero
console errors and real fetched intelligence data, where it previously
showed `Error: Failed to fetch` and a CORS console error on every
API-backed screen.

### Lesson
"The build compiles" and "the CLI works" are not evidence that the UI
actually works in a browser against the live API — this gap sat
unnoticed since Stage D specifically because nobody had opened a real
browser against the running pair before. Genuine UI verification means
opening the actual application, not just building it.

## BUG-0005: project-scoped API keys could see other projects' data through the "no `project_id` filter" path on `/findings` and `/approvals`

- **Date:** 2026-08-17
- **Component:** `src/aep/api/app.py`, Phase 9 Stage D Wave 2 (threat-model review, item 16).

### Symptom
`api_keys.project_scope` (migration `0007_api_auth.sql`) restricts a key
to one project, and `_require_project_scope()` correctly enforced it
whenever a caller passed `?project_id=...` (or a path parameter like
`/incidents/<project_id>`). But `GET /findings` and `GET /approvals` both
treat `project_id` as an *optional* filter: when a project-scoped caller
simply omitted it, both handlers fell through to an **unfiltered,
cross-project** list (`PostgresFindingRepository.list(None, severity)` /
`store.non_terminal_tasks()`), silently returning every other project's
findings/approvals to a key that should only ever see its own project.
Cross-project access WITH an explicit `project_id` was already correctly
rejected with 403 — the gap was specifically the "no filter given"
branch.

### Root cause
`_require_project_scope(project_id)` was only ever called `if project_id`
truthy — the isolation check was conditioned on the caller supplying the
parameter, instead of being conditioned on whether the caller's key
itself was scoped. A scoped key omitting the parameter never hit the
check at all.

### Fix
Both handlers now resolve the effective `project_id` from
`g.project_scope` when the caller didn't supply one, before querying: a
scoped key is now always pinned to its own project regardless of whether
it explicitly names it, and an unscoped (org-wide) key's behavior is
unchanged (still sees everything, as before).

### Tests added
- `tests/test_api_threat_model.py::test_scoped_key_cannot_see_other_projects_findings_via_unfiltered_query`
- `tests/test_api_threat_model.py::test_scoped_key_cannot_see_other_projects_approvals_via_unfiltered_query`

### Verification evidence
```
$ AEP_PG_PASSWORD=aep_local_dev_only python3 -m pytest -q tests/test_api_threat_model.py tests/test_api_app.py
.........................                                                [100%]
25 passed in 3.67s
```

### Lessons learned
An "optional filter" query parameter on an endpoint gated by
project-scoped auth must never be optional for the auth check itself —
any endpoint accepting an optional `project_id` must resolve it from
`g.project_scope` FIRST when the key is scoped, then apply the caller's
explicit filter only as a further narrowing, never as the sole source of
the isolation boundary. Every future endpoint with this shape must be
tested the same way: the case where the scoped caller supplies no
filter at all, not just the case where they name the wrong project.

## BUG-0004: clean `pip install .` (no extras) installs a package whose DEFAULT runtime path immediately raises `ModuleNotFoundError: No module named 'psycopg2'`

- **Date:** 2026-08-17
- **Component:** `pyproject.toml` (`[project.optional-dependencies].postgres`), Phase 9 Stage D Wave 1 ("fix the installation/bootstrap experience").

### Symptom
A fresh checkout, `pip install .` (no extras), then any code path that
constructs the default durable store (e.g. `python -c "import
aep.cli"` followed by any command that calls `build_state_store`/
`build_orchestrator`, or simply `import aep.db.state_store_postgres`)
raised `ModuleNotFoundError: No module named 'psycopg2'`.

### Impact
Total install-time breakage of the platform's default/production
runtime path for anyone who installs the package the ordinary way
(`pip install .` with no extras) — exactly the failure a new
contributor or a CI job with a bare install would hit first, before
ever touching a single feature. This is a pure packaging-metadata bug,
not a code-logic bug: the Postgres client code itself was correct and
already tested; it simply wasn't declared as a required dependency of
the package that now depends on it unconditionally.

### Root cause
`pyproject.toml`'s `postgres` extras group held `psycopg2-binary`/
`pgvector`, with a comment stating: *"Optional because the SQLite
StateStore remains the default/production path in this stage - only
tooling/tests that touch the new Postgres layer need this installed."*
That comment was accurate when written (Stage A), but Stage A.5
("PostgreSQL Runtime Cutover") flipped `src/aep/db/factory.py::
resolve_backend`'s default from `sqlite` to `postgres` — with nothing
set (no `db_backend` argument, no `AEP_DB_BACKEND` env var), the
platform now unconditionally imports and constructs a
`PostgresStateStore`, which imports `psycopg2` at module scope
(`src/aep/db/postgres.py`). The dependency metadata was never updated
to match, so the extras comment became stale and actively misleading:
the "SQLite is the default" premise it depended on had already stopped
being true. This was found by re-reading `pyproject.toml` against the
already-documented Stage A.5 default-backend change (`handoff.md`/
`ARCHITECTURE.md` §31) rather than by a test failure — the existing
test suite always runs inside this sandbox's fully-provisioned
environment (`psycopg2-binary` already installed via `dev`/test
tooling), so no existing test ever exercised a genuinely bare install.

### Detection
Manual re-read of `pyproject.toml`'s dependency declarations against
the documented Stage A.5 default-backend behavior (pre-diagnosed for
this Stage D wave, then independently confirmed here): `psycopg2` is
imported unconditionally by `src/aep/db/postgres.py`, which
`src/aep/db/state_store_postgres.py` imports at module scope, which
`src/aep/db/factory.py::build_state_store` imports at module scope,
which is reached by the default (nothing-set) code path.

### Fix
Moved `psycopg2-binary>=2.9`/`pgvector>=0.2` from
`[project.optional-dependencies].postgres` into
`[project.dependencies]` (required), since PostgreSQL is genuinely no
longer an optional capability of this package — it is the default
runtime backend. The `postgres` extras group was removed entirely
(nothing legitimately needs to opt into what is now unconditionally
installed). This is the "simplest correct change" per the smallest
real fix that matches the codebase's actual behavior today: no
SQLite-only standalone install path is documented or tested anywhere
in this repository (checked — every test module that exercises the
default backend assumes Postgres is present, per
`tests/conftest.py`'s own `AEP_PG_PASSWORD` default-setting comment),
so there was no supported "optional Postgres" mode to preserve behind
a nicer error message instead.

### Files changed
- `pyproject.toml` — `psycopg2-binary`/`pgvector` moved into
  `dependencies`; `postgres` extras group removed; a new `api` extras
  group added for the Stage D Wave 1 Flask dependency (unrelated to
  this bug, added in the same pass).
- `scripts/bootstrap.sh` — new local dev bootstrap script that runs
  `pip install -e .` and lets this fix's dependency resolution do the
  right thing automatically, with no manual extras flag required (see
  `docs/BOOTSTRAP.md`).

### Tests added
- `tests/test_bootstrap_install_dependencies.py`:
  - `test_psycopg2_and_pgvector_are_required_not_only_optional` — static
    check parsing `pyproject.toml` (same lint-style convention as
    `tests/test_db_migration_only_enforcement.py`), asserting both
    packages are required dependencies.
  - `test_default_backend_resolution_is_postgres_matching_the_dependency_fix`
    — documents/proves the coupling this fix depends on (default backend
    is genuinely Postgres today).
  - `test_importing_db_factory_module_does_not_raise_modulenotfounderror`
    — direct reproduction of the actual failure mode (importing the
    module that constructs the default backend).
  - A full fresh-venv `pip install -e .` (no extras) +
    `python -c "import aep.cli"` reproduction was run BY HAND during
    verification (see the Stage D Wave 1 session report) rather than
    added as a permanent suite test, since spinning up a fresh venv on
    every `pytest` invocation would meaningfully slow down this
    project's normal test run; the static + direct-import tests above
    are the permanent regression guard, per this bug's own triage note
    that a static check is an acceptable minimum when the full
    venv-based test is too heavy for the suite's conventions.

### Regression risk
Very low. This only changes dependency *declaration* metadata (moving
two packages from one list to another in `pyproject.toml`); no
application code changed. The only way to reintroduce this bug is to
either move these two packages back to being optional, or add a new
unconditional import of a package that isn't declared as required —
both are exactly what the new static test in
`test_bootstrap_install_dependencies.py` catches.

### Verification evidence
```
$ python3 -m pytest -q tests/test_bootstrap_install_dependencies.py
...                                                                       [100%]
3 passed in 0.05s
```
Hand-verified separately: fresh venv, `pip install -e .` (no extras
flag passed), then `python -c "import aep.cli"` — no
`ModuleNotFoundError` (see Stage D Wave 1 session report for the exact
transcript).

### Lessons learned
A comment justifying why a dependency is optional is itself a claim
that can go stale exactly like code can — when a change (Stage A.5's
default-backend flip) invalidates the premise a *different* file's
comment depended on, that other file's comment/config needs to be
revisited in the same pass, not discovered later by a fresh install
failing. Any future "make X the default" change must include a search
for `optional-dependencies`/extras comments whose stated rationale is
"because Y is still the default" and update them in the same commit.

## BUG-0003: `aep demo run` crashes on a second invocation against the default work dir

- **Date:** 2026-08-14
- **Component:** `src/aep/demo.py` — `_materialize_demo_repo()` (Phase 9 Stage C demo vertical slice).

### Symptom
`run_demo()`'s default `work_dir` is the fixed path `/tmp/aep_demo_run`
(so the documented `docs/DEMO.md` command sequence is exact and
copy-pasteable without requiring a `--work-dir` flag). `_materialize_demo_repo()`
called `shutil.copytree(DEMO_TEMPLATE_DIR, repo, ...)` unconditionally.
Running `aep demo run` (or `--scenario ambiguous`, if it also reached this
path) a second time against the same default work dir raised
`FileExistsError: [Errno 17] File exists: '/tmp/aep_demo_run/demo_project'`.

### Impact
The whole point of the demo is that it be reproducible for a live CEO
demo (`docs/DEMO.md`'s literal command sequence, and the Stage C
acceptance gate's "Demo can be reproduced" item) — a demo that crashes on
its second run, requiring the operator to manually `rm -rf /tmp/aep_demo_run`
first, is not actually reproducible as documented.

### Root cause
`shutil.copytree()` refuses to write into an already-existing destination
directory by default (`dirs_exist_ok=False`), and nothing cleaned up the
prior run's materialized repo first.

### Detection method
Found during independent hand-verification of the demo CLI: ran
`aep demo run --scenario ambiguous` (uses the same default work dir),
then ran plain `aep demo run` immediately after — the second command
crashed with the exact `FileExistsError` above.

### Fix
`_materialize_demo_repo()` now removes any pre-existing `demo_project/`
under `dest_root` (`shutil.rmtree`) before copying the template in —
matching the "disposable fixture" framing already documented for this
directory (never mutates `demo_project_template/` itself, only the
per-run materialized copy).

### Files changed
- `src/aep/demo.py` — `_materialize_demo_repo()`.

### Tests added
Re-ran `aep demo run --scenario ambiguous` immediately followed by
`aep demo run` (both against the default work dir) by hand — the second
invocation now succeeds instead of crashing. (No new automated test
added beyond this hand-verification; `tests/test_end_to_end_demo.py` and
`tests/test_cli_demo.py` already exercise `run_demo()` with an explicit
per-test `tmp_path`-based `work_dir`, which is why this path was never
exercised twice against the SAME directory by the existing suite.)

### Regression risk
None. The only behavior change is removing a stale directory that would
otherwise cause an immediate crash; a first-ever run (empty `dest_root`)
behaves identically to before (`repo.exists()` is `False`, the `rmtree`
branch is skipped).

### Lessons learned
Any "materialize a disposable fixture into a fixed default path" helper
must be safe to call more than once against that same default path — a
demo/CLI entrypoint documented with a literal, no-flags-required command
sequence will always eventually be re-run against its own leftovers, and
that path needs its own explicit hand-test, not just tests that isolate
each run into its own fresh `tmp_path`.

---

## BUG-0002: `OmniRouteConfig`'s default dataclass repr/str leaks the raw credential

- **Date:** 2026-08-14
- **Component:** `src/aep/ai_gateway/omniroute_provider.py` — `OmniRouteConfig` (Phase 9 Stage C, AI Gateway / OmniRoute adapter).

### Symptom
`OmniRouteConfig` is a plain `@dataclass` with a `credential: str` field and
no custom `__repr__`/`__str__`. Python's auto-generated dataclass repr
prints every field verbatim, so `repr(cfg)`, `str(cfg)`, `f"{cfg}"`, or any
accidental `print(cfg)`/logging call/exception that happened to embed the
config object itself (as opposed to just its `.credential` attribute)
would print the raw credential value in full.

### Impact
This sits directly on top of Stage C's explicit "NEVER print credentials"
requirement (Part E of the Stage C spec). The network-facing paths
(`_headers()`, `_redact()`, exception messages built from response bodies)
were already covered by `tests/test_ai_gateway_credential_safety.py`, but
none of those tests exercised `repr()`/`str()` of the config object
directly — a debugging `print(self.config)` anywhere in this module, or a
future logging statement that logged the config object instead of one of
its fields, would have leaked the credential with no test catching it.

### Root cause
Relying on the dataclass-generated `__repr__` for a class that holds a
secret field, instead of overriding it — the same class of mistake the
credential-safety tests were written to catch on the network paths, just
missed on the "print the object itself" path.

### Detection method
Found by hand-testing credential redaction independently during Stage C
verification: constructed a real `OmniRouteConfig` with an obviously-fake
credential and checked `repr(cfg)`/`str(cfg)` directly (not just the
network-call paths the existing test file covered). `repr(cfg)` printed
the fake credential in full before the fix.

### Fix
Added an explicit `__repr__` (and `__str__ = __repr__`) to
`OmniRouteConfig` that always renders `credential='[REDACTED]'`,
regardless of the real value.

### Files changed
- `src/aep/ai_gateway/omniroute_provider.py` — `OmniRouteConfig.__repr__`/`__str__` added.
- `tests/test_ai_gateway_credential_safety.py` — added `test_credential_never_appears_in_config_repr_or_str`.

### Regression risk
None. Purely additive — `base_url`/`provider_label` still render normally; only `credential` is now always redacted in any string representation of the object.

### Verification evidence
```
$ python3 -c "from aep.ai_gateway.omniroute_provider import OmniRouteConfig; \
  cfg = OmniRouteConfig(base_url='http://x', credential='sk-fake-not-a-real-secret-xyz'); \
  print(repr(cfg))"
OmniRouteConfig(base_url='http://x', credential='[REDACTED]', provider_label='omniroute')
```
`tests/test_ai_gateway_credential_safety.py::test_credential_never_appears_in_config_repr_or_str` passes.

### Lessons learned
Any dataclass/class holding a secret field needs an explicit `__repr__`/`__str__` override from the moment it's created, not just tests covering the paths where the secret is deliberately used (headers, requests) — the default object-printing path is an equally real leak vector and needs its own test, not an assumption that "we only print specific fields."

---

## BUG-0001: `PostgresLeaseRepository.acquire()` uncaught `IntegrityError` on concurrent first-time claims

- **Date:** 2026-08-13
- **Component:** `src/aep/db/postgres.py` — `PostgresLeaseRepository.acquire()` (Stage A.5 PostgreSQL Runtime Cutover, part of the new `src/aep/db/` repository layer that Phase 8's runtime leases will be cut over onto).

### Symptom
When two (or more) workers race `acquire()` on the *same task_id that has
never had a lease row before*, more than one racer could reach the
"no existing row" branch of the method at the same time. That branch did
a bare `INSERT INTO runtime_leases (...) VALUES (...)` with no conflict
handling. All but one of the concurrent INSERTs targeting the same
`task_id` primary key raised `psycopg2.errors.UniqueViolation` /
`IntegrityError`, which propagated straight out of `acquire()` as an
unhandled exception instead of the loser cleanly getting `False` back.

### Impact
Any caller relying on `acquire()`'s documented contract ("returns False
if another worker currently holds it") to decide whether to proceed with
a task would instead see a crash on the very first contested acquisition
of a brand-new task's lease. In the runtime supervisor/worker pool this
would surface as an unhandled exception inside a worker's task-claim loop
during real concurrent startup (e.g. several workers coming up
simultaneously and all trying to claim the same freshly-created task) —
exactly the scenario the lease mechanism exists to make safe.

### Root cause
`SELECT ... FOR UPDATE` only takes a row lock on rows that already
exist. It provides no protection against two transactions concurrently
inserting a brand-new row with the same primary key — that race is only
resolved at the `INSERT`, by whichever transaction's insert commits
first; the loser gets a unique/primary-key constraint violation, not a
"row is locked" wait. The original code assumed the `SELECT ... FOR
UPDATE` had already serialized all contenders down to this branch, which
is false for first-time inserts specifically (as opposed to the
already-exists branch, which the `FOR UPDATE` correctly serializes).

### Detection method
Root-caused as an "audit-suspected" issue named explicitly in the Stage
A.5 task scope, then proven concretely with a new real-Postgres
concurrency test: 8 threads, each opening its own independent psycopg2
connection/pool, all racing `acquire()` on one never-before-seen
`task_id`, synchronized to fire together via a `threading.Barrier`.
Reverting the fix locally and re-running that test reproduced the exact
predicted failure mode: 7 of the 8 threads raised
`psycopg2.errors.UniqueViolation: duplicate key value violates unique
constraint "runtime_leases_pkey"` (all against the same `task_id`),
confirming the double-INSERT race. With the fix restored, the same test
passes with zero exceptions and exactly one `True`/seven `False`.

### Fix
Replaced the bare `INSERT` in the "no existing row" branch with
`INSERT INTO runtime_leases (...) VALUES (...) ON CONFLICT (task_id) DO
NOTHING`, and used `cur.rowcount` to determine whether *this* connection's
insert actually won (`rowcount == 1`) or lost the race silently
(`rowcount == 0`, no exception). `acquire()` now returns that boolean
directly. No other code path (existing-row update, or the row-exists
value-copy fields) changed.

The same defensive pattern was proactively applied to the brand-new
`PostgresProjectLockRepository.acquire()`, which has the identical
first-time-insert shape (`runtime_project_locks` keyed by
`project_id`), using `ON CONFLICT (project_id) DO NOTHING`.

### Files changed
- `src/aep/db/postgres.py` — `PostgresLeaseRepository.acquire()` fixed;
  `PostgresProjectLockRepository.acquire()` implemented with the fix
  applied from the start.

### Tests added
- `tests/test_db_repositories_postgres.py::test_lease_repository_real_postgres_concurrent_first_time_acquire_exactly_one_winner`
  — 8 real threads, 8 independent psycopg2 connections, one never-before-seen
  `task_id`, `threading.Barrier` synchronization. Asserts: zero exceptions
  raised across all 8 threads, exactly one `True`, exactly seven `False`.
- `tests/test_db_repositories_postgres.py::test_project_lock_repository_real_postgres_concurrent_first_time_acquire_exactly_one_winner`
  — identical structure/assertions for the new `ProjectLockRepository`.

### Regression risk
Low. The change only affects the branch that previously had no conflict
handling; the already-exists branch (the common steady-state case: renew
or genuinely-contested-but-already-created lease) is untouched. `ON
CONFLICT DO NOTHING` combined with an explicit `rowcount` check is a
standard, well-understood Postgres idiom for this exact race and
degrades to identical single-writer behavior when there is no
contention.

### Verification evidence
```
$ python3 -m pytest -q tests/test_db_repositories_postgres.py
..............                                                           [100%]
14 passed in 2.55s
```
Both concurrency tests (lease and project-lock) are included in that
run and pass with zero exceptions and the expected 1-winner/7-loser
split across 8 racing threads.

### Lessons learned
`SELECT ... FOR UPDATE` guards contention over *existing* rows only —
it is not a substitute for `ON CONFLICT` handling on the insert path
whenever the "row doesn't exist yet" branch can be reached by more than
one concurrent transaction. Any future Postgres repository method with
this "check-then-insert" shape (get-or-create semantics under
concurrency) must use `INSERT ... ON CONFLICT DO NOTHING/DO UPDATE`
for the insert itself, never a bare `INSERT`, and must have a real
multi-connection/multi-thread test proving the race — a single-threaded
test cannot catch this class of bug at all.

## BUG-0006: `PostgresFindingRepository.save()` silently discards a caller-supplied `discovered_at`, always recording "now" instead

- **Date:** 2026-08-17
- **Component:** `src/aep/db/postgres.py::PostgresFindingRepository.save`,
  found while building Phase 10 Wave 1's cross-project prioritization
  engine (`src/aep/intelligence/prioritization.py`), which reuses this
  exact read/write path unchanged.

### Symptom
Constructing a `FindingRecord` with an explicit `discovered_at` (e.g. to
represent an already-old finding - which any backfill, migration
importer, or the "age" factor's own hand-verification script needs to
do) and calling `PostgresFindingRepository.save()` on it silently
persists `discovered_at = now()` instead of the value on the dataclass.
Confirmed directly against the real `findings` table: a record built
with `discovered_at` 45 days in the past came back with a
`discovered_at` timestamp identical to the moment `save()` ran.

### Root cause
`save()`'s `INSERT INTO findings (...)` column list does not include
`discovered_at` at all (only `id, project_id, category, severity,
status, resource, description, confidence, false_positive, task_id,
evidence`), so the column always falls back to its schema default
(`discovered_at timestamptz NOT NULL DEFAULT now()`,
`supabase/migrations/0001_initial_schema.sql`) regardless of what the
caller set on the `FindingRecord` before calling `save()`.

### Impact / who is affected
Every current caller (the security/dependency/infra scanners that create
findings for the first time) is unaffected in practice, since they never
have a "real" historical `discovered_at` to preserve - a brand-new
finding's discovered time genuinely is "now". The gap only bites a
caller that needs to preserve a pre-existing `discovered_at` - e.g. a
future data-migration/backfill path, or any test (including this wave's
own hand-verification script) trying to construct a finding that has
"been open for N days" against real Postgres. `FakeFindingRepository`
(the in-memory test double used by `tests/test_prioritization.py`) does
not have this bug - it stores the record as-is - so the age-factor unit
tests pass correctly; only the real-Postgres path silently loses the
value. **Fixed in Phase 10 Wave 2** (`src/aep/intelligence/incident_patterns.py`'s
recurrence-interval computation directly needs correct real `discovered_at`
values, which is the "genuine defect blocking me" case BUGFIX.md
governance allows fixing rather than just documenting) - see Fix/Tests/
Verification below.

### Fix (applied in Phase 10 Wave 2)
`PostgresFindingRepository.save()`'s `INSERT` now includes `discovered_at`
in the column list, but ONLY when the caller supplied one
(`finding.discovered_at is not None`) - two INSERT statements are used (a
with-`discovered_at` branch and the original without-it branch) so that
a caller that leaves `discovered_at` unset (every pre-existing scanner
caller today) still gets the schema default `now()`, completely
unchanged. `ON CONFLICT DO UPDATE` deliberately does NOT include
`discovered_at` in its `SET` list (already the case before this fix), so
a re-save of an existing finding can never move `discovered_at` forward
- it is set exactly once, at first insert. Blast radius: small and
scoped, matching BUG-0005's precedent (both are `db/postgres.py`
INSERT-shape corrections); the `ON CONFLICT` branch and every other
column are untouched.

### Tests added
`tests/test_db_repositories_postgres.py::test_finding_repository_real_postgres_preserves_caller_supplied_discovered_at`
- against real Postgres: (1) a finding saved with an explicit 45-day-old
`discovered_at` round-trips within 1 second of the supplied value; (2) a
finding saved with NO `discovered_at` still gets `now()` (unchanged
behavior, asserted within a 30-second tolerance); (3) re-saving the
same finding (a status change) with the same old `discovered_at` leaves
it unmoved.

### Verification evidence
```
$ AEP_PG_PASSWORD=aep_local_dev_only python3 -m pytest -q tests/test_db_repositories_postgres.py
...............                                                          [100%]
15 passed in 2.58s
```
Full suite re-run after the fix: 707 passed, 1 skipped baseline plus this
wave's new tests, all green (see `handoff.md` for the exact final count).

### Lessons learned
An `INSERT` column list is the single source of truth for what a
dataclass's write path actually persists - a field present on the
Python dataclass and even read back correctly by `list()` (which does
`SELECT ... discovered_at`) does not guarantee it was ever written on
that same code path. Any repository method claiming to round-trip a
dataclass field needs a test that writes a *non-default* value for that
field and reads it back, not just a test that reads back whatever the
schema default happened to produce. Once found, a bug of this shape
(silently discarding a caller-supplied value) should be fixed as soon as
a real downstream consumer (here, recurrence-interval math) depends on
correctness, rather than accumulating "documented but unfixed"
limitations indefinitely.
