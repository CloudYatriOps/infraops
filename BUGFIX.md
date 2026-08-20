# Bug Fixes

## BUG-0018 (found, NOT fixed this pass - documented per BUGFIX governance): 4 pre-existing test failures unrelated to this session's local-database work

- **Date:** 2026-08-20
- **Component:** `tests/test_deployment_risk.py::test_dependency_recurrence_immediate`, `tests/test_dependency_e2e_real.py::test_real_end_to_end_dependency_remediation`, `tests/test_dependency_github_loop.py` (3 tests). Found running the release-gate full suite while verifying this session's zero-config local-PostgreSQL change on a Python 3.12 venv.

### Symptom
All 4 fail consistently (re-ran twice, not flaky). None touch
`aep.db.local_postgres`/`dsn_from_env` - `test_dependency_e2e_real.py` and
`test_dependency_github_loop.py` explicitly pass `db_backend="sqlite"`,
and `test_deployment_risk.py` uses in-memory fake repositories, so this
session's local-Postgres change cannot be the cause.
`test_dependency_recurrence_immediate` asserts a risk-horizon
classification of `IMMEDIATE` for a fixture computed from
`datetime.now()` minus a fixed day-count; it now resolves to `NEAR_TERM`
instead - consistent with a horizon boundary computed relative to a
fixture date that hasn't kept pace with the actual current date. The
`test_dependency_e2e_real.py` failure shows only a `dependency_scan` task
ever gets created (the downstream `dependency_remediate`/`run_tests`/
`dependency_rescan` tasks, which only get planned once a real
scan finds a vulnerability, never appear) - consistent with a live
scanner (pip-audit/npm audit, hitting the real registry) no longer
finding the specific historical CVE the fixture was built against.

### Impact
Not investigated further this pass - out of scope for a local-database/
packaging release (none of the 4 relate to database, migrations, or
packaging), and chasing them fully would have meant a second, unrelated
investigation on top of an already large one. Recorded here rather than
silently left as "some full-suite failures" with no trail, per this
project's own rule against undocumented gaps.

### Root cause (suspected, not confirmed)
Time/data-rot in fixtures that compute "how long ago" relative to
`datetime.now()` rather than a frozen clock, and/or live scanner results
for CVE fixtures drifting as upstream vulnerability databases and fixed
versions change over time.

### Fix
None applied this pass - flagged for a dedicated investigation.

### Tests
N/A - not fixed.

### Lesson
A test fixture built around "N days before now" or "the currently-known
CVEs for this exact pinned version" is not stable indefinitely; it should
either freeze time via dependency injection or be revisited periodically,
not treated as a one-time-verified constant.

## BUG-0017: two test-only Windows robustness gaps (sqlite file lock, `curl` exception type)

- **Date:** 2026-08-20
- **Component:** `tests/test_deployment_evidence.py`, `tests/test_cicd_github_actions.py`; found running the full release-gate suite on this machine.

### Symptom
1. `test_multiple_attempts_for_the_same_task_are_all_kept` opens a
   `StateStore` (sqlite) inside a `tempfile.TemporaryDirectory()` block
   and never calls `store.close()`. On POSIX, an open file can still be
   unlinked; Windows holds an exclusive lock until the connection object
   is closed, so `TemporaryDirectory.__exit__`'s cleanup raised
   `PermissionError` deleting `s.db`.
2. `test_live_github_actions_api_is_actually_blocked_from_this_sandbox`
   already catches `(subprocess.TimeoutExpired, FileNotFoundError)` around
   its `curl` invocation "for CI runners where curl is unavailable" - but
   on this machine, invoking `curl` raised `PermissionError` (an
   execution-policy block, not a missing binary), which the narrower
   except clause didn't cover.

### Impact
Neither is a production defect - both are test-harness gaps that made two
otherwise-passing tests fail on this specific machine for reasons
unrelated to what they're actually verifying.

### Root cause
(1) missing `store.close()` before the temp directory's own cleanup.
(2) except clause narrower than its own stated intent ("curl unavailable
... not what this test is verifying" logically covers any `OSError`
launching the binary, not just `FileNotFoundError`).

### Fix
(1) wrapped the test body in `try/finally: store.close()`. (2) widened
the except clause to `(subprocess.TimeoutExpired, OSError)`.

### Tests
Both files re-run — all 7 tests across the two files pass.

### Lesson
A sqlite connection opened inside a `tempfile.TemporaryDirectory()` block
must be explicitly closed before the block exits - this only surfaces on
Windows, so a test suite developed exclusively on POSIX won't catch it
until run cross-platform.

## BUG-0016: infra discovery used OS-native path separators and platform-default text decoding

- **Date:** 2026-08-20
- **Component:** `src/aep/infra/discovery.py`, found running the full release-gate suite on this machine (`test_infra_discovery.py` — 7 failures).

### Symptom
Two distinct defects in the same file:
1. `InfraAsset.path` was built from `str(some_path.relative_to(root))` in
   three of four call sites (Helm chart dirs, generic files, Terraform
   root/module dirs) with no separator normalization, so on Windows an
   asset's `path` was `"envs\\prod"` instead of `"envs/prod"` - every test
   asserting an exact posix-style relative path failed, and any
   downstream code/UI comparing paths against a posix-style value (CLI
   output, roadmap capability matching, etc.) would silently mismatch.
   The 4th call site (CI-workflow-directory detection) already correctly
   normalized with `.replace(os.sep, "/")`, but only used that normalized
   value locally - the stored `InfraAsset.path` for the Terraform root/
   module case still used the un-normalized one.
2. `_read_text()` called `path.read_text()` with no explicit `encoding=`,
   so it decoded under the platform's default locale encoding - UTF-8 on
   this project's Linux dev sandbox (where genuinely binary content
   correctly raised `UnicodeDecodeError` and got flagged `unreadable`),
   but Windows' default (commonly cp1252) can decode nearly any byte
   sequence without raising, so the same binary fixture silently
   "succeeded" and was never flagged.

### Impact
(1) means any consumer of infra-discovery asset paths that assumes
posix-style separators (tests, and potentially the API/UI layer) breaks
on Windows. (2) means the "unreadable files are recorded, not silently
skipped" guarantee this function exists to provide silently doesn't hold
on Windows for exactly the class of file (binary/non-UTF-8) it's meant to
catch.

### Root cause
Path-to-string conversion without `.replace(os.sep, "/")` at 3 of 4 call
sites; `read_text()` without pinning `encoding="utf-8"`.

### Fix
Normalized all `rel`/`path` constructions in `_discover` to
`.replace(os.sep, "/")` (Helm chart dir, generic file loop, and the
Terraform root/module loop - the last of which already computed a
`normalized` variable for its own `is_module` check but was still storing
the un-normalized `rel` on the asset; now stores `normalized`). Pinned
`_read_text()` to `encoding="utf-8"`.

### Tests
`tests/test_infra_discovery.py` (12 tests) re-run — all pass (was 7
failing before this fix, on this machine).

### Lesson
A relative path computed once and reused inconsistently (normalized for
a substring check, un-normalized for the stored field) is a common way a
partial fix hides a real bug - always trace every use of a `rel`-shaped
variable, not just the first one you find, and default every `read_text`/
`open` in cross-platform code to an explicit `encoding=` rather than the
platform locale.

## BUG-0015: progress engine invoked bare `"python3"`, silently reporting every phase `NOT_STARTED` on Windows

- **Date:** 2026-08-20
- **Component:** `src/aep/progress/calculator.py::_run_pytest_per_file`, found running the full release-gate suite on this machine (`test_progress_engine.py`, `test_cli_status.py` — 8 failures).

### Symptom
`compute_progress()` runs the roadmap's referenced test files once via
`subprocess.run(["python3", "-m", "pytest", ...])` and parses the
resulting JUnit XML. On this machine, `"python3"` either isn't resolvable
or resolves to an unrelated interpreter with no `pytest` installed, so the
subprocess produces no valid JUnit XML; the existing
`except (..., FileNotFoundError, OSError)`/`except ET.ParseError` handlers
(deliberately there so a real crash never gets misreported as a false
"complete") both quietly return `{t: (0, 0) for t in test_paths}` -
zero passed, zero failed, for every capability. Every phase then computed
`NOT_STARTED` instead of `COMPLETE`, and `aep status --json`'s capability
counts were wrong in the same way - not a crash, a **silently wrong
progress number**, exactly the kind of fabricated-looking output this
project's own rule against invented percentages exists to prevent.

### Impact
The platform's own headline "overall engineering completion %" - the
number this project's release process reports at every step - would read
as far lower than reality on any machine where a bare `python3` doesn't
resolve to the running interpreter, silently, with no error surfaced.

### Root cause
Hardcoded `"python3"` instead of `sys.executable` - the same class of bug
as BUG-0012, but here there is no allowlist to preserve (this is an
internal implementation detail of the progress engine, not a
security-gated `shell.run` call), so the fix is the direct one.

### Fix
Changed to `[sys.executable, "-m", "pytest", ...]` in
`_run_pytest_per_file`.

### Tests
`tests/test_progress_engine.py` (8 tests) and `tests/test_cli_status.py`
(2 of the tests that were failing) re-run — all pass.

### Lesson
A defensive `except` that silently falls back to a "safe-looking" zero
result is right to exist (a real pytest crash must never look like a
false completion), but it also means an interpreter-resolution bug here
produces no error at all - only a suspiciously-lower number. Worth
grepping for every other bare interpreter-name subprocess call in the
codebase when auditing cross-platform behavior, not just the ones that
visibly crash.

## BUG-0014: migrations and the demo fixture are not packaged inside the wheel — only work from a source checkout

- **Date:** 2026-08-20
- **Component:** `src/aep/db/migrations.py::MIGRATIONS_DIR`, `src/aep/demo.py::DEMO_TEMPLATE_DIR`; found building a real wheel and installing it into a genuinely fresh venv (Step 6/8/9 of this release pass), not assumed.

### Symptom
Both constants are computed as `Path(__file__).resolve().parent...parent`,
walking up from the installed module's location to what is *assumed* to
be the repo root, then appending `supabase/migrations` or
`demo_project_template`. Built `aep-0.1.0-py3-none-any.whl`, installed it
into a brand-new venv with no source checkout present, and confirmed
directly:
```
from aep.db.migrations import MIGRATIONS_DIR
MIGRATIONS_DIR         # .../site-packages/supabase/migrations
MIGRATIONS_DIR.exists()  # False
from aep.demo import DEMO_TEMPLATE_DIR
DEMO_TEMPLATE_DIR.exists()  # False
```
`aep --help` and every subcommand not touching migrations/the demo work
fine from the wheel install — this is not a full breakage, but migration
apply/verify and `aep demo run`/`demo readiness` cannot function from a
plain `pip install` of the wheel.

### Impact
Corrects an over-broad prior claim in this file/`handoff.md` that "clean
venv installation produced a working `aep`" — that was true for
`aep --help`/import, but migrations and the demo path were never
independently re-verified from an actual wheel install until this pass.
`supabase/migrations/` is referenced as "the single source of truth" in
~15 other files (`docs/DATABASE.md`, `ARCHITECTURE.md`, most of
`src/aep/intelligence/*.py`); physically relocating it into `src/aep/` to
make it wheel-packageable is a much larger, riskier change than this
pass's scope justifies without explicit sign-off, so it is NOT done here.

### Root cause
`supabase/migrations/` and `demo_project_template/` both live outside
`src/aep/` (the only tree `[tool.setuptools.packages.find]` packages into
the wheel), so nothing ships them - a plain `pip install .` (no `-e`) has
no way to find them relative to the installed module.

### Fix (partial, honestly scoped)
Added `AEP_MIGRATIONS_DIR`/`AEP_DEMO_TEMPLATE_DIR`/`AEP_DEMO_POLICY_PATH`
environment variable overrides (the third, `run_demo`'s default
`config/policy.yaml` lookup, is the identical gap, found live when this
fix was verified against an actual wheel install), so an operator
installing the wheel can point them at wherever they've placed a copy of
these directories (e.g. alongside a deployment). This does NOT make the
wheel self-contained -
that requires either moving both directories under `src/aep/` (schema/
demo-fixture relocation, a real but separate change) or a build step that
copies them in as package data. Documented as a known, current limitation
rather than silently left to fail with a confusing stack trace.

### Tests
Reproduced live: fresh venv, `pip install dist/aep-0.1.0-py3-none-any.whl`,
confirmed both paths missing before the fix; confirmed
`AEP_MIGRATIONS_DIR=<real path>` / `AEP_DEMO_TEMPLATE_DIR=<real path>` make
both resolve correctly after.

### Lesson
`pip install -e .` (editable) and `pip install <wheel>` are different
enough that a resource-path assumption ("N `.parent`s up from `__file__`
lands on the repo root") can pass under the former and silently fail
under the latter - Step 6 of a packaging release ("build wheel, install
in a fresh venv, re-verify") exists specifically to catch this class of
bug, and did.

## BUG-0013: `aep demo run` crashes on Windows re-run — `shutil.rmtree` can't delete git's read-only blob objects

- **Date:** 2026-08-20
- **Component:** `src/aep/demo.py::_materialize_demo_repo`, discovered running `aep demo run` a second time on the local Windows machine.

### Symptom
`PermissionError: [WinError 5] Access is denied` deleting a file under
`demo_project/.git/objects/...` on the second `aep demo run`.
BUG-0003 already made this idempotent on POSIX (delete-then-recopy the
leftover `demo_project/` dir), but git marks committed blob objects
read-only, and unlike POSIX (where the containing directory's write bit
governs deletion regardless of the file's own mode), Windows honors the
file's own read-only attribute — `shutil.rmtree` has no built-in handling
for that and raises.

### Impact
`aep demo run` — the CEO-demo happy path — cannot be re-run twice on
Windows using the documented default work dir, directly contradicting
BUG-0003's "must not crash on the second invocation" fix, which was only
ever verified on POSIX.

### Root cause
`shutil.rmtree(repo)` with no error handler; Windows requires clearing
`stat.S_IWRITE` on a read-only file before it can be unlinked.

### Fix
Added an `onerror` handler to the existing `shutil.rmtree` call that
clears the read-only attribute and retries the delete once, before
recopying the fixture. No change to the POSIX path (the handler is only
ever invoked when a delete actually fails).

### Tests
`aep demo run` run twice in a row on this machine (`--db-backend sqlite`,
no local PostgreSQL available here) — second run no longer crashes,
completes materialize → skills → policy → AI routing → security scan →
fix → re-scan → fix-bug graph, same as the first run.

### Lesson
A "no SQLite fallback"/"idempotent re-run" fix verified only on the
original POSIX sandbox is not proven cross-platform — Windows and POSIX
disagree on which side (file vs. directory) owns the delete-permission
check for a read-only file.

## BUG-0012: `shell.run`'s allowlisted binaries (`pytest`, etc.) fail to resolve unless the venv is activated

- **Date:** 2026-08-20
- **Component:** `src/aep/tools/shell_tool.py`, discovered running the demo's `run_tests` task from a genuinely fresh (never-activated) venv on the local machine.

### Symptom
`aep demo readiness`/`aep demo run` reported the `run_tests` task
`QUARANTINED` (circuit-breaker-tripped after repeated failure) even though
`pytest` was correctly installed via the `dev` extra. `shell_tool._handler`
calls `subprocess.run(args, cwd=cwd, ...)` with no explicit `env`, so
`args[0] == "pytest"` resolves via the *current process's* inherited
`PATH` — which only contains the venv's `Scripts/`/`bin` directory
(where `pytest`'s console-script shim actually lives) if the venv was
`activate`d first.

Tried anchoring to `sys.executable -m pytest` instead of a bare name
first; that broke `shell_tool.ALLOWED_BINARIES`'s exact-name allowlist
check (`args[0]` became an absolute interpreter path, not `"pytest"`),
correctly producing `BLOCKED_ON_APPROVAL` — the allowlist is a deliberate
security boundary (ARCHITECTURE.md §16) and must not be loosened to admit
arbitrary absolute paths. Reverted that approach.

### Impact
Directly contradicts this release's Step 11 requirement ("Quick Start
must NOT require users to manually activate a virtualenv") — the demo's
own `run_tests` step would silently fail on exactly the installed-CLI,
no-activation workflow the release is meant to support.

### Root cause
`subprocess.run` inherited `PATH` unmodified; nothing put the running
interpreter's own bin/Scripts directory (where every allowlisted
console-script binary from this same install actually lives) on that
`PATH`.

### Fix
`shell_tool._handler` now resolves `args[0]` via `shutil.which(name,
path=...)` against `PATH` plus `os.path.dirname(sys.executable)`, then
executes that resolved absolute path. (An earlier attempt just passed an
augmented `env=` to `subprocess.run` — that alone does not work on
Windows, where `subprocess`'s own executable search consults the real
process `os.environ`, not an `env=` override; confirmed by reproducing
the exact `FileNotFoundError` this produced before switching to
`shutil.which`.) `ALLOWED_BINARIES` and the `args[0]` allowlist check are
unchanged and still run against the original bare name — this only fixes
*resolution* of an already-allowlisted name, it does not admit anything
new. The evidence/result payload still reports the original logical
`args`, not the resolved absolute path.

### Tests
`tests/test_end_to_end_demo.py` (2 tests) re-run from a fresh,
never-activated venv — both pass; `run_tests` task now `SUCCEEDED`.

### Lesson
An allowlist that checks `args[0]` by exact name is right to reject an
absolute-path rewrite of the command; the correct fix for
activation-dependent `PATH` resolution is to fix `PATH` for the
subprocess, not to change what's being executed.

**Addendum, found running the full release-gate suite on this machine:**
`tests/test_dependency_scanning.py`'s own `_make_run_shell` helper
(deliberately mirrors `DependencyCVEAgent._run_shell`, not
`shell_tool.py`) had the identical bare-name resolution problem, one
step worse on Windows: `npm` there is really `npm.cmd`, and an
unresolved bare name raises `FileNotFoundError` inside a
`@pytest.mark.skipif(not npm_audit_scanner.is_available(...))` guard -
which runs at collection time, so it crashed collecting the *entire*
suite, not just this one test. Applied the same `shutil.which` resolution
there, plus a `try/except` around the subprocess call so a genuinely
unavailable binary now falls through to a clean `is_available() ->
False`/skip instead of an uncaught exception. Full suite re-run
afterward: collection succeeds.

## BUG-0011: dev-sandbox-only paths still present in the tracked repo (`src/aep.egg-info/`, `test_db_supabase_real.py`)

- **Date:** 2026-08-20
- **Component:** `.gitignore`/git index, `tests/test_db_supabase_real.py`; discovered during the local-machine portability audit (`grep` for `/home/`, `C:\Users\`).

### Symptom
1. `src/aep.egg-info/` (a generated build artifact `.gitignore` already
   matches via `*.egg-info/`) was nonetheless tracked in the git index
   from before the ignore rule existed, so every local build re-dirties
   `git status` with generated content.
2. `tests/test_db_supabase_real.py` hardcoded
   `SECRETS_PATH = "/home/claude/.secrets/aep_supabase.env"` — a
   dev-sandbox-only absolute path that can never exist on any other
   machine, including this one.

### Impact
(1) is repo hygiene noise, not a functional bug, but it means a build on
any machine perpetually shows a dirty `git status`. (2) means the "real
Supabase" test path is untestable anywhere except the original sandbox
even when a real Supabase secrets file legitimately exists elsewhere.

### Root cause
The egg-info directory was committed once before the `*.egg-info/`
ignore rule was added and never `git rm --cached`. The Supabase test path
was written against this one sandbox's fixed layout instead of an
env-configurable path.

### Fix
`git rm --cached -r src/aep.egg-info` (ignore rule already covers it, no
`.gitignore` change needed). `SECRETS_PATH` now reads
`AEP_SUPABASE_SECRETS_PATH` env var, falling back to
`~/.secrets/aep_supabase.env` (portable, still opt-in/skips cleanly when
absent).

### Tests
`tests/test_db_supabase_real.py` re-run standalone — same skip/blocked
behavior as before (no secrets file present), now via the portable
default path.

### Lesson
`.gitignore` only prevents new files from being tracked — it does nothing
for a path already committed before the rule existed; an audit needs an
explicit `git ls-files | grep <ignored-pattern>` check, not just a read of
`.gitignore` itself.

## BUG-0010: `aep` CLI documented as a bare command but no console-script entry point existed

- **Date:** 2026-08-20
- **Component:** `pyproject.toml`, discovered during final release-packaging clean-install verification.

### Symptom
`README.md`/`docs/QUICKSTART.md`/`docs/DEMO-CARD.md` all document running
`aep demo readiness`, `aep status`, `aep providers`, etc. as a bare `aep`
command. `pyproject.toml` had no `[project.scripts]` entry point mapping
`aep` to `aep.cli:main`. A genuinely fresh `pip install -e .` (verified in
a scratch venv with no pre-existing shims) produces no `aep` executable at
all — `which aep`/`aep --help` both fail with "command not found"; only
`python -m aep.cli ...` works. Also discovered 3 test files
(`test_cli_runtime_status.py`, `test_cli_skills.py`, `test_cli_demo.py`)
hardcoded `cwd="/home/claude/aep-platform"` in their subprocess calls,
which would fail on any machine/CI where the repo isn't cloned to that
exact path.

### Impact
Every documented Quick Start command using bare `aep ...` would have
failed with "command not found" on a clean machine, directly contradicting
this release's reproducibility goal. The 3 test files would fail outside
this sandbox's exact path, meaning "clean-machine simulation" would report
false failures on another machine even though the code itself is correct.

### Root cause
`aep.cli:main` was always invoked via `python -m aep.cli` inside this
sandbox during development, so the missing console-script entry point was
never noticed; the 3 test files were written against this sandbox's fixed
path rather than deriving the repo root from `__file__`.

### Fix
Added `[project.scripts]\naep = "aep.cli:main"` to `pyproject.toml`.
Replaced the 3 hardcoded `cwd="/home/claude/aep-platform"` occurrences
with `cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))`
(repo root derived from the test file's own location).

### Tests
Re-ran all 16 tests across the 3 affected files after the path fix — all
pass. Verified in a fresh scratch venv that `pip install -e .` now
produces a working `aep --help`/`aep status`/`aep demo readiness` as bare
commands.

### Lesson
"Runs inside this dev sandbox" and "reproducible on a clean machine" are
different claims — a console-script entry point and hardcoded dev-sandbox
paths in tests are exactly the kind of thing that only surfaces under an
actual clean-install/different-machine simulation, never under repeated
use of the same long-lived dev environment.

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
