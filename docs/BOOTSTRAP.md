# Local Dev Bootstrap

One command, `scripts/bootstrap.sh`, does the full local setup:

```
export AEP_PG_PASSWORD=aep_local_dev_only   # or your own local Postgres password
bash scripts/bootstrap.sh
```

What it does, in order (see the script itself for the exact commands):

1. **Installs Python dependencies** — `pip install -e ".[dev,api]"`. As of
   BUG-0004's fix (see `BUGFIX.md`), `psycopg2-binary`/`pgvector` are
   REQUIRED dependencies (not an extras group) because PostgreSQL is the
   platform's default runtime backend
   (`src/aep/db/factory.py::resolve_backend`) — a bare `pip install .`
   with no extras is enough for the default path to work. `dev` adds
   `pytest`; `api` adds `flask` for the Stage D product API layer
   (`src/aep/api/`).
2. **Checks `AEP_PG_PASSWORD`/`AEP_DB_BACKEND`.** If `AEP_DB_BACKEND`
   resolves to `postgres` (the default) and `AEP_PG_PASSWORD` isn't set,
   the script fails fast with the exact `export` line to fix it, rather
   than letting a later step fail confusingly.
3. **Checks PostgreSQL is reachable** — via `pg_isready` if present,
   otherwise a direct `psycopg2.connect(...)` probe. This script does
   **not** assume any particular service manager (`service`, `systemctl`,
   Docker, a managed cloud instance, ...) — it only checks connectivity
   and, if unreachable, prints the connection details it tried plus a few
   common ways to start Postgres, then exits non-zero. Start Postgres
   however is correct for your machine, then re-run the script.
4. **Runs pending migrations** via the existing migration runner
   (`src/aep/db/migrations.py::apply_pending`) — never a manual schema
   mutation, per the platform's standing database discipline (see
   `docs/DATABASE.md`).
5. **Confirms `python3 -m aep.cli --help` runs.** There is no installed
   `aep` console-script entry point (checked `pyproject.toml` — none is
   declared); every documented usage (`README.md`, `docs/DEMO.md`) invokes
   the CLI as `python -m aep.cli`, and this is what the bootstrap script
   checks.

## What "done" looks like

```
$ AEP_PG_PASSWORD=aep_local_dev_only bash scripts/bootstrap.sh
...
python3 -m aep.cli --help ran successfully.

Bootstrap complete.

Known, expected sandbox limitations (not bootstrap failures):
  - Live OmniRoute (AI_BASE_URL/AI_CREDENTIAL unset) is UNAVAILABLE by
    design in a constrained sandbox - `aep providers` reports this
    honestly rather than faking a call.
  - Live GitHub API / live Kubernetes access may be BLOCKED by network
    egress policy in constrained sandboxes - any endpoint/command that
    needs them reports BLOCKED/UNAVAILABLE explicitly rather than
    silently succeeding or failing.
```

## The one honest caveat

**Live OmniRoute / live GitHub / live Kubernetes being UNAVAILABLE or
BLOCKED in a constrained sandbox is expected, not a bootstrap failure.**
These are network-egress-policy blocks (or missing `AI_BASE_URL`/
`AI_CREDENTIAL`), the same "sandbox has no route out" situation
documented throughout `handoff.md`/`ARCHITECTURE.md` for Stage C. The
bootstrap script's job is to get the platform itself running against a
real local Postgres — it does not (and should not) fake these external
integrations into looking reachable.

## Next steps after bootstrapping

- `python3 -m aep.cli demo run` — the reproducible end-to-end demo (see
  `docs/DEMO.md`).
- Start the Stage D product API (see `docs/API.md`):
  ```
  export AEP_API_DEV_MODE=1   # local-only: disables auth entirely, loudly
  python3 -c "from aep.api.app import create_app; create_app().run(port=8000)"
  ```
