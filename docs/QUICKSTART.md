# Quick Start

This is the real, verified sequence to run AEP end to end. If a step here
disagrees with the top-level `README.md` Quick Start, `README.md` is the
summary and this file is the same flow with more detail.

**Three names, one product:** PyPI distribution `aep-platform`, Python
import package `aep`, CLI command `aep`. `aep` alone on PyPI is an
unrelated project and was never an option for this one.

**Distribution status: NOT YET PUBLISHED to PyPI.** `pip install
aep-platform` does not work today — the package is built and verified but
not uploaded (see "Current distribution status" in `README.md`). Until it
is, install from this repository or a built wheel artifact, below.

## 1. Clone

```bash
git clone <this-repo-url> aep && cd aep
```

## 2. Install

No virtualenv activation required for normal use — `pip install` on any
Python 3.10–3.12 works directly (3.13 is not supported: `pgserver`, the
embedded-PostgreSQL dependency, publishes no 3.13 wheel yet).

```bash
python -m pip install .
```

This installs `psycopg2-binary`, `pgvector`, and `pgserver` (a real,
bundled PostgreSQL 16.2 + pgvector binary) as core dependencies — nothing
extra to add for the local database or the demo. Optional extras add
capabilities that don't affect local startup:

| Extra | Adds | Capability |
|---|---|---|
| `dev` | `pytest` | running the test suite |
| `api` | `flask` | the product API |
| `anthropic` | `anthropic` | real `AnthropicProvider` (code_fix) |
| `dependency-scanning` | `pip-audit` | CVE scanning |
| `infra` | `boto3`, `bc-python-hcl2`, `kubernetes-validate` | cloud adapter, Terraform HCL2 parse, K8s manifest validation |
| `sbom` | `cyclonedx-python-lib` | SBOM generation |
| `github` | `requests` | real GitHub API client |
| `all` | every extra above | everything at once |

```bash
python -m pip install ".[all,dev]"
```

## 3. Run it

```bash
aep
```

No PostgreSQL install, no Supabase, no database password, no
`AEP_PG_PASSWORD`, no `DATABASE_URL`, no npm. `aep` (no subcommand)
provisions/reuses AEP's own local embedded PostgreSQL (via `pgserver`)
under your platform's AEP data directory, applies migrations, starts the
API, and serves the pre-built UI — printing progress as it goes:

```
AEP starting...
Local database: READY  (C:\Users\you\AppData\Local\AEP)
Migrations:     READY
AI Provider:    NOT_CONFIGURED  (OmniRoute is not configured: missing env var(s) ['AI_BASE_URL', 'AI_CREDENTIAL'])
UI:             READY
Runtime:        READY

Open: http://127.0.0.1:53017
```

## 4. Open the UI

Open the printed URL in a browser. Dashboard, Projects, Task Execution,
Findings, Incidents, Approvals, Runtime, Evidence, Providers, and the
Phase 10 intelligence panels are all there — see `docs/UI-GUIDE.md`.

## 5. Run the demo

```bash
aep demo readiness
aep demo run
aep demo run --scenario ambiguous
```

`aep demo readiness` and `aep demo run` work identically whether you're
running from this cloned repository or from a plain `pip install
aep-platform` with no source checkout anywhere on the machine - neither
one needs `/src/`, `/tests/`, or a Git repository at runtime (see
BUGFIX.md BUG-0024). `aep --version` (or `-V`) prints the installed
version, read from package metadata.

See `docs/DEMO-CARD.md` for a one-page cheat sheet and
`docs/DEMO-SCENARIOS.md` for example prompts.

## Wheel install (alternative to the source checkout)

```bash
python -m pip install build
python -m build --wheel
python -m pip install dist/aep_platform-0.1.0-py3-none-any.whl
aep
```

## Pointing AEP at your own PostgreSQL instead

Setting `AEP_POSTGRES_DSN` (or any `AEP_PG_HOST`/`AEP_PG_PORT`/
`AEP_PG_USER`/`AEP_PG_PASSWORD`/`AEP_PG_DBNAME`/`AEP_PG_SSLMODE`) opts
AEP OUT of its embedded local database and onto a Postgres you manage
yourself — a shared dev server, Supabase, cloud Postgres, anything. In
that mode migrations are not applied automatically; `docs/DATABASE.md`
and `scripts/bootstrap.sh` cover that path, including applying them
yourself. This is optional and not part of the normal local flow above.

## Development setup

Contributing to AEP itself, rather than using it, additionally needs:

```bash
python -m pip install -e ".[all,dev]"
pytest
```

Editing the UI needs Node (only for development — the packaged product
needs none):

```bash
cd ui && npm ci && npm run dev
```

After a UI change, rebuild the packaged assets so they ship in the wheel:

```bash
cd ui && VITE_API_BASE= npx vite build --outDir ../src/aep/ui_dist --emptyOutDir
```
