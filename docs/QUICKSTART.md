# Quick Start

This is the exact, verified sequence to run AEP locally end-to-end. Every
command below was run in this development sandbox during the final
release-packaging pass (BUG-0008/BUG-0009). If a step here disagrees with
the top-level `README.md` Quick Start, `README.md` is the summary and this
file is the same steps with more detail — they describe the same flow.

## Dependency source of truth

`pyproject.toml` is the **only** canonical dependency declaration. There is
no `requirements.txt` in this repo, deliberately — a second, separately
maintained list would silently drift from `pyproject.toml` the first time
one file was edited and the other wasn't (this is the same failure mode
BUG-0008 already produced once, at the extras level). If your tooling
needs a `requirements.txt`-shaped file, derive it on demand rather than
hand-maintaining one:

```bash
pip install -e ".[dev,api,anthropic]"
pip freeze > requirements.txt   # optional, derived, not committed
```

## 1. Clone

```bash
git clone <this-repo-url> aep-platform && cd aep-platform
```

## 2. Virtualenv

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
```

## 3. Install

Base install includes `psycopg2-binary`/`pgvector` (the default backend is
Postgres — see BUG-0004 in `BUGFIX.md`, they are core `dependencies`, not
optional). Add extras for the capabilities you need:

| Extra | Adds | Capability |
|---|---|---|
| `dev` | `pytest` | running the test suite |
| `api` | `flask` | the Stage D REST API |
| `anthropic` | `anthropic` | real `AnthropicProvider` (code_fix) |
| `dependency-scanning` | `pip-audit` | Phase 3 CVE scanning |
| `infra` | `boto3`, `bc-python-hcl2`, `kubernetes-validate` | cloud adapter, Terraform HCL2 parse, K8s manifest validation (BUG-0008) |
| `sbom` | `cyclonedx-python-lib` | SBOM generation |
| `github` | `requests` | real GitHub API client |

```bash
pip install -e ".[dev,api,anthropic,infra,sbom,github,dependency-scanning]"
```

Minimal demo-only install: `pip install -e ".[dev,api,anthropic]"`.

## 4. Environment

```bash
cp .env.example .env
# edit .env - at minimum set AEP_PG_PASSWORD
export AEP_PG_PASSWORD=<your-local-postgres-password>
```

## 5. PostgreSQL

```bash
service postgresql start   # or your platform's equivalent (brew services, systemctl, Docker, ...)
pg_isready                 # confirm "accepting connections" before continuing
```

Database/user/extension setup is in `docs/DATABASE.md` — this file assumes
a `aep`/`aep_platform` database already exists with `pgvector` enabled.

## 6. Migrations

```bash
python3 - <<'PY'
import psycopg2
from aep.db import migrations
conn = psycopg2.connect(
    f"host=localhost port=5432 user=aep password={__import__('os').environ['AEP_PG_PASSWORD']} dbname=aep_platform"
)
migrations.apply_pending(conn)
print(migrations.status(conn))
PY
```

## 7. Start the API

```bash
export AEP_API_DEV_MODE=1   # local dev only - disables API-key auth, prints a warning
python3 -c "from aep.api.app import create_app; create_app().run(port=5000)"
```

API is now at `http://localhost:5000`.

## 8. Start the UI

```bash
cd ui
npm ci          # NOT npm install - package-lock.json exists, ci is the reproducible command
npm run dev
```

Open `http://localhost:5173` in a browser.

## 9. Run the demo

```bash
aep demo readiness
aep demo run
aep demo run --scenario ambiguous
```

See `docs/DEMO-CARD.md` for a one-page cheat sheet and
`docs/DEMO-SCENARIOS.md` for example prompts.
