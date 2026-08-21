# AEP — Autonomous Engineering Platform

A local-first engineering and DevSecOps control plane: policy-gated task
orchestration, a versioned skill registry, real security/dependency/
infrastructure analysis, and cross-project intelligence — with a
zero-config embedded PostgreSQL and a packaged web UI.

No PostgreSQL install. No Supabase. No remote database. No Node/npm.

## Install

```bash
pip install aep-platform
```

> **Not yet published to PyPI.** The package is built and verified but not
> uploaded. Until then, install from a clone — identical result:
> `git clone <this-repo-url> aep && cd aep && python -m pip install .`
>
> Names differ on purpose: PyPI distribution `aep-platform`, Python import
> package `aep`, CLI command `aep`. (`aep` on PyPI is an unrelated project.)

Python 3.10–3.12. Not 3.13 — the embedded-PostgreSQL dependency publishes
no 3.13 wheel yet.

## Start

```bash
aep
```

Starts everything and prints where to go:

```
AEP starting...
Local database: READY  (C:\Users\you\AppData\Local\AEP)
Migrations:     READY
AI Provider:    NOT_CONFIGURED
UI:             READY
Runtime:        READY

Open: http://127.0.0.1:53017
```

## Analyze an existing project

```bash
aep scan /path/to/project
```

AEP detects what the repository actually is — from evidence on disk, never
from directory names — and runs only the checks that apply:

```
Detected:
  APPLICATION, PYTHON, TERRAFORM, CI_CD

SECURITY POSTURE
  Secrets       PASS
  SAST          SKIPPED
  Dependencies  PASS
  IaC           FAIL
  Containers    SKIPPED
```

Statuses are precise and not interchangeable:

| Status | Meaning |
|---|---|
| `PASS` / `FAIL` | applicable, ran, clean / found something |
| `SKIPPED` | **not applicable** — no Terraform files, no Chart.yaml, etc. |
| `UNAVAILABLE` | applicable, but this AEP install can't provide it |
| `BLOCKED` | applicable, but an external precondition (registry, credentials) prevents it |

`aep scan` is **read-only**: it never modifies, installs into, commits to,
or deploys the target repository. Remediation is a separate, explicit
action. Add `--json` for machine-readable output.

`aep security <path>` and `aep infra <path>` give the same read-only
analysis filtered to just security or just infrastructure — useful when
that's all you want the answer to. Every pre-existing command
(`security-status`, `infra-status`, `tasks`, `events`, …) still works
exactly as before; `scan`/`security`/`infra` are additions, not
replacements. `aep --help` shows a short, curated command list; every
subcommand's own `--help` is unchanged.

## What it does

- Secret detection (built in — no external binary required)
- SAST, dependency/CVE intelligence
- Infrastructure analysis (Terraform / Kubernetes / Helm, built in)
- Engineering health, remediation decisions, cross-project intelligence
- Deny-by-default policy enforcement and a versioned skill registry
- Durable execution history and evidence in local PostgreSQL + pgvector
- Packaged web UI, served by AEP itself

## Demo

```bash
aep demo run
```

```bash
aep demo run --scenario ambiguous
```

The second one is the interesting one: given an under-specified request
("make the database faster"), AEP refuses and asks for clarification
rather than guessing at scope.

## Diagnostics

There is no `aep doctor`. The same information comes from commands that
already exist: `aep` / `aep start` (prints database, migrations, provider,
UI, runtime at startup), `aep status`, `aep progress`, `aep providers`,
`aep demo readiness`, `aep --version` (or `-V`).

`aep demo readiness` and `aep demo run` work the same whether you
installed from a clone or from `pip install aep-platform` with no
source repository present at all - neither needs `/src/`, `/tests/`, or
a Git checkout at runtime (see BUGFIX.md BUG-0024).

## External integrations (all optional)

AI providers, GitHub, cloud (AWS/Azure/GCP/OCI), and Kubernetes are
optional and require your own credentials. AEP starts and runs fully
without any of them, and reports each honestly as `NOT_CONFIGURED`,
`BLOCKED`, or `UNAVAILABLE` rather than pretending.

## Current limitations

- Not yet on PyPI (install from a clone).
- Python 3.13 unsupported (upstream wheel gap).
- Container image scanning is `BLOCKED` — it needs registry access and a
  vulnerability database that cannot be shipped self-contained.
- SAST needs the optional extra: `pip install "aep-platform[sast]"`
  (semgrep is 45–79MB, deliberately not forced on every install).
- Install verified on Windows; macOS/Linux wheels exist but are not
  install-verified.

## Documentation

| Topic | Where |
|---|---|
| Full README / phase history | [docs/README-FULL.md](docs/README-FULL.md) |
| Architecture & threat model | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Quick start (detailed) | [docs/QUICKSTART.md](docs/QUICKSTART.md) |
| Database & migrations | [docs/DATABASE.md](docs/DATABASE.md) |
| Demo walkthrough | [docs/DEMO.md](docs/DEMO.md) · [docs/DEMO-CARD.md](docs/DEMO-CARD.md) |
| UI guide | [docs/UI-GUIDE.md](docs/UI-GUIDE.md) |
| Known defects & fixes | [BUGFIX.md](BUGFIX.md) |
