# AEP — Autonomous Engineering Platform

A local-first engineering and DevSecOps control plane: project
auto-detection, real security/infrastructure analysis, cross-project
engineering intelligence, and a packaged web UI — with a zero-config
embedded PostgreSQL.

No PostgreSQL install. No Supabase. No remote database. No Node/npm.
**No AI API key required** — AI providers are entirely optional (see
[Optional AI providers](#optional-ai-providers) below).

## Install

```bash
pip install aep-platform
```

Python 3.10–3.12. Not 3.13 — the embedded-PostgreSQL dependency publishes
no 3.13 wheel yet.

## Start

```bash
aep
```

Provisions the local database, applies migrations, and serves the API +
packaged UI, then prints the URL to open. No password, no config file,
no separately-installed PostgreSQL.

## Analyze an existing project

```bash
aep scan /path/to/project
```

AEP detects what the repository actually is — from evidence on disk,
never from directory names — and runs only the checks that apply, each
with a precise, non-interchangeable status (`PASS`/`FAIL`/`SKIPPED`/
`UNAVAILABLE`/`BLOCKED`). Read-only: it never modifies, installs into, or
deploys the target repository. The same workflow is available from the
UI's Projects screen (Add existing project → Scan Now), and every scan
is persisted — visible after a browser refresh or an AEP restart, not
just in that one CLI invocation's output.

## UI

Open the URL `aep` prints. **Projects** is the primary workflow:

```
Projects → Add existing project → Scan Now → Findings / Report / Timeline
```

Add an existing local repository, then **Scan Now** — the UI runs the
exact same read-only engine as `aep scan` and persists the result:
detected capabilities, security posture, findings (click one for exact
location/evidence/explanation), a downloadable report (JSON or
Markdown), and a real timeline of what the scan actually did. **Rerun
Scan** creates a new run without erasing the last one, so history and a
before/after comparison are always available. **Delete Project** only
removes AEP's own record — it never touches files on disk, your Git
repository, or scan history. Dashboard, Findings, Approvals, Evidence,
Runtime, and Providers cover the rest of the platform.

## Security

Built-in secret detection and infrastructure scanning (Terraform/
Kubernetes/Helm) work with zero external binaries. SAST is an optional
extra (`pip install "aep-platform[sast]"`, semgrep) since it's 45–79MB
and not every repository needs it. Container image scanning is honestly
reported `BLOCKED` — it needs registry access this local-first product
does not provide, rather than being shipped broken.

## Optional AI providers

AEP works fully without an AI provider — local engineering (detection,
scanning, intelligence, evidence) never depends on one. AI is used only
for AI-assisted reasoning/routing and is configured via environment
variables (`AI_BASE_URL`, `AI_CREDENTIAL`, optional `AI_PROVIDER` label)
pointing at your own Claude/Gemini/OpenAI/OmniRoute-compatible endpoint —
never a credential typed into the UI or stored in the browser. Check
status with `aep providers` or the UI's Providers screen.

## License

MIT — see [LICENSE](LICENSE). Dependency license audit:
[docs/LICENSES.md](docs/LICENSES.md).

## Documentation

| Topic | Where |
|---|---|
| Full README / phase history | [docs/README-FULL.md](docs/README-FULL.md) |
| Architecture & threat model | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Quick start (detailed) | [docs/QUICKSTART.md](docs/QUICKSTART.md) |
| Database & migrations | [docs/DATABASE.md](docs/DATABASE.md) |
| UI guide | [docs/UI-GUIDE.md](docs/UI-GUIDE.md) |
| Dependency licenses | [docs/LICENSES.md](docs/LICENSES.md) |
| Known defects & fixes | [BUGFIX.md](BUGFIX.md) |
| Release/QA demo walkthrough (developer tool, not a product feature — `aep demo readiness`/`aep demo run`) | [docs/DEMO.md](docs/DEMO.md) · [docs/DEMO-CARD.md](docs/DEMO-CARD.md) |
