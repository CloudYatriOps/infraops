# Product API (Phase 9 Stage D, Wave 1)

A THIN HTTP layer over the existing AEP engine — `src/aep/api/app.py`.
Every handler calls the same underlying `Orchestrator`/`SkillRegistry`/
`PolicyEngine`/repository code the CLI (`src/aep/cli.py`) already uses.
No business logic is reimplemented here: this is routing + JSON
marshalling + a minimal auth boundary, nothing else.

Technology: [Flask](https://flask.palletsprojects.com/) — the one new
dependency this wave adds (`pyproject.toml`'s `api` extras group,
`flask>=3.0`). Chosen over stdlib `http.server`/`wsgiref` because JSON
routing by hand across ~20 routes would itself become a small
reimplementation of what Flask already does correctly; chosen over
FastAPI/Django because this is the smallest dependency that gets
routing/JSON handling right without an ASGI server stack.

This is Wave 1 (backend/API only). A second wave builds the UI on top of
this API — nothing here renders HTML.

## Running it

```
export AEP_PG_PASSWORD=aep_local_dev_only
export AEP_API_DEV_MODE=1     # local dev only - see Auth model below
python3 -c "from aep.api.app import create_app; create_app().run(port=8000)"
```

## Auth model

Every request except `GET /health` requires `Authorization: Bearer
<key>`, checked against a new `api_keys` table
(`src/aep/migrations_sql/0007_api_auth.sql`):

- `key_hash` — sha256 of the raw key. **The raw key itself is never
  stored** — only its hash, so a database dump alone cannot be used to
  authenticate.
- `project_scope` — nullable. `NULL` means the key is org-wide (any
  project); a project id scopes the key to exactly that one project.
  Any route that resolves a `project_id` (tasks, findings, incidents,
  deployments, approvals) checks the caller's key scope and returns
  `403` on a mismatch.
- `revoked_at` — set once, never un-set; a revoked key is rejected the
  same way an unknown one is.

Issue a key (from a Python shell, or wire up a small admin script — no
HTTP route exposes key issuance in this wave, since a key-issuing
endpoint is itself a privileged operation this wave deliberately keeps
out of the HTTP surface):

```python
from aep.api.app import create_app
from aep.api import auth

app = create_app()
key_id, raw_key = auth.issue_key(app.config["AEP_POOL"], label="my-key")
print(raw_key)  # shown once - store it now, it cannot be retrieved again
```

Every authenticated request is logged through the SAME event-logging
mechanism the rest of the platform uses (`EventLogger.log` ->
`store.append_event`) — there is no second audit log. Org-wide requests
(no project scope) are logged against one fixed, auto-provisioned
sentinel project row (`00000000-0000-0000-0000-000000000000`), since
`events.project_id` is a `NOT NULL` foreign key and there is no "no
project" event in the existing schema.

### Dev-mode bypass

`AEP_API_DEV_MODE=1` disables authentication entirely — every request is
treated as an unscoped, org-wide caller. The app prints a loud warning
at startup whenever this is set:

```
*** AEP_API_DEV_MODE=1: API AUTHENTICATION IS DISABLED. Never run this way outside local development. ***
```

This exists so a local demo/dev loop doesn't require standing up a key
just to try the API. **This is a documented, intentional security
boundary that must never be set in a shared or production deployment.**
There is no production hardening beyond this in Wave 1 — a real
organization/user model (accounts, roles, per-user keys, key rotation,
rate limiting) is a documented future step, not built here. This wave's
`api_keys` table is the smallest real primitive that gives genuine
project-scoped isolation today; it is explicitly not a full multi-tenant
auth system.

## Guarantee: credentials never leak through this API

`GET /providers` never returns `AI_CREDENTIAL`'s value or anything
derived from it — verified by
`tests/test_api_app.py::test_provider_credential_never_leaks_in_api_response`,
in the same style as `tests/test_ai_gateway_credential_safety.py`. The
underlying `_build_providers_payload()` (reused verbatim from
`src/aep/cli.py` — not reimplemented) never reads the credential value
into the payload in the first place; only provider/model
metadata and OmniRoute's honest reachability status are exposed.

## Route surface

All routes return JSON. `project_id`s are Postgres `uuid` values (see
`src/aep/migrations_sql/0001_initial_schema.sql`) — a non-uuid lookup
value is reported as `404`, never a `500`.

| Method | Path | Calls into |
|---|---|---|
| GET | `/health` | (no auth, trivial liveness check) |
| GET | `/projects` | `PostgresProjectRepository.list()` |
| POST | `/projects` | `PostgresProjectRepository.save()` |
| GET | `/projects/<id>` | `PostgresProjectRepository.get()` |
| GET | `/repositories/<project_id>` | project's `repo_path` + `git remote get-url origin`; reports GitHub as `unavailable`/`not_github` rather than making a live API call |
| GET | `/agents` | `bootstrap.build_default_agents()` (read-only listing) |
| GET | `/skills` | `SkillRegistry.list_skills()`/`list_versions()` — same calls `aep skills list` makes |
| GET | `/skills/<id>` | `SkillRegistry.latest_version()` — same as `aep skills show` |
| GET | `/skills/<id>/versions` | `SkillRegistry.list_versions()` — same as `aep skills versions` |
| GET | `/providers` | `cli._build_providers_payload()` (reused directly, not reimplemented) |
| GET | `/findings?project_id=&severity=` | `PostgresFindingRepository.list()` |
| GET | `/incidents/<project_id>` | `operations.memory.list_incidents()` — same as `aep incident-status` |
| GET | `/deployments/<project_id>` | `deployment.evidence.list_deployment_evidence()` — same as `aep deploy-status` |
| POST | `/tasks` | `Orchestrator.submit_graph()` + `Orchestrator.run_task()` — the SAME policy gate (`_apply_generic_policy_gate`), skill gate (`_apply_skill_gate`), and `agent.run()` dispatch the CLI's `run_to_completion` loop uses |
| GET | `/tasks/<id>` | `store.get_task()` |
| GET | `/tasks/<id>/evidence` | `task.evidence` (same field the CLI/task record already carries) |
| GET | `/approvals?project_id=` | `store.list_tasks(statuses=[BLOCKED_ON_APPROVAL])` |
| POST | `/approvals/<id>/approve` | `Orchestrator.approve()` — same `TaskStatus`/`approval_status` transition the orchestrator already performs |
| POST | `/approvals/<id>/reject` | `Orchestrator.reject()` |
| POST | `/approvals/<id>/pause` | audited event only — `TaskStatus` has no separate PAUSED state; inventing one would be a second, parallel state machine (documented limitation) |
| GET | `/runtime/status` | `runtime.status.build_runtime_status_payload()` — same as `aep runtime-status` |
| GET | `/system/status?confirm=true` | `progress.calculator.compute_progress()` / `progress.deployability.compute_deployability()` — **slow** (see below) |

### `/tasks` really runs through the orchestrator, not a second engine

Verified by grep:

```
$ grep -n "class.*Orchestrator\|def run_task" src/aep/orchestrator.py
34:class Orchestrator:
221:    def run_task(self, task: Task) -> None:
```

`src/aep/api/app.py::create_task` calls `orch.submit_graph(...)` then
`orch.run_task(task)` on a real `Orchestrator` instance constructed the
same way `bootstrap.build_orchestrator` does (same `agents` dict, same
`PolicyEngine.from_yaml`, same shared `skill_registry`) — it does not
reimplement policy/skill gating or agent dispatch anywhere.

### `GET /system/status` is genuinely slow — this is documented, not hidden

`compute_progress()` runs a real pytest invocation over every roadmap
`test_paths` entry (~9-11 minutes) — exactly as slow as the full test
suite, because it *is* effectively a full suite run. This endpoint does
**not** fake a fast response or time out silently: calling it without
`?confirm=true` returns `202` with an explanation of the cost; calling
it with `?confirm=true` actually runs it and blocks for the full
duration. A future wave could move this to a background-job pattern
(kick off async, poll a job id) — not built in Wave 1, since polling
infrastructure is its own feature and this wave's job was exposing the
existing computation honestly, not redesigning it.

## Wave 2 additions

- **Project isolation, enforced (not just stored):** `project_scope` on
  an issued key is enforced on every endpoint that takes a `project_id`,
  including the two endpoints where it's an *optional* filter
  (`/findings`, `/approvals`) — a scoped key omitting `project_id`
  entirely is still pinned to its own project, never widened to see
  every project. This closed a genuine gap found in Wave 2 review; see
  `BUGFIX.md` BUG-0005.
- A small React/TypeScript UI (`ui/`) now calls this API directly; it
  adds no new routes and reimplements no logic — see `ui/README.md`.

## What Wave 1 does NOT do (explicitly out of scope)

- No UI — a second wave builds on top of this API.
- No key-issuance HTTP endpoint (see Auth model above).
- No new "environments"/"enabled skills"/"schedules" project-metadata
  fields or migration — `ProjectRecord` (see `src/aep/db/models.py`)
  wasn't extended for this beyond what genuinely required it
  (`api_keys`); a future wave that needs richer per-project metadata
  should add a real, justified migration then, not speculatively now.
- No live GitHub/Kubernetes calls from any route — reported
  BLOCKED/UNAVAILABLE explicitly wherever relevant, never faked.
