# AEP Web UI Guide

A short, practical tour of the actual screens in `ui/` (Vite + React +
TypeScript). This is not a design doc — see `ui/README.md` for why the UI
is architecturally incapable of affecting the backend, and `ARCHITECTURE.md`
§34/§47 for the Stage D/Phase-10-UI addenda. Every screen below is real and
verified against `ui/src/App.tsx` and `ui/src/pages.tsx`.

There is no router and no state-management library — the app is a single
page with a sidebar tab bar (`useState`-switched), calling one or more of
the Wave 1 API endpoints per tab via the thin `ui/src/api.ts` fetch
wrapper. No AEP logic (skill resolution, policy evaluation, AI routing) is
reimplemented in TypeScript anywhere.

The visual style (`ui/src/index.css`) is a dark, restrained
glassmorphism console — translucent blurred card surfaces over a near-black
base, five visually distinct status colors for `PASS`/`FAIL`/`SKIPPED`/
`UNAVAILABLE`/`BLOCKED` (`StatusBadge` in `ui/src/components.tsx` is the
single place that maps a status string to a color — every page uses it,
nothing hardcodes a badge color). This is styling only; no data flow,
component structure, or API contract changed.

## Nav tabs (exact labels, top to bottom in the sidebar)

`Dashboard`, `Projects`, `Task Execution`, `Task Detail`, `Findings`,
`Incidents`, `Approvals`, `Runtime`, `Evidence`, `Providers`.

### Dashboard

Calls `GET /system/status` (fast) by default. A "Compute fresh" button
explicitly calls `GET /system/status?confirm=true` instead, because that
variant re-runs the real test suite (roughly 9–11 minutes) to compute a
live progress/deployability number — the UI never triggers this
automatically or blocks silently waiting on it.

### Projects

Lists projects (`GET /projects`), lets you create one
(`POST /projects`), and — when you select a project — renders the
**Project Detail** view with three intelligence panels built during the
Phase 10 UI work (`ProjectIntel` component in `ui/src/pages.tsx`):

- **Engineering health** — `GET /intelligence/health-score?project_id=...`
  (Phase 10 Wave 12: an aggregate score built from every other Phase 10
  intelligence module, never an unexplained single number).
- **Cost intelligence** — `GET /intelligence/cost?project_id=...`
  (Phase 10 Wave 5). Honestly reports `BLOCKED` in this sandbox — no real
  cloud cost/billing data exists here; the UI shows this status as-is
  rather than hiding or faking a number.
- **Remediation decisions** — `GET /intelligence/remediation-decision?project_id=...`
  (Phase 10 Wave 10). Classification only — the panel shows a decision
  category, never a button that executes anything; actual remediation
  still goes through the existing orchestrator/skill/policy pipeline via
  Task Execution.

### Task Execution

A form over `POST /tasks` — submit a `project_id`/`type`/optional
`owner_agent`/`payload`. On success it opens the newly created task in
Task Detail.

### Task Detail

`GET /tasks/<id>` plus `GET /tasks/<id>/evidence`, rendered through a
shared `EvidenceView` component — the same component the Evidence
Browser uses, so evidence never renders two different ways depending on
which screen you're looking at it from.

### Findings

`GET /findings[?project_id=...]` — a flat list of persisted
`FindingRecord`s across whichever project(s) your API key can see.

### Incidents

`GET /incidents/<project_id>` — persisted operational incidents for one
project (Phase 7 incident memory).

### Approvals

`GET /approvals[?project_id=...]` plus the three action buttons
(`POST /approvals/<id>/approve|reject|pause`) for tasks sitting in
`BLOCKED_ON_APPROVAL`.

### Runtime

`GET /runtime/status` — live Phase 8 runtime operational status (workers,
leases, scheduled jobs), separate from the Dashboard's development-percent
view.

### Evidence

A standalone evidence browser (same `EvidenceView` component as Task
Detail) for looking up a task's evidence independent of the Task
Execution flow.

### Providers

Renders whatever `GET /providers` returns as-is — every registered AI
provider/model, which is default/fallback, the routing table, and
OmniRoute's real (not faked) reachability. `/providers` never includes a
credential value server-side, and the UI adds no additional env-var
rendering, so there is nothing here that could leak one.

## Running it

See the Quick Start in `README.md`, or `ui/README.md` for the full detail
(including how to point the UI at a non-default API URL or a real API
key via `ui/.env.local`).
