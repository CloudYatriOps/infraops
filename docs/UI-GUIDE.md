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

This is the primary product workflow (`pip install aep-platform` → `aep`
→ Projects → add an existing repository → Scan Now). Lists projects
(`GET /projects`, excludes archived/deleted ones), lets you add an
existing local repository (`POST /projects`, immediately shows its
auto-detected capabilities), and opens a **Project Detail** view per
project (`ui/src/pages.tsx::ProjectDetail`) covering the full scan
lifecycle - see "Project Detail" below. Every project row shows its
**Analysis** state (`NEVER_SCANNED`/`COMPLETED`/`COMPLETED_WITH_FINDINGS`/
etc. - see `aep.scan_lifecycle.analysis_state()`), never a stale "no
findings" for a project that has never actually been scanned.

### Project Detail

Everything here reads/writes through `aep.scan_lifecycle`, which itself
calls the exact same `aep.scan.scan_project()` the CLI's `aep scan`
uses - the UI and CLI can never disagree about what a repository is or
what was found in it (see BUGFIX.md for the review that established
this).

- **Top** — name, repository path, detected capabilities, last scan
  time, and the current Analysis state, plus **Scan Now**/**Rerun
  Scan** (`POST /projects/<id>/scan`) and **Delete Project**
  (`DELETE /projects/<id>` - archives, explained inline before you
  confirm; never touches files on disk or scan history - see BUG-0026's
  sibling migration `0008_project_archive.sql`).
- **Analysis summary** — Detected / Analyzed / Skipped / Blocked, pulled
  directly from the latest persisted scan's report.
- **Security posture** — one row per analyzer (`PASS`/`FAIL`/`SKIPPED`/
  `UNAVAILABLE`/`BLOCKED`) with its real reason string, never a made-up
  percentage.
- **Trust** — the Trust Contract read-model for the current scan
  (`GET /tasks/<scan_id>/trust`, `src/aep/trust.py` - Trust-First
  Architecture Review P0). Shows **Trust Level** (`L0`/`L1`/`L2` -
  `L3`-`L5` are not implemented yet) and **Verification**
  (`VERIFIED`/`PARTIALLY_VERIFIED`/`UNVERIFIED`/`CONTRADICTED` - never a
  numeric confidence headline), plus what was actually verified, what
  was **NOT** verified (always listed explicitly, never a silent
  omission), the matched policy rule, and rollback availability. A
  read-only scan is always at most `L1`: AEP never claims `L2`
  ("verified remediation") for an action that mutated nothing.
- **Findings** — a real table with a "Details" button per finding
  (exact file/line, rule, explanation, and a reminder that remediation is
  a separate action AEP never applies automatically).
- **Report** — download the current scan's report as JSON (machine-
  readable) or Markdown (executive-readable, `GET
  /projects/<id>/report?format=markdown`) - client-side blob download,
  nothing server-rendered as a file.
- **Timeline** — the real `Event` rows logged for that scan run
  (`scan.started`, one `scan.<analyzer>_completed` per analyzer that
  actually ran, `scan.report_generated`, `scan.completed`/`scan.failed`)
  - no fabricated progress percentage, ever.
- **Scan history** — every previous run for this project
  (`GET /projects/<id>/scans`), each independently viewable and never
  overwritten by a rerun, plus a same-page comparison against the
  previous run (new/resolved/unchanged finding counts).

Also still renders the three Phase 10 intelligence panels
(`ProjectIntel` component) below the scan lifecycle section:

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

In-product help (`<details>` "Help" sections, no separate documentation
page) sits next to Projects, the scan/empty state, Security posture, and
Report - short, concrete answers ("What does PASS mean?", "Does AEP
modify my repository?", "Can AEP delete my source code?"), never the
full architecture document.

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
