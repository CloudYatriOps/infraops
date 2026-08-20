# AEP UI (Stage D)

A small Vite + React + TypeScript single-page app. It is a **thin view
layer over `src/aep/api/app.py`** (the Wave 1 Flask API) and contains
**no AEP business logic** — no skill resolution, no policy evaluation, no
routing decisions. Every page calls one or more API endpoints with plain
`fetch` (see `src/api.ts`) and renders the JSON it gets back. There is no
state-management library and no router library — a handful of
`useState`-switched tabs is all this size of UI needs.

## Why a UI failure can never affect the backend/runtime

This app is a separate Node/Vite process and build artifact that talks to
the API only over HTTP. It does not import any `aep` Python module, does
not run in the same process as the Flask app, and does not touch
PostgreSQL directly. If the UI crashes, fails to build, or is not running
at all, every AEP capability remains fully usable via the API directly
(`curl`) or via the `aep` CLI, which the API itself is a thin wrapper
around.

## Pages

Dashboard, Projects, Task Execution, Task Detail, Findings, Incidents,
Approvals, Runtime Status, Evidence Browser, AI Provider Status. Task
Detail and the Evidence Browser share one `EvidenceView` component
(`src/EvidenceView.tsx`) — evidence is rendered the same way in both
places, not built twice.

The Dashboard's "Compute fresh" button calls `/system/status?confirm=true`
explicitly, because that endpoint runs the full test suite
(~9–11 minutes) to compute progress/deployability. The default fast call
(`/system/status`) never triggers that; it is documented in the API
response itself. The UI never silently blocks for 9 minutes.

The Providers page renders whatever `/providers` returns as-is. Wave 1's
`/providers` endpoint never includes a credential value; the UI does not
add any additional rendering of env vars, so there is nothing here that
could regress that guarantee.

## Running locally

```bash
# 1. Start the API (from repo root), dev mode for local use:
export AEP_PG_PASSWORD=aep_local_dev_only
export AEP_API_DEV_MODE=1
python3 -m flask --app 'aep.api.app:create_app()' run

# 2. In another shell, start the UI:
cd ui
npm install
npm run dev   # http://localhost:5173
```

To point the UI at a non-default API URL or supply a real API key
(when `AEP_API_DEV_MODE` is not set), create `ui/.env.local`:

```
VITE_API_BASE=http://localhost:5000
VITE_API_KEY=aep_...
```

## Build

```bash
cd ui && npm run build   # outputs static assets to ui/dist/
```
