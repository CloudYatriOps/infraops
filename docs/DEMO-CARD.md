# AEP Demo Cheat Sheet

**START**
```
service postgresql start   # if not already running
export AEP_PG_PASSWORD=aep_local_dev_only
```

**RUN DEMO**
```
aep demo readiness
aep demo run
aep demo run --scenario ambiguous
```

**OPEN UI**
```
export AEP_API_DEV_MODE=1
python3 -c "from aep.api.app import create_app; create_app().run(port=5000)"
# in another shell:
cd ui && npm ci && npm run dev
```
→ http://localhost:5173

**TRY**
- `aep demo run` — normal, happy-path: recon → code_fix → security_scan
  (blocks on a real detected secret) → fix applied → clean re-scan →
  run_tests, all SUCCEEDED.
- `aep demo run --scenario ambiguous` — type "make the database faster"
  conceptually; the platform REFUSES with a clarifying question and
  executes nothing (confirmed via `run_ambiguous_demo()` in
  `src/aep/demo.py`).
- `aep intelligence patterns` — real cross-project incident-pattern
  detection over whatever findings exist in your local Postgres.

**WHAT TO WATCH**
- **Skills** — which canonical skill versions gated the task (evidence
  payload, `docs/SKILLS.md`).
- **Policy** — deny-by-default evaluation; a real secret always blocks,
  never a WARN.
- **Provider** — `aep providers` shows the AI Gateway routing to
  `FakeAIProvider` honestly (OmniRoute UNAVAILABLE — no `AI_BASE_URL` set).
- **Execution** — the real fix applied to `src/aep/demo_template/`'s copy.
- **Verification** — a real second security scan and a real `pytest` run,
  never assumed.
- **Evidence** — persisted to real PostgreSQL, viewable via the UI's
  Task Detail / Evidence Browser.
