# AEP Demo Cheat Sheet

Not on PyPI — install from this repo or a built wheel (see
`docs/QUICKSTART.md`).

**INSTALL**
```
git clone <this-repo-url> aep && cd aep
python -m pip install .
```

**START**
```
aep
```
No PostgreSQL install, no Supabase, no password, no npm. This starts the
local database, applies migrations, and serves the API + UI, then prints
the URL to open.

**OPEN UI**
```
Open the URL `aep` printed (e.g. http://127.0.0.1:53017).
```

**CHECK VERSION**
```
aep --version
```

**RUN DEMO**
```
aep demo readiness
aep demo run
```
Both work the same from a plain `pip install aep-platform` with no
source checkout present - see BUGFIX.md BUG-0024.

**RUN AMBIGUOUS DEMO**
```
aep demo run --scenario ambiguous
```

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
