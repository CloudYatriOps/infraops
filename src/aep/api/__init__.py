"""Phase 9 Stage D (Wave 1): thin HTTP API layer over the existing AEP
engine. See docs/API.md for the full surface, auth model, and the
explicit "no secret ever leaves this layer" guarantee.

Nothing in this package re-implements orchestrator/skill/policy logic -
every handler in `app.py` calls the same `Orchestrator`/`SkillRegistry`/
`PolicyEngine`/repository functions the CLI (`src/aep/cli.py`) already
uses. This package only adds: HTTP routing/JSON marshalling (Flask,
the one new dependency - see the `api` extra in pyproject.toml) and a
minimal per-request API-key auth boundary (`auth.py`).
"""
