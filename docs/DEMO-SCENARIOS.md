# Demo Scenarios — Illustrative Prompts

**`aep demo run` (and `aep demo run --scenario ambiguous`) is the one
scripted, reproducible demo** — see `docs/DEMO.md`. It runs the same real
code path every time: materialize `src/aep/demo_template/`, resolve
skills, route through `AIGateway`, run the real secret scanner, apply a
fix, re-scan, persist to Postgres.

**There is no free-text "submit a natural-language task" CLI or API
command today.** `aep run-fix-bug` takes explicit `--project`/`--repo`/
`--file`/`--description` flags (not a free-form request string), and the
API's `POST /tasks` takes a structured `{project_id, type, payload}` body
— a real `task.type` from a fixed set, not an English sentence. The
prompts below are **illustrative of the kinds of requests AEP's skill/
policy system is designed around**, not something you can currently paste
into a working command and expect the platform to parse. Treat them as a
guide to what a future natural-language front-end could route to, given
today's real `TASK_SKILL_RULES` task types
(`src/aep/skills/loader.py`: `security_scan`, `sast_scan`, `secret_scan`,
`dependency_scan`, `terraform_review`, `kubernetes_review`, `helm_review`,
`cicd_pipeline`, `deployment`, `incident_response`,
`database_migration`, `git_operation`, `github_operation`,
`architecture_review`, `code_review`, `testing`, `cost_optimization`) and
skills (`docs/SKILLS.md`'s 18 canonical skills).

Generic, project-independent examples:

1. "Scan this repository for hardcoded secrets and committed credentials."
   → maps conceptually to `secret_scan` / the `secrets` skill.
2. "Run a dependency/CVE audit on the Python and Node manifests."
   → `dependency_scan` / `dependency-cve` skill.
3. "Review this Terraform module for security misconfigurations before
   we apply it." → `terraform_review` / `terraform` skill.
4. "Check this Kubernetes manifest for privileged containers or missing
   resource limits." → `kubernetes_review` / `kubernetes` skill.
5. "Find and fix the bug where `add()` subtracts instead of adds."
   → real, working today via `aep run-fix-bug` (explicit flags, not free
   text) / `code_review`+`testing` skills.
6. "Open a pull request with this fix and watch CI until it's green."
   → `github_operation`/`cicd_pipeline` skills, Phase 2's real diagnose→
   fix→push→re-check loop.
7. "Is our current security posture ready for release?"
   → `aep security-status` (real, working today) / `security` skill.
8. "Which findings across all our projects should we fix first?"
   → real, working today: `aep prioritize` (Phase 10 Wave 1).
9. "Do we have any recurring incident patterns across projects?"
   → real, working today: `aep intelligence patterns` (Phase 10 Wave 2).
10. "What's this project's overall engineering health score?"
    → real, working today: `aep intelligence health-score` (Phase 10
    Wave 12).
11. **"Make the database faster."** → deliberately ambiguous — no target,
    no metric, no scope. This is the exact string `aep demo run
    --scenario ambiguous` uses to demonstrate refusal: AEP asks for
    clarification rather than guessing, and executes nothing.

## What is real vs. illustrative here

- Real, callable today with a structured command/flag set: prompts 5-10
  above (`aep run-fix-bug`, `aep security-status`, `aep prioritize`,
  `aep intelligence patterns`, `aep intelligence health-score`), plus
  every other `aep intelligence <subcommand>` listed in `docs/PHASE10.md`.
- Illustrative only (no free-text parser exists yet): prompts 1-4, 6 as
  phrased — the underlying skills/scanners/policy gates are real, but you
  invoke them via explicit CLI flags or a structured API task body, not
  by typing the sentence itself.
- Refusal behavior (prompt 11) is real and hand-verified — see
  `handoff.md` and `docs/DEMO.md`.
