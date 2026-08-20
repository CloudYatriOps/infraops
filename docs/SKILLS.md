# Skill Registry (Phase 9 Stage B)

This document describes the canonical AEP skill registry and the Claude
skill adapter. See ARCHITECTURE.md §32 for the full design writeup and
honest scope notes; this file is the practical "how do I use this"
reference.

## What a skill is (and isn't)

A skill is **declarative platform configuration**, not a prompt. It is a
published, immutable, versioned description of how AEP safely performs
one class of work: which real tool capabilities it may use
(`allowed_tools`), which real scanners/checks must run
(`required_checks`/`verification_rules`), which real policy actions it
must never claim to perform (`prohibited_actions`), what other skills it
depends on, and what escalation/approval rules apply.

A skill **never grants capability**. The `PolicyEngine` and
`ToolRegistry` are still the only things that actually authorize an
action; a skill only describes the intended safe procedure around
capability that already exists. This is enforced structurally (see
"Policy boundary" below), not just documented.

## Domain model

```
Skill(skill_id, name, description, purpose, scope)
SkillVersion(
    skill_id, version,                # e.g. "security", "1.0.0"
    risk_level,                       # low | medium | high
    capabilities, allowed_tools, prohibited_actions,
    required_checks, verification_rules,
    dependencies,                     # list[SkillDependency]
    escalation_rules, approval_requirements,
    input_contract, output_contract, examples,
    lifecycle_state,                  # draft | published | deprecated
    compatibility_metadata,
)
```

Publishing a corrected version is always a **new row** with a new
`version` string. `SkillRegistry.publish()` raises
`SkillImmutabilityError` if you try to publish an already-existing
`(skill_id, version)` pair — there is no "force"/"overwrite" option, by
design.

## The 18 canonical skills

`security`, `sast`, `dependency-cve`, `secrets`, `terraform`,
`kubernetes`, `helm`, `cicd`, `deployment`, `incident-response`,
`database`, `postgresql`, `git`, `github`, `architecture-review`,
`code-review`, `testing`, `cost-optimization`.

Each references only REAL existing AEP tools/scanners/policy actions —
`security`/`sast`/`secrets`/`dependency-cve` name the real scanner ids
(`gitleaks`, `semgrep`, `checkov`, `trivy`); `terraform`/`kubernetes`/
`helm` never claim a live cluster/cloud apply capability (Phase 5 is
repository-file-only); `database`/`postgresql` require the actual
migration-only, drift-detected discipline Stage A/A.5 established.

Defined in `src/aep/skills/definitions.py`, seeded through the real
`SkillRegistry.publish()` path via `seed_canonical_skills()`.

## Self-validation

`SkillRegistry.publish()` rejects any version whose `allowed_tools`,
`required_checks`, `verification_rules`, or `prohibited_actions`
reference something that does not actually exist in this platform.
`src/aep/skills/known_capabilities.py` is the source of truth for
"actually exists": a fixed enumeration of real tool capability strings
(cross-checked against a live-wired `ToolRegistry` in
`tests/test_skills_self_validation.py`), the real scanner ids imported
directly from the scanner modules' own `SCANNER_ID` constants, and the
real policy actions read fresh from `config/policy.yaml`.

## Dependency resolution

`SkillRegistry.resolve_dependencies(skill_id, version)` walks the full
transitive dependency graph and returns a `DependencyResolution` with
`ok`, `missing` (a referenced skill was never registered), `conflicts`
(no published version satisfies the requested constraint), `cycle` (the
actual cycle path, if one exists), and `resolved` (topological order).
None of these is ever silently swallowed.

Real dependency edges among the canonical skills: `deployment` →
`testing`/`security`; `terraform` → `security`/`testing`; `postgresql` →
`database`; `helm` → `kubernetes`; `sast`/`secrets`/`dependency-cve` →
`security`; `github` → `git`; `code-review`/`architecture-review` →
`testing`(/`security`); `incident-response` → `database`/`security`;
`cicd` → `testing`; `cost-optimization` → `dependency-cve`.

## Capability resolver (task → required skills)

`src/aep/skills/loader.py::TASK_SKILL_RULES` is a fixed, explicit dict —
the sole resolution mechanism today, deliberately not an AI-driven one.
`resolve_required_skills(task_type, registry, tool_capabilities=None)`
resolves every REQUIRED skill's latest published version, validates its
dependency graph, and (if a real tool-capability set is supplied)
confirms its `allowed_tools` is a subset of what the caller's tool
registry actually has. It raises `SkillResolutionError` — never silently
downgrading — if any of this fails; a caller (an agent/orchestrator
integration point) must treat that as "stop and escalate," not "proceed
without skills."

```python
from aep.skills.loader import resolve_required_skills, SkillResolutionError

try:
    resolved = resolve_required_skills("deployment", registry)
except SkillResolutionError as exc:
    # stop / escalate the task - never proceed as if skills were optional
    ...
```

## Policy boundary

Nothing in `src/aep/skills/` evaluates policy or constructs a
`PolicyDecision`. The loader only decides *which skill versions* must be
loaded; the actual authorization decision for any action a skill
describes is still made exclusively by `PolicyEngine.evaluate()`, at the
point the action is attempted, exactly as before Stage B existed. A
production `deployment.deploy` still requires human approval even once
the `deployment`/`testing`/`security` skills all resolve successfully —
proven directly in `tests/test_skills_runtime_integration.py`.

## Claude skill adapter

`src/aep/skills/claude_adapter.py::project_to_claude_skill(version)` is a
pure, deterministic function: canonical skill id + version, a
`generated_from` provenance string, markdown instructions, sorted
applicable tools, sorted verification expectations, and safety
constraints (risk level, approval requirements, escalation rules).
`render_claude_skill_markdown(version)` produces the full SKILL.md-shaped
artifact. Running the identical published version through either
function twice produces byte-identical output — there is no second,
independently-authored Claude skill definition anywhere in this
platform.

```
$ aep skills project security --markdown
---
canonical_skill_id: security
canonical_version: 1.0.0
generated_from: aep-skill-registry:security@1.0.0
name: security
description: ...
---

# security (v1.0.0)
...
```

## Evidence

`ResolvedSkillSet.evidence_payload()` returns exactly what a task's
evidence must record: task type, and for each required/optional skill
its id, version, dependencies, allowed tools, prohibited actions,
required checks, and verification rules. Attach this to a task's
`Evidence`/audit trail so a later audit can see precisely which skill
versions gated a given run.

## CLI

```
aep skills list [--seed] [--backend postgres|fake] [--json]
aep skills show <skill_id> [--version X.Y.Z] [--json]
aep skills versions <skill_id> [--json]
aep skills validate [--seed] [--json]
aep skills project <skill_id> [--version X.Y.Z] [--markdown] [--json]
```

`--backend` defaults to `postgres` (matching `db/factory.py`'s default);
`--backend fake` uses a zero-network in-memory registry, useful for a
one-off local check. `--seed` seeds the 18 canonical skills first and is
idempotent (already-published versions are left untouched).

## Change governance

Updating a published skill follows the same process as any AEP
engineering change: inspect the previous version's content, check
`BUGFIX.md` for related history, identify impacted
agents/policy/tools, evaluate backward compatibility for anything
depending on the skill, and publish a **new version** —
`SkillRegistry.publish()` structurally prevents editing the old one.

## Honest scope

- `resolve_required_skills` is a real, tested, callable pre-execution
  gate, but no existing Phase 1-8 agent's dispatch path was modified to
  call it automatically — that wiring is deliberately left for a future
  pass rather than risking the 560-test Phase 1-8/Stage A/A.5 baseline.
- No AI-assisted capability resolution exists yet; `TASK_SKILL_RULES` is
  the entire mechanism today, by design (Part 14 allows AI assistance
  only as an optional future enhancement layer, never the sole
  mechanism).
- Stage C (AI provider gateway) and Stage D (governance/docs) are not
  started.
