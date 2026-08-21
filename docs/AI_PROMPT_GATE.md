# AI Prompt Review Gate - Machine-Readable Contract

A short, reusable review-gate contract for any change proposed to this
platform (by a human or an agent). This is a contract, not an essay -
keep additions to it just as short.

## 10 review categories

1. **scope_conflicts** - does the change touch something outside its
   stated scope (e.g. a bugfix that also refactors an unrelated module)?
2. **existing_architecture_duplication** - does the change reinvent
   something that already exists (a second routing table, a second
   skill resolver, a second state store)?
3. **db_persistence_risk** - any schema change outside
   `src/aep/migrations_sql/000N_*.sql`? Any hand-edit of an existing
   migration? Any manual `ALTER`/`CREATE`/`DROP` bypassing the migration
   runner?
4. **security_risk** - any credential/secret value (not just a var name)
   in code, logs, docs, tests, or exception messages? Any weakening of
   an existing DENY/REQUIRE_APPROVAL policy rule?
5. **ai_provider_coupling** - does the change hardcode a specific AI
   provider/model instead of routing through `AIGateway`? Does a "fake"
   test double get presented anywhere as real inference?
6. **skill_policy_boundary** - does any skill/agent code evaluate policy
   itself, construct a `PolicyDecision`, or otherwise bypass
   `PolicyEngine`'s most-restrictive-rule-wins guarantee?
7. **missing_rollback_recovery** - for anything stateful (deployment,
   schema change, runtime lease), is there a documented/tested
   rollback or crash-recovery path?
8. **missing_tests** - does new logic have a real, runnable test (not
   just a manual demonstration)? Does a new CLI command reuse tested
   underlying functions rather than duplicating logic untested?
9. **unverifiable_completion_criteria** - can "done" be checked by
   running something concrete (a test suite, a CLI command, a grep),
   or does it rely on a claim with no way to independently confirm it?
10. **excessive_scope** - does the change do meaningfully more than what
    was asked, especially into an explicitly out-of-scope stage/phase?

## Output format

```json
{
  "verdict": "PASS" | "FAIL",
  "findings": [
    {"category": "<one of the 10 above>", "severity": "blocking|advisory",
     "summary": "<one sentence>", "evidence": "<file:line or command output>"}
  ]
}
```

`verdict` is `FAIL` if any finding has `severity: "blocking"`.

## Required checks (must actually be run, not assumed)

- The new/touched test files pass standalone.
- `grep` for the literal rule being enforced (e.g.
  `grep -rn "resolve_required_skills" src/aep/`) rather than trusting a
  description of where it's called.
- Any credential-safety claim is verified by grepping actual test/log
  output for the fake placeholder value, not by re-reading the source
  that's supposed to prevent it.
- Any "no regression" claim is checked by running the pre-existing
  related test file(s), not assumed from the diff alone.

## Prohibited behaviors (automatic blocking finding)

- Presenting a fake/mock provider's output as if it were real inference.
- Any code path that silently skips a skill/policy check instead of
  stopping and escalating.
- A real secret/credential VALUE (not a var name) appearing in code,
  logs, docs, tests, or exception messages.
- A manual schema edit outside the migration runner, or editing an
  existing migration file instead of adding a new one.
- Claiming "complete"/"verified" without having personally re-run the
  verification in this session.

## Evidence requirements

Every PASS verdict must cite: (a) the exact test command run and its
pass/fail count, (b) the exact grep command(s) run for any "X is the
only place this happens" claim, and (c) the file paths touched. A PASS
with no evidence attached is itself a FAIL under category 9
(`unverifiable_completion_criteria`).
