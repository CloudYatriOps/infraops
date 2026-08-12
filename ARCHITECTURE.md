# Autonomous Engineering & DevSecOps Platform — Architecture

Status: Phase 1 and Phase 2 (GitHub integration) are implemented and tested
in this repository. Phases 3–7 are specified below to their
component-contract level; several have partial reference implementations
(recon, code-agent, testing-agent, a deterministic secret scanner) so the
seams are real code, not prose. Nothing here claims capability the repo
doesn't demonstrate — see the "What is and isn't real" section at the end,
and §23 for what's specifically true of Phase 2.

## 0. Framing

This is a control plane, not a chatbot with file access. The AI model is a
replaceable reasoning component invoked through an adapter interface
(`AIProvider`). Everything that makes the system trustworthy — task state,
retries, policy, audit, verification — lives in deterministic platform code
that does not depend on any model vendor.

Two ideas recur throughout and explain most of the design choices:

1. **The model proposes, the platform decides.** An `AIProvider` call can
   suggest a patch, a plan, or a risk rating. It never directly mutates
   state, calls a tool, or crosses a policy boundary — the orchestrator does
   that, after checking the policy engine, and it writes down what happened
   either way.
2. **Nothing is true until it's re-checked.** "Tests pass," "CVE fixed,"
   "secret removed," and "deployment succeeded" are all claims until a
   deterministic tool (pytest, a scanner, a git-history grep, a health
   check) re-produces the evidence. The `Evidence` field on a `Task` is
   never a model's prose — it's the captured stdout/exit-code/scanner output
   of the tool that ran.

## 1. System Boundaries

**In scope for the platform core:** task orchestration, state persistence,
tool execution, policy evaluation, approval workflow, audit/event log, model
routing, failure classification/retry, and a project-adapter layer so none
of the above hard-codes a specific repo, cloud, or vendor.

**Out of scope for the core, delegated to adapters:** how to talk to a
specific git host, cloud provider, Kubernetes cluster, CI system, secret
manager, or model vendor. The core only knows the `Tool` and `AIProvider`
interfaces.

**Out of scope for this repository, by environment:** this session runs in
an ephemeral sandbox container with no cloud credentials, no live
Kubernetes cluster, no CI runner, and no durable 24/7 host. Phase 1 proves
the orchestration core against a local filesystem/git/shell environment.
Phases 3–5's cloud/k8s/CI adapters are specified with concrete interfaces
and one reference implementation each (local-only) so a real credential can
be dropped in later without touching the orchestrator.

## 2. Component Map

```
                         ┌─────────────────────────────┐
                         │        Orchestrator          │
                         │  intake → decompose → graph  │
                         │  schedule → dispatch → retry  │
                         └──────────────┬────────────────┘
                                        │
        ┌────────────────┬─────────────┼─────────────┬────────────────┐
        │                │             │             │                │
  ┌─────▼─────┐   ┌──────▼──────┐ ┌────▼────┐  ┌─────▼──────┐  ┌──────▼──────┐
  │ Task Engine│   │Policy Engine│ │  Tool   │  │AI Provider │  │  Failure    │
  │ (state     │   │ ALLOW/DENY/ │ │ Registry│  │  Router    │  │ Classifier  │
  │ machine +  │   │REQUIRE_APR/ │ │(capabil-│  │(Claude/    │  │(retry, back-│
  │ SQLite     │   │   WARN      │ │ ities,  │  │ OpenAI/    │  │ off, circuit│
  │ durability)│   │             │ │ risk,   │  │ Gemini/    │  │  breaker)   │
  └─────┬──────┘   └──────┬──────┘ │ schema) │  │ mock/local)│  └─────────────┘
        │                 │        └────┬────┘  └─────┬──────┘
        │                 │             │             │
        │           ┌─────▼─────────────▼─────────────▼─────┐
        │           │              Agents                     │
        │           │ Recon · Code · Test · Security · Infra  │
        │           │ Dependency/CVE · CI/CD · Database ·     │
        │           │ Observability · Cost · Review ·         │
        │           │ Verification                            │
        │           └─────────────────┬───────────────────────┘
        │                             │
  ┌─────▼─────────────────────────────▼───────────────────────┐
  │                    Event Log / Audit Trail (append-only)    │
  └───────────────────────────────────────────────────────────┘
```

Every agent is a plain function of `(Task, ProjectConfig, ToolRegistry,
AIProvider) -> TaskResult`. Agents call tools; they never touch the
database, the policy engine, or another agent directly. This is what keeps
the system testable — an agent can be unit-tested with a fake tool
registry and a mock provider, with no orchestrator running.

## 3. Data Model

Core entities (implemented in `src/aep/models.py`):

- **Project** — id, name, repo adapter config, policy file path, risk
  posture, environments. First-class, not hard-coded.
- **Task** — id, type, project_id, priority, risk (`low|medium|high`),
  status (state machine below), dependencies (task ids), owner_agent,
  attempts, max_attempts, evidence (list of `Evidence` records), artifacts
  (paths/urls produced), approval (`ApprovalStatus` or `None`),
  created_at/updated_at, parent_task_id (for follow-up work discovered
  mid-task).
- **Evidence** — task_id, source ("pytest", "trivy", "git-log", …),
  captured_at, exit_code, summary, raw_output_ref (path to full log, never
  inlined into a prompt in full).
- **Event** — append-only audit record: actor (agent name or "human"),
  action, task_id, project_id, decision (policy outcome if applicable),
  timestamp, details. This is the audit trail referenced in §14/§18/§27.
- **PolicyDecision** — action, context, decision (`ALLOW|DENY|
  REQUIRE_APPROVAL|WARN`), matched_rule, reason.
- **Approval** — task_id, requested_at, requested_by, decided_by, decision,
  decided_at, rationale shown to the human (what/why/impact/risk/rollback).

## 4. Task State Machine

```
PENDING → READY → RUNNING → {SUCCEEDED, FAILED, BLOCKED_ON_APPROVAL}
FAILED → (failure classifier) → RETRY_SCHEDULED → READY   [if retries remain]
FAILED → QUARANTINED                                       [retries exhausted]
BLOCKED_ON_APPROVAL → READY   [approved]
BLOCKED_ON_APPROVAL → CANCELLED [rejected]
```

A task is `READY` only when every task in its `dependencies` list is
`SUCCEEDED`. The orchestrator's scheduling loop is a single deterministic
query: "which PENDING tasks have all dependencies SUCCEEDED and no unmet
policy block" — never an LLM decision. This is what makes the task graph
resumable after a crash: on restart, the orchestrator re-runs that query
against durable state instead of replaying an in-memory plan.

`QUARANTINED` tasks stop being scheduled automatically and surface as
`HUMAN_REQUIRED` events (see §9 Failure Classification) — this is the
circuit breaker: after N consecutive failures of the same
(task_type, project) pair, the whole task_type is quarantined for that
project until a human clears it, not just the one task retried forever.

## 5. Agent Contracts

Every agent implements:

```python
class Agent(Protocol):
    name: str
    required_capabilities: list[str]   # tool capabilities it may request
    def run(self, task: Task, ctx: AgentContext) -> TaskResult: ...
```

`AgentContext` bundles a `ToolRegistry` view scoped to that agent's
declared capabilities (an agent cannot call a tool it didn't declare —
enforced by the registry, not by convention), an `AIProvider` handle
resolved by the model router for that task type, the `PolicyEngine`, and a
read-only project config.

Implemented in this repo: `ReconAgent`, `CodeAgent`, `TestingAgent`, and a
deterministic `SecurityScanAgent` (secret/pattern scanning — a first slice
of Phase 3, included early because "never trust AI for security" needs a
real deterministic gate to point at in Phase 1's demo). Specified but not
implemented in code: Infrastructure, Dependency/CVE, CI/CD, Database,
Observability, Cost, Review, Verification agents — their contracts above
are sufficient for a Phase 2+ implementation to slot in without
orchestrator changes, because the orchestrator only ever calls
`agent.run(task, ctx)`.

## 6. Tool Registry

Tools declare capabilities, a risk level, and JSON-schema input/output —
`src/aep/tool_registry.py`. Example (`git_tool.py`):

```python
Tool(
    name="git",
    capabilities={"git.branch", "git.commit", "git.diff", "git.push_local"},
    risk="medium",
    input_schema=...,
)
```

Agents are granted capabilities, not tools — `ToolRegistry.scoped_for(caps)`
returns a view that raises `PermissionError` on anything outside that set.
`shell` (arbitrary command execution) is `risk="high"` and is only granted
to `TestingAgent` (to invoke `pytest`) with an explicit allowlist of
binaries; no agent gets unrestricted shell access. Every tool call is
written to the event log with actor, capability used, inputs (secrets
redacted), and result — this is the audit trail, not a side effect of
logging.

## 7. AI Provider Abstraction

`src/aep/providers/base.py` defines:

```python
class AIProvider(Protocol):
    name: str
    def generate(self, request: GenerationRequest) -> GenerationResult: ...
    def capabilities(self) -> ProviderCapabilities: ...  # context window, supports_tools, cost/1k tokens
    def health(self) -> ProviderHealth: ...
```

`ModelRouter` (`providers/router.py`) picks a provider per task type from a
declarative routing table (e.g. `security_analysis -> anthropic:claude-...`,
`trivial_refactor -> mock:cheap`, with a fallback chain), tracks provider
health from recent calls, and fails over on repeated errors. This repo
ships two concrete providers: `AnthropicProvider` (real API calls, used
only if `ANTHROPIC_API_KEY` is set) and `MockProvider` (deterministic,
offline, used by every automated test and the demo run so CI/tests never
depend on network access or a paid key). Adding OpenAI/Gemini/Copilot is
implementing the same three methods — the orchestrator, agents, and router
are unaware which one is in use.

## 8. Policy Engine

`src/aep/policy.py`. Rules are declarative YAML per project
(`config/policy.yaml`), evaluated as `evaluate(action, context) ->
PolicyDecision` before any tool call that matches a rule pattern. Decision
order: explicit `DENY` rules first (cannot be overridden by anything else
in this repo, including future self-modifying "self-improvement" code —
see §23 in the master prompt and the Threat Model below), then
`REQUIRE_APPROVAL`, then `WARN` (logged, allowed), then default `ALLOW` if
nothing matches and the project's default posture is permissive, else
default `DENY`.

Example policy used by the demo:

```yaml
deny:
  - action: "git.push"
    when: {branch: "main"}
  - action: "secret.commit"
require_approval:
  - action: "deploy.apply"
    when: {environment: "production"}
  - action: "db.migrate"
    when: {destructive: true}
allow:
  - action: "git.branch"
  - action: "test.run"
```

## 9. Failure Classification & Recovery

`src/aep/failure.py`. Every raised exception or non-zero tool exit is
classified into one of: `TRANSIENT, AUTH, SECURITY, CODE, TEST,
INFRASTRUCTURE, MODEL, TOOL, HUMAN_REQUIRED`. Retry policy is
per-classification (exponential backoff with jitter for `TRANSIENT`/`MODEL`
/`TOOL`; zero automatic retries for `SECURITY`/`AUTH`/`HUMAN_REQUIRED` —
those always produce a `BLOCKED_ON_APPROVAL` or `QUARANTINED` task instead).
A per-`(project, task_type)` circuit breaker counts consecutive failures
independent of which specific task instance failed, so the system doesn't
retry a structurally-broken task type forever under different task IDs.

## 10. Event Model / Audit Trail

Append-only `events` table in the same SQLite store as tasks (see §12).
Every state transition, tool call, policy decision, and approval
decision/request produces one `Event`. This is what §14 (Verification
Philosophy) and §18 (Observability) both depend on — "did the tests
actually run" is answered by querying events for a `tool_call` event with
`capability="test.run"` and reading its `Evidence`, not by trusting an
agent's return value.

## 11. Security Architecture

Layered, matching the master prompt's "security is never a final step":

1. **Deny-by-default policy gates** (§8) sit in front of every tool call,
   not just deploy — e.g. `git.push` to `main`/`master` is a hard `DENY`
   regardless of which agent requests it.
2. **Deterministic secret scanning** runs before every commit task and
   again post-commit as a re-check (`SecurityScanAgent`, pattern-based in
   Phase 1: AWS keys, private key blocks, generic high-entropy tokens,
   common `.env`-style assignments). A detected secret blocks the commit
   task (`DENY`, not `WARN`) and raises a `HUMAN_REQUIRED` event — it is
   never silently stripped and merged, because that is itself a risky
   automated action per the master prompt.
3. **No secret ever enters a prompt.** `GenerationRequest` construction
   redacts any string matching the same secret patterns before it reaches
   an `AIProvider`, and the event log stores a redacted view of tool
   inputs/outputs.
4. **Phase 3 (specified, not yet implemented in code):** SAST, SCA/CVE
   scanning (e.g. wrapping `pip-audit`/`osv-scanner`/`trivy`), IaC scanners
   (`checkov`/`tfsec`), container/K8s scanners — all as `Tool`
   implementations with `risk="low"` (read-only) so they can be granted
   broadly, feeding a `DependencyCVEAgent`/`SecurityAgent` that only
   *proposes* remediation; the policy engine still gates any resulting
   write.

## 12. Persistent State & 24/7 Operation Model

`src/aep/state_store.py` uses SQLite in WAL mode as the durable backing
store for Phase 1 (tasks, events, approvals, project configs) — chosen
because it needs zero external services to demonstrate crash-recovery
honestly in a sandbox, while the schema and access pattern (a
`StateStore` interface) are what a Postgres-backed implementation would
also satisfy for a real 24/7 deployment. On restart, `Orchestrator.resume()`
reloads all non-terminal tasks and re-enters the scheduling loop — proven
by `tests/test_state_store.py`'s crash-mid-run simulation.

For real 24/7 operation beyond this sandbox: run the orchestrator as a
worker process pool reading `READY` tasks from the store (SQLite →
Postgres for concurrent workers), a scheduler tick that periodically
re-evaluates continuous-mode inspection tasks (§13), and a supervisor
(systemd/k8s Deployment) that restarts crashed workers — the
`Orchestrator.resume()` contract is what makes that restart safe. This
repo does not stand up that supervisor/process pool; it proves the
resumability contract it would depend on.

## 13. Continuous Mode

`Orchestrator.plan_continuous(project)` (specified; a minimal version is
implemented) enumerates inspection tasks (recon diff vs. last known state,
open-PR check via the git adapter, security scan) as a task graph with no
human-provided root request, scores discovered follow-up work by
`risk`/`priority`, and enqueues the highest-value low-risk item first. It
explicitly does not loop `while True: call_llm()` — each tick is one
bounded task-graph execution against durable state, so it can be driven by
an external scheduler (cron, k8s CronJob) without an always-on process
being architecturally required.

## 14. Verification Philosophy in Code

Concretely: `TestingAgent.run()` shells out to `pytest --tb=short` via the
`shell` tool and parses the real exit code and summary line; it does not
ask the `AIProvider` whether tests passed. `SecurityScanAgent.run()`
re-scans the working tree after `CodeAgent` finishes, even though
`CodeAgent`'s own `AIProvider` call may claim the secret was removed.
Every agent's `TaskResult.evidence` field must be populated from a tool's
captured output; an agent that only sets evidence from provider text
fails a lint check in this repo (`tests/test_verification_discipline.py`
greps agent implementations for this pattern).

## 15. Git / PR Workflow

`git_tool.py` (Phase 1, local-repo real implementation) supports
branch/commit/diff/local-push; a `GitHostAdapter` interface (specified) is
what `GitHubAdapter`/`GitLabAdapter` would implement for
PR-create/PR-update/PR-list against a real host, so `CodeAgent` never
special-cases GitHub vs GitLab. Policy denies any `git.push` where
`branch in {"main", "master"}` unconditionally (§8, §11) — the only path
to `main` is a human merging a PR.

## 16. Threat Model (platform-as-attack-surface)

Per §24 of the brief, the platform itself is treated as privileged:

- **Prompt injection via repository content** (malicious README/CI
  config/code comments instructing the agent to skip checks, exfiltrate
  secrets, or widen its own permissions): repository content is passed to
  `AIProvider.generate()` only inside a clearly-delimited "untrusted
  content" field of the prompt template; the orchestrator and policy
  engine never parse model output as instructions to change policy,
  capabilities, or approval requirements — those are only ever changed by
  editing `config/policy.yaml`, which is not in the set of files any agent
  is permitted to write (`tool_registry` denies `filesystem.write` on
  paths under `config/`).
- **Poisoned dependency / malicious CI config**: read-only recon and
  scanning tools only; nothing in Phase 1 executes fetched CI config or
  arbitrary repository scripts as trusted code — `shell` tool calls are
  restricted to an explicit allowlisted command set (`pytest`, `git`, a
  small number of scanners in Phase 3), not "whatever the repo's Makefile
  says."
- **Credential exfiltration**: secrets never enter provider prompts (§11);
  event log and evidence capture redact matches of the same secret
  patterns; tool inputs/outputs are redacted before persistence.
- **Self-improvement overreach** (§23): nothing in the orchestrator can
  write to `config/policy.yaml` or change `max_attempts`/approval
  requirements at runtime; those require a human commit reviewed like any
  other change to the platform's own repo.

## 17. Cost Model

`ModelRouter` records tokens/cost per call (from `GenerationResult`) into
the event log; `Task.evidence` for any `model_call` event includes the
estimated cost. A per-project token budget (config) causes the router to
downgrade to a cheaper provider/model and, if exhausted, raises `MODEL`
failures that pause continuous-mode work rather than exhausting spend —
this is a real, tested code path (`tests/test_providers.py::
test_router_budget_exhaustion`), not aspirational.

## 18. Observability

Every `Event` is queryable (`StateStore.query_events(...)`); `cli.py`
exposes `aep events --task <id>` and `aep status --project <id>` as thin
read paths over that table — the "dashboard" for this phase is a CLI
report; a real dashboard would read the same `StateStore` (SQLite/Postgres)
with no orchestrator changes.

## 19. Testing Strategy

- Unit: state store durability, policy decisions, tool permission
  boundaries, failure classification, provider routing/fallback/budget —
  all offline, all using `MockProvider`.
- Integration/E2E: `tests/test_end_to_end_demo.py` runs a full request
  ("fix the bug in demo_project") through `Orchestrator` against a real
  local git repo fixture, asserting on real git state (branch exists, no
  commit landed on `main`), real pytest output (fixture's failing test now
  passes), and real event-log content (policy `DENY` fired at least once
  for the attempted direct-`main` write, secret scan flagged the fixture's
  placeholder secret).
- Security testing: `SecurityScanAgent` is tested against a fixture file
  containing known secret-shaped strings (never real credentials) to
  assert detection, and against clean files to assert no false-positive
  blocks the demo.

## 20. Repository Structure

```
aep-platform/
  ARCHITECTURE.md
  README.md
  pyproject.toml
  config/
    policy.yaml
    project.yaml
  src/aep/
    models.py
    state_store.py
    events.py
    policy.py
    failure.py
    secrets.py                          # Phase 2: approved secret mechanism
    tool_registry.py
    orchestrator.py
    bootstrap.py
    cli.py
    tools/{git_tool,filesystem_tool,shell_tool,github_tool}.py
    providers/{base,anthropic_provider,mock_provider,router}.py
    agents/{base,recon_agent,code_agent,testing_agent,security_agent,
            push_agent,pull_request_agent,ci_monitor_agent,ci_diagnose_agent}.py
    github/{client,planner}.py          # Phase 2: real GitHub REST adapter + task-graph planner
  demo_project/            # toy fixture repo used by the E2E test
  tests/
    test_state_store.py
    test_policy_engine.py
    test_tool_registry.py
    test_providers.py
    test_failure_classifier.py
    test_verification_discipline.py
    test_end_to_end_demo.py
    test_secrets.py
    test_github_client.py
    test_github_tool.py
    test_github_push_policy.py
    test_github_ci_loop.py              # the Phase 2 end-to-end test
    github_fakes.py                     # stateful fake GitHub API used by the above
```

## 21. Roadmap (Phases 2–7) — superseded by `config/roadmap.yaml`

**As of Phase 3, this table is no longer the source of truth.** Per Phase
3's explicit instruction ("do not make ARCHITECTURE.md the source of
truth"), the roadmap now lives in a versioned, machine-readable file,
`config/roadmap.yaml`, with exactly 9 platform phases, each broken into
named capabilities with the test file(s) that verify them. `aep status`
and `aep progress` (`src/aep/cli.py`, `src/aep/progress/`) compute
percentage/status/deployability from that file plus a live test run —
never from a number written in this document. The table below is kept only
as a human-readable snapshot of the OLD (Phase 1/2) 7-phase numbering for
historical context; it does not match the current 9-phase numbering in
`config/roadmap.yaml` and should not be used to answer "what phase are we
in" — run `aep status` or `aep progress` for that, or read
`config/roadmap.yaml` directly.

| Old Phase # | Scope | Status as of Phase 2 |
|---|---|---|
| 1 | Orchestrator, Task Engine, Tool Registry, AI Provider abstraction, persistent state | Implemented + tested |
| 2 | Recon, Code, Testing agents; Git/PR integration | Implemented + tested against a real GitHub REST client (mocked transport) and real local git — see §23 |
| 3 | Security agent, secret detection, SAST/SCA/CVE, IaC/container security | Deterministic secret scanner implemented; SAST/SCA/IaC scanners specified as `Tool` contracts only |
| 4 | Infrastructure agent: Terraform/Kubernetes/cloud | Specified only — no cloud credentials in this environment |
| 5 | CI/CD agent, deployment verification, runtime observability | Specified only |
| 6 | 24/7 scheduler, continuous remediation, cross-project | Minimal `plan_continuous` implemented; process-pool/supervisor not stood up |
| 7 | Cost optimization, architecture optimization, predictive remediation, self-improvement (policy-safe) | Specified only |

The current 9-phase numbering (`config/roadmap.yaml`, §24 below covers
Phase 3 of it in detail) is: 1 Core Platform, 2 GitHub Engineering,
3 Dependency & CVE Intelligence, 4 Security Intelligence, 5 Infrastructure
Intelligence, 6 CI/CD & Deployment, 7 Runtime/Observability, 8 24/7
Autonomous Operation, 9 Multi-Project/Advanced Intelligence.

## 22. What is and isn't real in this repository

Real and tested: task graph + state machine, SQLite durable state with
crash-recovery, policy engine with deny/require-approval/warn/allow,
capability-scoped tool registry, git/filesystem/shell tools operating on
real local repos, a real GitHub REST API client and tool (§23), an
`AIProvider` abstraction with a working offline mock and an optional real
Anthropic-backed provider, a failure classifier with backoff and circuit
breaking, a deterministic secret scanner, and two end-to-end demos (Phase 1's
local fix-a-bug flow and Phase 2's full PR/CI diagnose-and-fix loop) that a
human can re-run and inspect the resulting git repo and event log for
themselves.

Specified but not implemented as running code: cloud/Kubernetes/CI/CD
adapters (no credentials available in this sandbox), SAST/SCA/IaC/container
scanners beyond the secret pattern scanner, the review/verification agents
as separate roles (verification discipline is currently enforced by a
lint-style test rather than a dedicated agent), a process-pool/worker
supervisor for real 24/7 concurrency, and any self-improvement loop. These
are named explicitly rather than left implicit so a follow-up session knows
exactly what to build next and doesn't need to re-derive it from this
document.

## 23. Phase 2 Addendum: GitHub Integration

Added on top of Phase 1 without changing `orchestrator.py`'s scheduling
core, `models.py`'s state machine, `tool_registry.py`'s capability
enforcement, or `policy.py`'s evaluation order — Phase 2 is new adapters,
new agents, and one new planner module, plus two narrowly-scoped bug fixes
to the core that this work's own tests surfaced (below).

**GitHub client** (`src/aep/github/client.py`): a real REST v3 client
speaking the actual documented endpoints — repo/branch/commit discovery,
PR list/get/create/update, PR files, issue/PR comments, combined status,
check-runs, issues, workflow runs and jobs. It depends on `requests` only
through a swappable `transport` callable (mirroring the `AIProvider`
pattern in §7): the same client code runs unmodified against
`api.github.com` or against a test fake. Error responses are classified
into specific exception types (`GitHubAuthError`, `GitHubRateLimitError`,
`GitHubNotFoundError`, `GitHubValidationError`) which `failure.py`'s
`classify()` maps to `FailureClass` — a rate limit is `TRANSIENT` (retry),
a bad token is `AUTH` (never auto-retried, surfaces as `HUMAN_REQUIRED`
immediately per §9).

**GitHub tool** (`src/aep/tools/github_tool.py`): registers every client
capability plus one non-REST capability, `github.push_branch`, which does a
real `git push` over HTTPS. The token is resolved from a `SecretManager`
(`src/aep/secrets.py` — new in Phase 2, §11/§16 "approved secret
mechanism") and handed to git via a short-lived `GIT_ASKPASS` script and a
subprocess-scoped environment variable, specifically so it never appears in
argv (visible via `ps`) or in any returned/logged string; subprocess
stdout/stderr are also scrubbed of the literal token value before being
returned, on top of the existing pattern-based redaction in `redaction.py`
(which gained `github_pat_...`, `gh[pousr]_...`, and
`https://user:pass@github.com` patterns, plus a `redact_literal()` helper
for exact-value scrubbing regardless of pattern match).

**New agents**, each still just "call a real tool, return evidence" (§5):
`PushAgent`, `PullRequestAgent` (lists open PRs by head branch before
creating, so a duplicate is never opened — updates the existing one
instead), `MonitorCIAgent` (reads real check-run state; pending is a
`FailureClass.TRANSIENT` return so the *existing* retry/backoff mechanism
does the polling — no new polling loop was written), and
`DiagnoseCIFailureAgent` (pulls failed check output plus workflow-job/step
detail via two more real tool calls, asks the model to turn that evidence
into a one-line fix description, posts it as a PR comment, then hands off
to a fresh code_fix → security_scan → run_tests → push chain).

**The diagnose/fix/push/re-check loop** is not a new orchestrator
construct. It's the *existing* `TaskResult.follow_up_tasks` mechanism
(§5/orchestrator.py `run_task`), used to submit a fresh sub-graph each time
`MonitorCIAgent` finds a real failure. `src/aep/github/planner.py` builds
both the initial graph (`plan_github_fix_and_pr`) and every loop
iteration's sub-graph (`build_fix_verify_push_chain`) from the same
function, so the shape is identical whether it's attempt 1 or attempt N.
A `ci_loop_iteration`/`max_ci_loops` counter carried in task payloads
(durable, since it's part of `Task.payload`) caps the loop — past the
limit, `MonitorCIAgent` returns `FailureClass.HUMAN_REQUIRED` instead of
scheduling another attempt, which is the existing NO_AUTO_RETRY path
(§9) → `BLOCKED_ON_APPROVAL`. This is the "genuinely blocked" case the
brief asked for, implemented with zero new blocking primitives.

**Policy**: no new enforcement mechanism. `config/policy.yaml` gained one
action name, `github.push`, with `deny` rules for `branch: main/master`
(identical shape to the existing `git.push` rules) and a `require_approval`
rule for `force: true`. `PushAgent`'s task payload sets
`policy_action`/`policy_context` the same way the Phase 1 test
`test_direct_push_to_main_is_denied_by_policy_gate` already exercised —
Phase 2 added no policy-evaluation code at all, only data.

**Two real bugs in the Phase 1 core, found by this work's tests and
fixed** (both narrow, both covered by regression tests, neither changes
behavior for any of the original 36 tests):

1. `Orchestrator._handle_failure` incremented the per-task-type circuit
   breaker counter on *every* retry, not just on an instance's final,
   exhausted failure. A task with a legitimately high `max_attempts` for
   polling (`MonitorCIAgent`, `max_attempts=8`) would trip the
   project-wide breaker (default threshold 5) from ordinary "still
   pending" retries alone, well before its own retry budget was used.
   Fixed by only calling `store.record_failure` once an instance's own
   retry budget is exhausted, so the breaker tracks "how many distinct
   instances of this task type have definitively failed," not "how many
   retry attempts occurred in total."
2. `Orchestrator._apply_generic_policy_gate` re-evaluated `policy_action`
   on every scheduling pass with no memory of a prior approval, so a task
   a human had just approved (`orchestrator.approve()`) would be
   re-blocked by the same `REQUIRE_APPROVAL` rule the instant it was
   rescheduled — approval was structurally impossible for any task that
   used this gate. Fixed by skipping the gate when
   `task.approval_status == "APPROVED"`.
3. (Also fixed, lower severity) `GitHubClient` interpolated `ref`/`branch`/
   `sha` values directly into URL path segments; a branch name containing
   `/` (the platform's own convention, e.g. `aep/fix-1234`) silently
   produced a malformed path and a 404 against every ref-based endpoint.
   Fixed with `urllib.parse.quote(value, safe="")` on those segments.

**What's real vs. what's test infrastructure for Phase 2**: the client,
tool, agents, planner, secret mechanism, and policy wiring are real code
that runs unmodified against `api.github.com` given a real token and repo.
What's environment-specific is the transport: this sandbox's egress proxy
returns 403 for `api.github.com` ("GitHub access to this repository is not
enabled for this session") and no GitHub connector/credential is available
in this session, so the end-to-end demonstration
(`tests/test_github_ci_loop.py`, plus a standalone script producing the
same evidence) uses `FakeGitHubTransport` (`tests/github_fakes.py`) — a
small, stateful in-memory implementation of the exact endpoints
`GitHubClient` calls, driving a realistic pending → failing → success
check-run sequence — combined with a real local bare git repository
standing in for GitHub's git storage. `github.push_branch`'s
credential-handling code path (the `GIT_ASKPASS` construction) is exercised
and asserted on directly in `tests/test_github_tool.py` even though the
push itself, in the test suite, targets a local path rather than
`github.com`. Pointing this at a real repository requires only setting
`AEP_SECRET_GITHUB_TOKEN` and passing `owner`/`repo` (no `remote_url`
override) to `plan_github_fix_and_pr` — no code changes.

## 24. Phase 3 Addendum: Dependency & CVE Intelligence + Platform Progress Engine

Added on top of Phase 1/2 without changing `orchestrator.py`,
`models.py`'s Task/Evidence contract, `tool_registry.py`'s enforcement, or
`policy.py`'s evaluation order. Phase 3 is a new `dependency/` package, one
new agent, one new planner module (same shape as `github/planner.py`), a
new `progress/` package, new CLI commands, one new data file
(`config/roadmap.yaml`), and two small, targeted bug fixes to existing
Phase 1/2 code that this work's own tests surfaced (below) — not a
redesign of anything.

### Dependency/CVE pipeline

`src/aep/dependency/` implements DISCOVER → UNDERSTAND → REMEDIATE → TEST
→ RESCAN, and hands off to the *existing*, unmodified GitHub PR/CI
machinery for → PR → CI → VERIFY:

- **`manifests.py`** discovers `requirements*.txt`/`pyproject.toml`/
  `package.json`/`go.mod`/`Dockerfile` — architected for four ecosystems
  from the start, not Python-only, per the explicit instruction.
- **`scanners/`** — one module per ecosystem, each exposing
  `is_available(run_shell)`/`scan(manifest, project_root, run_shell)`, the
  same swappable-adapter shape as `AIProvider`/`GitHubClient.transport`:
  - `pip_audit_scanner.py` — **real**, shells out to `pip-audit`. Verified
    against a real, currently-vulnerable pin (`urllib3==1.26.4`) returning
    genuine PyPI-JSON-API-backed advisory data (PYSEC-2021-108 /
    GHSA-q2q7-5pp4-w6pg / CVE-2021-33503). `pip-audit`'s default backend
    queries `pypi.org`, which this sandbox can reach, rather than
    `api.osv.dev`, which it cannot (confirmed 000/unreachable via direct
    curl) — that's *why* pip-audit works here and a direct osv.dev client
    would not.
  - `npm_audit_scanner.py` — **real**, shells out to `npm audit` (resolving
    a lockfile via `--package-lock-only` first if one isn't already
    committed, so no third-party install script ever runs). Verified
    against a real vulnerable pin (`minimatch@3.0.4`) returning genuine
    `registry.npmjs.org`-backed advisory data (GHSA-f8q6-p94x-37v3 and
    related ReDoS advisories).
  - `govulncheck_scanner.py` / `trivy_scanner.py` — **specified, not
    verified**: `govulncheck` isn't installed and `go install
    .../govulncheck@latest` needs `proxy.golang.org`, which returns 403
    from this sandbox (the same egress-proxy-block pattern §23 documents
    for `api.github.com`); no `trivy`/`grype` binary or container runtime
    exists here at all. `is_available()` returns `False` for both, so
    `inventory.py` records a discovered `go.mod`/`Dockerfile` as
    "discovered, not scanned" with the exact reason — it never fabricates
    a clean or dirty result for an ecosystem this sandbox can't reach.
- **`remediation.py`** picks, per package, the smallest fixed version that
  resolves *every* finding reported against it at once (the max of each
  finding's own minimal fix — not a blind jump to latest). A package with
  any finding lacking a published fix, or with unparseable version
  strings, is marked `safe=False` with a reason and is never guessed at.
- **`manifest_writer.py`** applies a plan as a text/structure-level edit
  (a regex-anchored pin rewrite for `requirements.txt`, a JSON field
  update for `package.json`) and raises rather than silently no-opping if
  the expected pin isn't found.
- **`agents/dependency_cve_agent.py`** (`DependencyCVEAgent`) — one agent,
  four `mode`s (`scan`/`remediate`/`rescan`/`escalate`), reusing only
  existing capabilities (`filesystem.*`, `git.*`, `shell.run`) — no new
  Tool type was added. `mode="rescan"` is the Part B verification gate: it
  re-runs the real scanner and only returns success if the specific
  finding(s) are actually gone; if they're still present it returns
  `failure_class=CODE` with an evidence line starting `NOT resolved` and
  never emits a `CONFIRMED resolved` claim. A finding with no safe upgrade
  becomes a `dependency_escalate` task, which always terminates
  `FailureClass.HUMAN_REQUIRED` → `BLOCKED_ON_APPROVAL` — a durable,
  queryable "this needs a human" signal, not a dropped/silent finding.
- **`dependency/planner.py`** (`build_remediation_chain`,
  `plan_dependency_scan`) builds `dependency_remediate → run_tests →
  dependency_rescan → push_branch → create_pull_request → monitor_ci`
  exactly the way `github/planner.py` builds its chain — reusing
  `build_push_task` directly. If CI fails afterward, `MonitorCIAgent`'s
  *existing*, unmodified hand-off to `DiagnoseCIFailureAgent` →
  `build_fix_verify_push_chain` takes over; nothing in `dependency/`
  reimplements CI diagnosis. `include_github=False` (no `owner`/`repo`/
  `remote_url` given) truncates the chain after `dependency_rescan`, so
  dependency remediation works standalone in a repo with no GitHub wiring
  at all.
- A remediation's evidence chain (Part B) — scanner name+version,
  scan timestamp, finding id(s)/severity, previous/new version, install
  result, test result, second-scan result, and (when applicable) PR/CI
  result — is written as ordinary `Task.evidence` entries on the ordinary
  tasks in this chain; no new evidence storage primitive was added. A
  human/dashboard reads it the same way they'd read any other task's
  evidence (`aep events --project X` or `orch.store.get_task(...).evidence`).

### Two bugs found and fixed (both narrow, both covered by regression tests)

1. **`shell_tool.py` stdout truncation corrupted scanner JSON.** The
   existing `[-8000:]` tail-truncation (tuned for terse `pytest -q`
   output) silently corrupted `pip-audit -f json`'s output (~16KB for a
   single vulnerable package) into invalid JSON; the scanner's
   `except json.JSONDecodeError` fallback to `{}` then made a real,
   known-vulnerable fixture report "0 findings" with no error surfaced
   anywhere. Caught by a manual end-to-end run, not a unit test — nothing
   before Phase 3 ever produced >8000 characters of stdout. Fixed by
   raising the caps to 200,000/20,000 characters (stdout/stderr); still
   bounded, just no longer tuned exclusively for pytest's output shape.
2. **Bare `pytest` is isolated from `python3 -m pip install` in this
   sandbox.** `pytest` here is a separately managed tool install
   (`/root/.local/share/uv/tools/pytest/bin/python`), not `python3`'s own
   interpreter — installing an upgraded dependency via
   `python3 -m pip install` has zero effect on what bare `pytest` can
   import. `dependency/planner.py`'s `run_tests` task therefore passes
   `test_args=["python3", "-m", "pytest", "-q"]` explicitly, so the same
   interpreter that received the upgrade is the one running tests against
   it. This is scoped to the dependency-remediation chain only —
   `TestingAgent`'s own default (bare `pytest`) and every Phase 1/2 call
   site are unchanged, since this quirk only matters when a test actually
   imports a package that was just installed programmatically.

Also fixed for correctness (not a Phase-1/2 regression, an issue in
Phase 3's own new `progress/` code found and fixed before this report): an
earlier version of the progress calculator ran pytest once per capability
plus once per phase plus once overall, so a shared, slow, real-network
test file could execute three-plus times per `aep status` call — and,
separately, having `platform.status_cli`'s own gating test
(`tests/test_cli_status.py`) call the real, un-injected `compute_progress`
against the real roadmap created a literal self-reference (an `aep status`
call's pytest run would re-invoke `aep status` inside itself). Both are
fixed: `compute_progress` now runs pytest exactly once per call, over the
de-duplicated union of every referenced test file, attributing pass/fail
per capability via the JUnit report's per-testcase `classname`; and
`tests/test_cli_status.py` exercises `_build_status_payload` exclusively
against an injected temporary roadmap, never the real one.

### Platform progress engine (Part C/D/G)

`config/roadmap.yaml` is now the single source of truth for what phases
and capabilities exist — **not** this document (see §21). It defines the 9
platform phases, each broken into capabilities with the test file(s) that
verify them, and, where applicable, an explicit `blocked`/`blocked_reason`
(used for `dependency.go_scanning`/`dependency.container_scanning` above).

`src/aep/progress/calculator.py` computes, from a single live pytest run
plus this file: per-capability status (`COMPLETE` only if its test(s) pass
right now with zero failures; `IN_PROGRESS` if some pass and some fail;
`PENDING` if untested or 0 passing; `BLOCKED` if the roadmap says so), and
per-phase status (`NOT_STARTED`/`IN_PROGRESS`/`BLOCKED`/`COMPLETE`, plus
`VERIFIED` — reachable only via an explicit `aep verify-phase` durable
event, distinguishing "tests pass right now" from "someone explicitly ran
and recorded full verification"). Phase/overall percentages are derived
counts, never literals.

`src/aep/progress/deployability.py` computes one of `NOT_DEPLOYABLE` /
`DEVELOPMENT_READY` / `INTEGRATION_READY` / `STAGING_READY` /
`PRODUCTION_CANDIDATE` / `PRODUCTION_READY` from those phase statuses plus
two operator-asserted facts this codebase cannot observe about itself —
whether live GitHub API integration and live CVE-feed integration have
ever actually been exercised (`--live-github-verified`, default `False`;
this sandbox has never had one, so the default is honest). "Tests pass" is
explicitly *not* sufficient for `PRODUCTION_READY` — an incomplete later
phase or an unexercised live integration always shows up as an explicit
`Blocking:` reason.

**Note on cost**: `aep status`/`aep progress` re-run the platform's own
real, partially network-dependent test suite on every invocation (currently
~90 seconds against this repo, dominated by the real npm/pip-audit and
GitHub-loop integration tests) — this is intentional per Part C ("Do NOT
hard-code a percentage"): the number is either freshly computed or it
doesn't exist. This is a deliberate trade-off for a status/audit command,
not for a hot dashboard-polling path; a future phase could cache the last
run's per-file result and add a `--fast`/`--cached` flag without changing
the underlying calculation.

### CLI (Part E/F)

`aep status` / `aep progress` / `aep status --json` (`src/aep/cli.py`)
render the computation above — ASCII progress bars, current
work/completed/next lists, and a `DEPLOYABILITY:`/`Blocking:` section in
the human-readable form; the identical data as nested JSON (phases,
capabilities, tests, deployability, and, with `--project`, a live task
snapshot) via `--json`. `aep verify-phase --phase N` refuses (exit 1) to
record `VERIFIED` unless the phase already reads `COMPLETE`.

**A pre-existing CLI surface changed**: `aep status --project X` meant
"list this project's tasks" before Phase 3. Since Part E specifically asks
for `aep status` to mean platform-wide status, that per-project listing is
now `aep tasks --project X`. No test exercised the old CLI surface
(checked before renaming — see `tests/`), so nothing broke; called out
here and in the Phase 3 completion report as an explicit, intentional
change.

### Testing (Part H) and real-vs-mocked (Part I)

New test files: `test_dependency_manifests.py` (discovery, all four
ecosystems, ignore-list), `test_dependency_remediation.py` (safe-upgrade
selection, severity, ambiguous/no-fix escalation, manifest mutation —
pure logic, no scanner/network), `test_dependency_scanning.py` (real
`pip-audit`/`npm audit` against real vulnerable pins — skipped, not faked,
if the binary genuinely isn't present), `test_dependency_agent.py`
(remediate/rescan/escalate/scan-mode wiring, real git/filesystem, a
monkeypatched scanner layer for fast/offline coverage of failure paths:
unresolved CVE, failed upgrade, safe-vs-unsafe splitting),
`test_dependency_e2e_real.py` (Part I's real end-to-end chain — see
below), `test_dependency_github_loop.py` (GitHub hand-off + CI-failure-
after-dependency-upgrade + crash/resume, mocked transport — see below),
`test_progress_engine.py` (capability/phase/deployability calculation
against throwaway fixture roadmaps), `test_cli_status.py` (JSON shape,
also against an injected fixture roadmap — see the self-reference bug
fix above). All prior Phase 1 (36) and Phase 2 (24) tests still pass
unmodified; full suite is 104 tests.

**REAL LOCAL EXECUTION vs MOCKED EXTERNAL GITHUB TRANSPORT, stated
explicitly per Part I**:
- `test_dependency_e2e_real.py` is 100% real, nothing mocked: a disposable
  fixture with a genuinely vulnerable pinned dependency
  (`urllib3==1.26.4`) → real `pip-audit` finds the real, published CVE →
  `DependencyCVEAgent` picks the real smallest safe version → rewrites the
  real manifest → commits to a real git branch → installs the real
  upgraded package → runs the real project test suite → runs `pip-audit`
  again for real → confirms the finding is gone, cross-checked by an
  independent direct `pip-audit` invocation outside the platform's own
  code path. No GitHub involvement at all in this file.
- `test_dependency_github_loop.py` adds the PR/CI hand-off on top of that
  same real local chain, using `FakeGitHubTransport` (§23) for the GitHub
  REST responses only — identical boundary to Phase 2's
  `test_github_ci_loop.py`. This sandbox still cannot reach
  `api.github.com` (§23); nothing here claims otherwise.

## 25. Phase 4 Addendum: Security Intelligence & Automated Remediation

Added on top of Phase 1–3 without changing `orchestrator.py`, `models.py`,
`tool_registry.py`, `policy.py`'s evaluation order, or any Phase 1/2/3
agent. Phase 4 is a new `security/` package (parallel to `dependency/`),
one new agent (`SecurityAgent`, distinct from Phase 1's `SecurityScanAgent`
— see below), one new planner module, three new binaries added to the
existing `shell.run` allowlist, `security.finding`/
`security.git_history_inspection` rules added to `config/policy.yaml`, a
`security_posture` addition to the existing progress/status system, and 15
new roadmap capabilities under Phase 4 — not a redesign of anything.

### Two "SecurityAgent"-shaped things, on purpose, not a naming accident

`agents/security_agent.py::SecurityScanAgent` is Phase 1's deterministic,
pattern-based secret gate that runs before every `CodeAgent` commit
(`redaction.find_secrets`, high-confidence patterns only). It is
unmodified. `agents/security_intelligence_agent.py::SecurityAgent` is
Phase 4's new capability: four real scanner *categories* (secret/SAST/
IaC/container), real remediation, real second-scan verification, policy
integration, suppression, and posture reporting. Both are registered in
`bootstrap.py` under different keys (`security_scan_agent` /
`security_agent`) and never call each other.

### Real scanner adapters (Part 1) — genuinely verified, not assumed

`security/scanners/` mirrors `dependency/scanners/`'s adapter shape
(`check_availability(run_shell)` / `scan(project_root, run_shell)`), with
an explicit `ScannerDescriptor` (scanner id, capability, supported files,
tool, findings schema, severity levels, evidence kind, remediation
support, availability) per Part 1's ask for a richer contract than Phase
3's minimal duck-typed modules:

- **`gitleaks_scanner.py`** — **real**. `gitleaks` (8.16.0) installs via
  `apt-get install -y gitleaks` (Ubuntu universe) and was verified against
  a fixture AWS-access-key pattern, returning genuine rule/file/line/
  entropy metadata. gitleaks' own exit-code convention (0=clean,
  1=leaks-found) is handled explicitly — 1 is a successful scan with
  results, not an error.
- **`semgrep_scanner.py`** — **real, with a documented environment
  workaround**. `semgrep` (1.172.0) installs via `pip install
  --break-system-packages semgrep`. Two real network gotchas found during
  investigation, both fixed with flags rather than fabricated output:
  (1) `--config auto`/any `p/...` registry shorthand needs
  `semgrep.dev`/`c.semgrep.dev`, unreachable here (curl returns `000`) —
  fixed by always using the bundled local rule file
  `security/rules/semgrep_rules.yaml` (six hand-written rules, each mapped
  to a real CWE: command injection, SQL injection, insecure
  deserialization, unsafe YAML load, eval/exec, weak hash); (2) even with
  a local `--config`, semgrep's version-check (on by default) still tries
  to reach a semgrep.dev server and hangs — observed adding ~90+ seconds
  of pure wall-clock wait to *every* invocation, including `--version`
  itself. Fixed with `--disable-version-check`, verified to bring a real
  scan from ~99s to ~2s.
- **`checkov_scanner.py`** — **real**, and fully offline (checkov's
  built-in policy set ships with the package, unlike semgrep's registry
  path). Verified against a Terraform fixture with a public-ACL S3 bucket
  and an open-ingress security group, correctly flagging `CKV2_AWS_6`,
  `CKV_AWS_24`, and several lower-priority checks. Open-source checkov
  doesn't populate a `severity` field (a paid-tier feature) — this
  platform's own `_infer_severity()` is an explicit, documented,
  best-effort keyword heuristic, never presented as an authoritative CVSS
  score.
- **`trivy_scanner.py`** — **CONFIRMED BLOCKED**, via two independent,
  exhausted paths: no `trivy`/`grype` binary (not in apt; GitHub releases
  403), AND — this is the more interesting finding — a container runtime
  genuinely *can* be started in this sandbox (`dockerd` reaches a healthy
  `docker info` in ~6s, overlayfs storage driver) but Docker Hub itself is
  blocked at the registry layer (`docker pull hello-world` and
  `docker pull aquasec/trivy:latest` both return `403 Forbidden` on the
  `registry-1.docker.io` manifest request). A working daemon with zero
  pullable images is still zero container-scanning capability. Reported
  as `BLOCKED` (an environment/network constraint distinct tools install
  won't fix), not `UNAVAILABLE` (a local tooling gap) — see
  `security/models.py::ScannerAvailability`'s docstring for that
  distinction, new in Phase 4.

### Normalized finding model, remediation, and the "never print the secret" rule (Parts 2/4/5/6)

`security/models.py::SecurityFinding` is deliberately richer than Phase
3's `VulnerabilityFinding` (adds category, confidence, resource, status,
false-positive state, task/verification linkage) since it spans four
scanner categories rather than one CVE feed. `security/remediation.py`
implements three **narrow, verified-shape** fixers — never a generic
"apply what the scanner text suggests" rewriter:

- **Secret remediation**: `assess_credential_likelihood()` flags
  known-placeholder values (AWS's own `AKIAIOSFODNN7EXAMPLE` doc example,
  values/lines containing "example"/"placeholder"/"dummy"/"fake") as not
  requiring rotation, and everything else as requiring it.
  `plan_secret_remediation()` only matches a literal `NAME = "value"`
  assignment line; anything else (an f-string, a function call) returns
  `None` and the finding is escalated instead of guessed at. The
  generated `SecretRemediationPlan` **cannot contain the raw value in any
  field** — enforced by an `assert` at construction time, not just
  convention — including in `original_line`, which is scrubbed the same
  way `redaction.redact()` scrubs known patterns. `security/
  secret_manager.py::SecretReferenceManager` is a **separate, repo-facing**
  Protocol from the platform's own `src/aep/secrets.py::SecretManager` —
  the former decides what a *target repository* should reference (e.g.
  `os.environ["X"]`); the latter resolves the *platform's own* credentials
  (its GitHub token). Only one concrete adapter ships (`EnvVarSecretReference`),
  per Part 4's explicit "do not hard-code AWS/Azure/OCI into the core."
  `inspect_git_history_for_secret()` is read-only (a `git log` count,
  policy-gated via the new, explicitly-`allow`ed
  `security.git_history_inspection` action) and never rewrites history.
- **SAST remediation**: one fixer, for `dangerous-subprocess-shell-true`
  only, matching the exact shape `subprocess.run("<literal>" + var,
  shell=True)` and rewriting it to
  `subprocess.run(["<tok1>", "<tok2>", var], shell=False)`. Every other
  bundled rule (SQL injection, pickle, unsafe YAML, eval/exec, weak hash)
  has no auto-fixer and is always escalated — Part 5 asks for *one*
  demonstrated real fix, not five guessed ones.
- **IaC remediation**: one fixer, for checkov's `CKV2_AWS_6` (S3 public
  access block) specifically — matched by **rule id**, not just "any
  finding on an S3 bucket resource" (a real bug caught by this phase's own
  end-to-end test: matching by resource type alone applied the identical
  "add an access-block resource" fix once per S3-related finding,
  duplicating the appended Terraform block seven times for one bucket).
  The fix changes `acl = "public-read"` → `"private"` and appends a real
  `aws_s3_bucket_public_access_block` resource. The open-ingress
  security-group finding from the same fixture (`CKV_AWS_24`) is
  deliberately never auto-fixed — picking a "correct" restricted CIDR
  needs operator knowledge this platform doesn't have — and is always
  escalated instead.
- Container remediation (Part 7) has no code at all: trivy is BLOCKED, and
  Part 7 explicitly forbids auto-upgrading a base image without
  compatibility verification, so there is nothing safe to automate yet.

### SecurityAgent (Part 3) and severity → policy mapping (Part 8)

`agents/security_intelligence_agent.py::SecurityAgent` mirrors
`DependencyCVEAgent`'s four-mode shape (`scan`/`remediate`/`rescan`/
`escalate`), reusing only existing capabilities
(`filesystem.*`/`git.*`/`shell.run`) — no new Tool type. Severity maps to
the *existing* `PolicyEngine.evaluate()` (new `config/policy.yaml` rules,
no new mechanism):

- **CRITICAL → DENY**: always escalated, **even when a safe mechanical fix
  could technically be built** — this is how "automatically block merge/
  deployment" is enforced: no PR is ever opened for an unresolved
  CRITICAL, because it never reaches the remediate/PR path at all.
- **HIGH → REQUIRE_APPROVAL**: "remediation required" — a safe fix (if one
  exists) is attempted automatically; anything without one escalates.
- **MEDIUM → WARN**: attempted opportunistically if a safe fix exists,
  else tracked via escalation.
- **LOW/INFO → ALLOW** (explicit rules, not `default_posture: deny`
  fallthrough — the fallthrough would otherwise route every low-severity
  finding into the same escalation path as CRITICAL): tracked in scan
  evidence, never auto-remediated, to avoid low-value PR churn.
- Every SECRET finding additionally records the **pre-existing**,
  unconditional Phase 1 `secret.commit` DENY decision as evidence — Part
  8's "secret detected → block commit" reuses that rule rather than adding
  a duplicate.

`mode="rescan"` is Phase 4's verification gate, identical in spirit to
Phase 3 Part B: it re-runs the real scanner category(ies) touched by this
remediation and only reports success if the specific finding fingerprint
is actually gone from the fresh results — an evidence line literally
starting `NOT resolved` otherwise, never a false `CONFIRMED resolved`.
`security/planner.py::build_security_remediation_chain` builds
`security_remediate → run_tests → security_rescan → push_branch →
create_pull_request → monitor_ci`, reusing `github/planner.py::
build_push_task` directly, exactly like `dependency/planner.py`.

### False-positive suppression (Part 9)

`security/suppressions.py` records suppressions as ordinary, append-only
`Event`s through the *existing* StateStore/EventLogger machinery (same
approach as `progress/calculator.py::record_phase_verified`) — there is no
`DELETE` anywhere in this module. `suppress_finding()` requires all five
Part 9 fields (justification, reviewer, evidence, plus the always-present
finding id and optional expiry) and raises on a blank one. Revoking a
suppression appends a *new* event rather than touching the original —
`list_suppressions()` replays the full log, so a suppressed-then-revoked
finding is still fully visible with `revoked=True`, never silently gone.

### Security posture (Part 10)

`security/posture.py::compute_security_posture()` is a pure function over
already-collected `SecurityScanRecord`s + Phase 3's `dependency.models
.ScanRecord`s + suppressions — same "compute fresh from real evidence,
never store a percentage" rule as `progress/calculator.py`. The five
category rows match the spec's own example verbatim (Secrets/SAST/
Dependencies/IaC/Containers); readiness is `NOT_READY` if any category is
`BLOCKED`/`UNAVAILABLE`, or any *unsuppressed* CRITICAL/HIGH finding is
open. Because `trivy` is permanently `BLOCKED` in this sandbox, **every
live posture run here reads `NOT_READY`** — this is the honest, expected
outcome given Part 7's constraints, not a bug. Wired into
`aep status`/`aep progress` via an opt-in `--security-repo PATH` flag
(kept opt-in so the default, fast, dependency-free `aep status` path is
unaffected — Part 11's explicit "do not break the existing Phase 1–3
status calculations"), and into a standalone `aep security-status
--repo PATH` command. `aep security-suppress`/`aep security-suppressions`
expose Part 9's model from the CLI.

**Dogfooding note**: running `aep security-status --repo .` against this
platform's own repository reports `Secrets: N HIGH` — gitleaks correctly
detects the fake AWS-key patterns used throughout `tests/conftest.py`,
`tests/test_providers.py`, and `tests/test_end_to_end_demo.py` to test the
redaction/secret-scanning logic itself. These are genuine gitleaks
findings (the values really are shaped like AWS keys), correctly NOT
auto-remediated by this same platform (they don't match
`plan_secret_remediation`'s single-assignment-line shape inside test
files using them as string literals in assertions), and are exactly what
`security-suppress` exists for: an operator can suppress each with a
justification ("test fixture, not a real credential") rather than the
platform silently ignoring or deleting them.

### Roadmap and progress (Part 11)

`config/roadmap.yaml`'s Phase 4 has 15 capabilities (scanner framework,
one per scanner category, the unified model, the agent pipeline, one per
remediation category, policy integration, suppression, posture, real E2E
verification, and the agent threat-model). `security.container_scanning`
is `blocked: true` with the dual-path-exhausted reason above — this means
**Phase 4 can never read `COMPLETE` in this sandbox**, by construction,
matching Part 11's "do not invent percentages" and Phase 3's identical
precedent for `dependency.container_scanning`/`dependency.go_scanning`.
`progress/deployability.py`'s later-phase blocker message was also
tightened (`"Phase 4 is IN_PROGRESS (93.3%)"` instead of a hardcoded
`"not started"`) once Phase 4 became the first later phase to actually
have partial progress — a wording fix, not a logic change; no existing
test asserted the old exact string.

### Testing (Part 13) and end-to-end verification (Part 12)

Nine new test files, 71 new tests, all 175 passing alongside the
unmodified Phase 1–3 104: `test_security_models.py`,
`test_security_scanners.py` (real gitleaks/semgrep/checkov against real
fixtures, skipped-not-faked if a binary is genuinely absent; trivy's
BLOCKED state asserted directly, not skipped), `test_security_discovery.py`,
`test_security_remediation.py` (includes the hard "raw value never
appears in any plan field" assertion), `test_security_suppressions.py`,
`test_security_policy.py`, `test_security_posture.py`,
`test_security_agent.py` (mode-level wiring, monkeypatched scanner layer
for fast/offline coverage — mirrors `test_dependency_agent.py`),
`test_security_e2e.py` (Part 12's real, unmocked DISCOVER→REMEDIATE→
TEST→RESCAN→VERIFY for secret/SAST/IaC, plus an explicit
"container is BLOCKED not mocked" assertion), `test_cli_security_status.py`,
and `test_security_agent_safety.py` (Part 14, below).

**REAL LOCAL EXECUTION, no mocked transport of any kind in this phase's
own new tests** (Phase 4 doesn't add a new external network dependency the
way Phase 2's GitHub client or Phase 3's PyPI/npm registries did — every
scanner here is a local binary): `test_security_e2e.py` demonstrates, for
secret/SAST/IaC independently, a disposable fixture with a genuine
vulnerability → the real scanner finds it → `SecurityAgent` builds a real
plan → applies a real fix on disk → the real project test suite still
passes → the real scanner runs again → confirms the specific finding is
gone. GitHub PR/CI hand-off is not re-tested here (Phase 3's
`test_dependency_github_loop.py` already proves that shared push/PR/
monitor_ci wiring against `FakeGitHubTransport`); `include_github=False`
is used throughout this phase's E2E tests, exactly like Phase 3's
standalone `test_dependency_e2e_real.py`.

### Threat-modeling the agent itself (Part 14)

`test_security_agent_safety.py` asserts, from the actual source (not just
this prose): `SecurityAgent` never calls `router.generate`/imports
`subprocess` directly (every command goes through capability-scoped
`shell.run`, so a malicious repository's file content has no prompt to
inject into and no direct execution path); no scanner adapter calls
`subprocess`/`os.system` itself or `eval`s/`exec`s/unpickles scanner
output; `required_capabilities` is never mutated at runtime; every
`ctx.policy.evaluate(...)` call site uses a fixed string action literal,
never an f-string built from a finding's own text (which would otherwise
let poisoned repository content or scanner output forge a different
policy rule match); and `remediation.py` never logs a raw secret value.
Scanner output and repository content are both treated as untrusted data
throughout — normalized into `SecurityFinding` objects before any
decision is made from them, never passed to a shell or a policy action
string verbatim.

## 26. Phase 5 Addendum: Infrastructure Intelligence & Remediation

Added on top of Phase 1–4 without changing `orchestrator.py`,
`models.py`, `tool_registry.py`, `policy.py`'s evaluation order, the
Phase 4 scanner framework, or the GitHub pipeline. Phase 5 is a new
`infra/` package (parallel to `dependency/` and `security/`), two new
agents, one new planner, `infra.*` rules added to `config/policy.yaml`,
17 new roadmap capabilities, three new CLI commands, and one small
correctness fix to Phase 4's posture renderer (below) — not a redesign.

### Reusing the Phase 4 scanner framework rather than duplicating it

Part 2 is explicit: "Integrate with the existing SecurityScanner
framework rather than creating a duplicate scanner architecture." That is
satisfied structurally, not by convention. Every module in
`infra/scanners/` exposes the exact Phase 4 adapter surface
(`check_availability`/`describe`/`scan`), returns Phase 4's
`SecurityScanRecord`/`SecurityFinding`, and is executed by Phase 4's
`security/scan_runner.py::run_security_scan()` through the `scanners=`
parameter that already existed. There is no second scanner runner, no
second finding model, and no second availability enum in Phase 5.

Two new `SecurityCategory` members (`KUBERNETES`, `HELM`) are additive
only: `INFRA_SCANNERS` is a separate tuple from Phase 4's `ALL_SCANNERS`,
so `security.discovery.discover_scanners()` and every Phase 4 test still
describe exactly the original four categories. Terraform stays under
`IAC`, since Phase 4's checkov adapter already owns it.

**One Phase 4 fix was required**: `security/posture.py` rendered one row
per scan *record*. With Phase 5 adding a second scanner to two categories
(`iac`: checkov + terraform-deep; `kubernetes`: checkov-kubernetes +
k8s-native) that produced two separate "IaC" rows — and worse, a passing
row could sit directly above a failing one for the same category. Records
are now grouped by category with "worst availability wins", so a
partially-covered category can never render as a clean PASS. Phase 4 had
exactly one scanner per category, so its behavior and tests are unchanged.

### What is real, what is blocked, and one dangerous default

Real and verified against the shipped fixtures in `tests/fixtures/infra/`:

- **checkov Kubernetes policy set** (`checkov_k8s_scanner.py`) — offline,
  no cluster. Returns 30+ real findings on the fixture covering every
  category Part 3 names: privileged (CKV_K8S_16), hostNetwork/hostPID
  (19/17), added capabilities (25/37), root execution (23), missing
  CPU/memory requests+limits (10–13), missing probes (8/9), wildcard RBAC
  (CKV_K8S_49) and RBAC escalation (155–158).
- **Native Kubernetes analysis** (`k8s_native_scanner.py`) — closes four
  Part 3 gaps checkov's set does not cover. Verified concretely: the
  fixture's `type: NodePort` Service with `nodePort: 30080` drew exactly
  ONE checkov finding (CKV_K8S_21, "default namespace") and nothing at
  all about being node-exposed. This module adds NodePort/public-LB
  exposure, hostPort binding, committed `Secret` data, ingress-without-TLS,
  and missing NetworkPolicy.
- **python-hcl2 Terraform analysis** (`terraform_deep_scanner.py`) —
  complements, never duplicates, Phase 4's checkov Terraform scanner. It
  covers configuration-level risks that are not properties of any
  resource: hardcoded provider credentials, `local` state backends,
  backends with `encrypt = false`, and unpinned providers. It invokes no
  binary at all, which is why it stays AVAILABLE where the `terraform`
  CLI is BLOCKED.
- **kubernetes-validate schema validation** — bundled upstream schemas,
  no cluster. Verified to accept the fixture and reject `replicas:
  "three"` with a type error.

Genuinely BLOCKED, with the reason recorded in `config/roadmap.yaml`:

- **`terraform` CLI** — `releases.hashicorp.com` is unreachable through
  the egress proxy (curl `000`), the same block pattern §23–§25 document
  for `api.github.com`, `proxy.golang.org` and `registry-1.docker.io`. So
  `terraform fmt` and `terraform validate` cannot run.
- **`helm` CLI** — `get.helm.sh` unreachable. `helm lint`/`helm template`
  cannot run and charts cannot be rendered.
- **`kubectl`, kube-score, kube-linter, kubescape** — `dl.k8s.io`
  unreachable; the Go tools need `proxy.golang.org` (403).
- **Live cloud** — no credentials, no reachable endpoint.

**The dangerous default worth its own paragraph.** checkov ships a
`--framework helm`, which looked like the obvious answer for Part 4. With
the `helm` binary absent it renders nothing, finds nothing, and exits
**zero**:

```
$ checkov -d . --framework helm -o json --quiet    # helm binary ABSENT
{"passed": 0, "failed": 0, "resource_count": 0, ...}
$ echo $?
0
```

A naive integration would have reported "Helm: PASS" for a chart that is
demonstrably full of privileged/root/NodePort/wildcard-RBAC defaults.
Nothing would have been fabricated — a tool's exit code would simply have
been trusted without checking whether it actually ran. `helm_scanner.py`
therefore checks for the binary FIRST and reports `BLOCKED` regardless of
what checkov would say, while still returning real findings from a real
parse of `values.yaml` (plain YAML, and where a chart's insecure defaults
actually live). The posture renders this as `Helm  BLOCKED (+9 found)` —
partial coverage stated as partial coverage.

### Validation is three-state, and "did not run" is never "passed"

`infra/validation.py` returns `ValidationResult(ran, passed, ...)` rather
than a bool. That is the single most consequential design decision in
Phase 5: with `terraform fmt`, `terraform validate`, `helm lint` and
`helm template` ALL blocked here, a two-state return would have silently
reported "validated" for every Terraform and Helm change this platform
makes. `summarize()` returns `validated=True` only when at least one
validator RAN and everything that ran passed; a set in which nothing ran
can never be True. `InfrastructureIntelligenceAgent._remediate` **reverts
the file and fails the task** when validation does not pass — a change
this platform cannot validate is not committed on hope.

### Risk model (Part 8) — escalation-only, on purpose

`infra/risk.py` scores each finding as `base × environment × blast_radius
× exploitability` and separately computes a *priority* severity, which is
what the policy engine evaluates (not the raw scanner severity — that is
what makes production weighting actually change behavior). Environment
comes from `infra/discovery.py::infer_environment`, a path-convention
heuristic that records a confidence and defaults to `UNKNOWN` rather than
guessing production.

Risk context can only ever **escalate** a finding, never demote it. A
CRITICAL in a directory that looks like dev stays CRITICAL. De-escalating
on an inferred environment would mean a mis-inferred path silently hides a
real problem; escalation-only keeps the heuristic's failure mode noisy
instead of dangerous. Promotion also requires *two* aggravating factors,
so a single one doesn't push everything to CRITICAL and flatten the
ranking.

### Remediation (Part 9) and what is deliberately never fixed

Same discipline as Phase 4: every fixer matches an exact verified shape
and returns `None` otherwise, so unrecognized cases become
human-approval tasks. Kubernetes fixes operate on the parsed document
(privileged→false, drop hostNetwork/hostPID/hostIPC,
allowPrivilegeEscalation→false, runAsNonRoot with the contradictory
`runAsUser: 0` corrected in the same edit — otherwise the "fix" produces
a pod the kubelet rejects at admission, capabilities dropped to `ALL`,
conservative resource requests/limits inserted). Terraform fixes are
anchored text rewrites, because python-hcl2 can read HCL but not write
it and reconstructing HCL from a parse tree would mangle every file it
touched.

Never auto-fixed, by design: IAM policy documents and wildcard RBAC
(choosing a least-privilege action list requires knowing what the
workload does), security-group and NetworkPolicy CIDRs (identical
reasoning to Phase 4's refusal on `CKV_AWS_24`), base images, and
anything touching live infrastructure. **And every CRITICAL finding**,
even one this platform has a working mechanical fix for — `CKV_K8S_16`
(privileged) is auto-fixable and is nonetheless always escalated, because
`infra.finding severity=critical` is a policy DENY. `test_infra_e2e.py`
asserts `privileged: true` is still present after a full pipeline run
alongside its escalation task, so a future change that started
auto-fixing CRITICALs fails loudly.

### Cloud adapters (Part 5/6/12) — one provider, read-only by construction

`infra/cloud/base.py` defines a provider-agnostic `CloudProviderAdapter`
covering all eleven Part 5 capability areas. Read-only is structural, not
advisory: the contract contains no create/update/delete verb at all,
`CloudCapability` enumerates only inspections, and `assert_read_only()`
raises `ReadOnlyViolation` for any operation not on an explicit allowlist
— including `get_session_token`/`get_secret_value`, which start like
reads but mint or expose credentials. Every AWS API call routes through a
single `_call()` that gates first.

AWS is the one fully-implemented provider (boto3 is the only cloud SDK
installable here). Azure/GCP/OCI ship **no adapter at all** rather than
stubs: an empty result from a stub is indistinguishable from a real
adapter reporting a clean account — the same false-assurance failure the
Helm scanner exists to avoid. `registry.describe_provider()` reports
`NOT_IMPLEMENTED` with a reason instead.

**A false positive worth documenting.** `status()` originally checked
whether boto3 could resolve credentials. It reported `AVAILABLE` — and
`CloudDiscoveryResult.is_real` would have been True — for an AWS account
that does not exist, because this sandbox exports
`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` holding its **egress proxy's**
credentials: a 14-character value beginning `prox`, not a 20-character
`AKIA...` key. The actual API call fails with `ProxyConnectionError`.
`status()` now does a cheap shape check and then a real, read-only
`sts:GetCallerIdentity` round-trip; a network failure is `BLOCKED`, an
auth failure is `UNAVAILABLE`, and only a successful response is
`AVAILABLE`. **This platform has never contacted a real cloud account**,
and `is_real` is False for every result it has ever produced.

### Drift (Part 7)

`infra/drift.py` compares repository desired state against adapter-
reported actual state and produces a `DriftReport` with three kinds:
`drift` (attribute differs), `unmanaged` (live but undeclared — always
flagged security-relevant, since nobody reviews it and no repository
scanner can see it), and `missing`. Security-relevant attribute changes
are separated from cosmetic ones. `reconciled` is hard-coded `False`,
nothing in the module writes anywhere, and the produced plan is a list of
instructions for a human that explicitly states nothing was executed.
`desired_state_from_terraform()` reads configuration, not a plan or state
file, and marks unresolvable interpolations `<computed>` rather than
guessing.

### Agents and policy (Part 11/14)

`InfrastructureDiscoveryAgent` declares **only** `filesystem.list` and
`filesystem.read`. It is structurally incapable of running a command,
using git, or calling GitHub, because the capability-scoped
`ScopedRegistry` will not hand it those tools — Part 6's "discovery must
default to read-only" is enforced by construction, with a policy check on
top. `InfrastructureIntelligenceAgent` mirrors the four-mode shape of
`DependencyCVEAgent` and `SecurityAgent`, and `infra/planner.py` builds
`infra_remediate → run_tests → infra_rescan [→ push_branch →
create_pull_request → monitor_ci]` reusing `build_push_task` directly.
Validation is not a separate task: it runs inside `infra_remediate`
immediately after each write, because a gate whose job is to prevent a bad
commit must run before the commit, not after.

New `config/policy.yaml` rules, using the existing engine: `terraform
apply`, production IAM/networking modification, cluster apply and
credential rotation are `REQUIRE_APPROVAL`; live resource deletion and
`terraform destroy` are `DENY` (not approval-gated — this platform should
not perform them at all); read-only discovery is `ALLOW` conditioned on
`read_only: true`, so the allowance cannot silently widen; repository
fixes are `ALLOW`. Note the deliberate asymmetry: non-production IAM
changes match no rule and hit `default_posture: deny`, which is stricter
than production's approval gate — documented in the policy file itself so
it reads as intent rather than oversight. **Phase 5 never invokes any of
the mutating actions**; they are declared now so the gate exists before
any phase gains the ability to trip it.

### Threat model (Part 17)

Infrastructure configuration is untrusted input: a Terraform file, a
Kubernetes manifest, a Helm template and a cloud API response are all
attacker-controllable in a repository this platform is pointed at.
`tests/test_infra_threat_model.py` asserts from the actual source that
neither infra agent calls an AI provider (so there is no prompt for
repository content to inject into); no `infra/` module imports
`subprocess`, uses `os.system`, or passes `shell=True` (every command
goes through the allowlisted capability-scoped shell tool); nothing
`eval`s, `exec`s or unpickles configuration; YAML is always
`safe_load`ed; capability sets are never mutated at runtime; every
`ctx.policy.evaluate()` call uses a fixed string literal so a crafted
resource name cannot forge a different policy decision; no argv anywhere
would execute `terraform apply`/`kubectl delete`/`helm upgrade`; the
cloud contract has no write verb; and no credential value or unmasked
account id reaches a finding.

### Testing (Part 16)

Thirteen new test files, 163 new tests, 338 passing in total with all 175
Phase 1–4 tests unmodified and still green. `test_infra_e2e.py` is the
real, unmocked pipeline: real fixtures → real checkov/hcl2 → real risk
ranking → real fixes on disk → real kubernetes-validate → real test suite
→ a second real checkov run confirming resolution. Two bugs in Phase 5's
own code were caught by it and fixed before this report: an IaC
remediation that matched by resource type instead of rule id and so
appended the same Terraform block once per S3-related finding, and a Helm
subchart filter that skipped the extremely common top-level
`charts/myapp/Chart.yaml` layout — leaving a whole chart unscanned while
the scan still reported success.

## 27. Phase 6 Addendum: CI/CD & Deployment Intelligence

Added on top of Phase 1–5 without touching `orchestrator.py`, `policy.py`'s
evaluation order, the Phase 4 scanner framework, `infra/`, or the GitHub
pipeline. Phase 6 is two new sibling packages (`cicd/`, `deployment/`,
parallel to `dependency/`/`security/`/`infra/`), three new agents
(`CIIntelligenceAgent`, `DeploymentAgent`, `DeploymentVerificationAgent`),
one new tool (`deployment`, alongside `git`/`filesystem`/`shell`/`github`),
nine new `FailureClass` members, `deployment.*` rules added to
`config/policy.yaml`, thirteen new roadmap capabilities, two new CLI
commands plus a `--cicd-repo` opt-in flag, and 87 new tests — not a
redesign of anything that existed before.

### CI/CD abstraction and pipeline discovery (Parts 1–2)

`cicd/providers/base.py` is a `Protocol` deliberately shaped like
`infra/cloud/base.py`'s `CloudProviderAdapter`: a `status()` call that
performs a real round-trip and classifies the result as
AVAILABLE/MOCKED/UNAVAILABLE/BLOCKED, never inferred from "a token is
configured." Exactly one provider is fully implemented —
`cicd/providers/github_actions.py`, a thin wrapper around the EXISTING
`github/client.py::GitHubClient` (Phase 2's transport-injection pattern,
reused verbatim — no second HTTP client exists anywhere in this repo).
GitLab CI, Jenkins, and a generic webhook provider are named in
`providers/registry.py` as architecturally supported and explicitly NOT
stubbed, for the identical reason Phase 5 shipped only an AWS cloud
adapter: an empty-looking stub is indistinguishable from a real adapter
reporting a clean pipeline.

Pipeline *discovery*, in contrast, needs no provider at all: `cicd/
discovery.py` parses `.github/workflows/*.yml` with `yaml.safe_load`
(never `yaml.load`, never executed) into a normalized `PipelineModel` —
jobs classified into BUILD/TEST/SECURITY/ARTIFACT/DEPLOY/APPROVAL/
ROLLBACK/LINT by name/step-text heuristics, `environment:` blocks read as
GitHub's built-in approval-gate mechanism, and a job's steps scanned for
rollback language. This works identically whether the live Actions API is
reachable or not, which matters a great deal in this sandbox (see below).

### What is REAL, MOCKED, or BLOCKED — stated once, precisely

Verified during Phase 6 investigation, the same way Phase 2/3/5 verified
their own network boundaries:

```
curl -m 6 -o /dev/null -w "%{http_code}" \
  https://api.github.com/repos/octocat/hello-world/actions/runs   -> 403
which kubectl                                                      -> (nothing)
docker info                                                        -> "Cannot connect to the
                                                                        Docker daemon"
pip show cyclonedx-python-lib                                      -> 7.6.2 (installed)
```

So, precisely:

- **GitHub Actions live API — BLOCKED.** `GitHubActionsProvider.status()`
  performs one real `get_repo` round-trip and returns `BLOCKED` with the
  403 recorded verbatim. `test_cicd_github_actions.py` proves this with an
  actual `curl` invocation, not an assumption, and separately exercises
  every classification branch (MOCKED/BLOCKED) with a `FakeGitHubTransport`
  or a synthetic 403 response so the *logic* is verified without needing
  the network to cooperate.
- **Kubernetes — UNAVAILABLE.** No `kubectl` binary, no cluster.
  `deployment/kubernetes_provider.py` is a fully-written real adapter
  (manifest apply, rollout status, pod/service checks, rollback via
  `kubectl rollout undo`) that has *never been exercised against a real
  cluster by this platform* — its `status()` says so, its `deploy()`
  refuses to even attempt an apply when unavailable, and it is never the
  default provider anywhere in `bootstrap.py`.
- **Local fixture deployment — REAL, but explicitly not live infra.**
  `deployment/local_provider.py` is the one fully-implemented,
  safe-by-default `DeploymentProvider`: it really writes and reads back
  JSON state representing replica counts and a version history on disk,
  and `verify()`/`rollback()` are real logic over that real (if
  locally-simulated) state — not hard-coded `True`. `status()` reports
  `LOCAL_FIXTURE`, a fourth availability value distinct from `AVAILABLE`,
  so nothing downstream can mistake a passing E2E test for a live
  Kubernetes verification.
- **SBOM generation — REAL, scoped.** `cyclonedx-python-lib` is installed
  in this sandbox; `cicd/artifact.py::generate_sbom()` produces a real
  CycloneDX BOM from a project's `requirements*.txt` files. This is
  Python-dependency-only — no container-layer or other-language SBOM tool
  (`syft`, the `cyclonedx-py` CLI) is installed here, and the result says
  so explicitly.
- **Provenance signing — never claimed.** `Provenance.signed` is `False`
  unconditionally; there is no cosign/sigstore infrastructure in this
  sandbox, and `signature_reason` says exactly that rather than omitting
  the field.

### Failure classification (Parts 3, 14)

`cicd/failure_classification.py::classify_ci_failure()` is a signal-shape
classifier over job/step names and log text — the same discipline
`failure.classify()` already applies to Python exceptions, extended to a
domain `failure.classify()` cannot see at all (it only ever receives a
raised exception, never a GitHub Actions job list). Nine `FailureClass`
members were added to the EXISTING enum in `models.py`
(`DEPENDENCY`/`BUILD`/`CI_CONFIGURATION`/`DEPLOYMENT`/`HEALTH`/`NETWORK`/
`EXTERNAL_SERVICE`/`FLAKY`/`UNKNOWN`) — every Phase 1–5 member and every
existing `classify()` branch is untouched. `CI_CONFIGURATION` and
`UNKNOWN` were added to `failure.NO_AUTO_RETRY` (a malformed workflow or
an unrecognized signal is not fixed by waiting and retrying).
`CIIntelligenceAgent.classify` mode routes CODE/TEST/BUILD/DEPENDENCY/
FLAKY into the EXISTING `github/planner.py::build_fix_verify_push_chain`
(Phase 2's fix-verify-push loop, reused, not reimplemented) and escalates
everything else — CI logs are untrusted data read only as strings for
substring matching, never executed, never used to build a policy action.

### Build artifacts and release gates (Parts 4–5)

`cicd/artifact.py::BuildArtifact.is_deployable` is `True` only when both
`security_scan_status` and `test_status` are recorded `PASSED` — the
default is `NOT_RUN`, which never counts, mirroring `infra/validation.py`'s
`ran=False != passed` rule exactly. Artifact identity is a real
`sha256` digest of actual content, never a random id.

`cicd/release_gates.py::evaluate_release_gates()` is a pure function over
already-computed booleans (SOURCE/DEPENDENCIES/SECURITY/INFRASTRUCTURE/
CI/ARTIFACT/APPROVAL/DEPLOYMENT, matching the Phase 6 spec's example
verbatim) — it does not scan, build, or call anything, which keeps "never
fabricate a pass" enforceable in one small module: every gate defaults to
`NOT_RUN`, and `NOT_RUN` never satisfies `all_required_passed`.
Infrastructure gates are `required=` only when the caller says
`infra_required=True` (from real `infra.discovery` output), so a
non-infrastructure project is never blocked on a gate that has nothing to
check.

### Environment model and deployment policy (Parts 6, 11)

`cicd/environment.py::DeploymentEnvironment` (development/staging/
production) is a deliberate sibling of, not a reuse of,
`infra.models.Environment` — the infra enum is a heuristic *inference*
about a repository path with a confidence score; this one is an explicit,
caller-declared deployment target. Conflating them would let a
mis-inferred Phase 5 heuristic silently select a production deployment
policy.

`config/policy.yaml` gained, fully evaluated through the EXISTING
`PolicyEngine` (no new policy mechanism): `deployment.deploy` is
`ALLOW` for development/staging and `REQUIRE_APPROVAL` for production;
`deployment.rollback` mirrors that; and `deployment.emergency_rollback`
is a **separate, narrowly-scoped action name** (never a flag on the
normal rollback action) matched only for
`{environment: production, reason: critical_rollout_failure}` — the one
explicit "automatic rollback allowed in production" carve-out the spec
asks for. Every one of these action strings is a fixed literal in
`deployment_agent.py`/`environment.py`; `test_cicd_threat_model.py`
asserts this from source the same way Phase 4/5's threat-model tests do.
Phase 5's `infra.*_destroy`/`infra.*_delete` DENY rules and
`infra.credential_rotate`'s REQUIRE_APPROVAL are asserted untouched.

### Deployment abstraction, verification, and rollback (Parts 7–10, 13)

`deployment/provider.py::DeploymentProvider` is the five-verb contract
(`plan`/`deploy`/`status`/`rollout_status`/`verify`/`rollback`). `deploy →
observe → verify → decide` is enforced structurally, not by convention:
`DeploymentAgent` never marks a deployment `VERIFIED` without a separate
`provider.verify()` round-trip having actually run and passed, and
`kubernetes_provider.py`'s docstring/tests specifically prove `kubectl
apply` succeeding does not by itself satisfy `verify()`.

`DeploymentVerificationAgent` is a deliberately narrower, separate agent
from `DeploymentAgent` — the same "narrower sibling" split Phase 5 used
for `InfrastructureDiscoveryAgent` vs `InfrastructureIntelligenceAgent`.
It can observe and re-verify an existing deployment on its own later
(a scheduled re-check) but holds no `deployment.deploy`/
`deployment.rollback` capability, so it structurally cannot mutate
anything.

`deployment/rollback.py::plan_rollback()` implements the Part 10 table
literally: a CRITICAL rollout failure or a health-check failure is
rollback-eligible; a SECURITY gate failure blocks the deployment instead
(rolling back does not fix a compromised finding — a human must); an
unrecognized failure requires approval rather than guessing. Production
adds `requires_approval=True` on top of eligibility regardless — the
`deployment.emergency_rollback` policy action above is the only way past
that, and it is evaluated by `DeploymentAgent`, never granted by
`rollback.py` itself.

Every deployment attempt's evidence (task id, commit sha, artifact,
environment, release-gate result, approval status, start/end,
rollout/verification/rollback status, final state) is written via
`deployment/evidence.py` as an `Event` on the platform's EXISTING
`StateStore` — the same durable, crash-safe SQLite log Phase 1 already
built, not a new storage primitive. `test_deployment_evidence.py` proves
"survives a process restart" literally, by closing one `StateStore` and
reopening a fresh instance against the same file.

The `deployment` tool (`tools/deployment_tool.py`) routes every
provider call through the EXISTING capability-scoped `ToolRegistry` — the
same audit/permission boundary `shell.run`/`git.*` already enforce — so
`DeploymentAgent`'s declared capabilities are the only way it can reach a
provider at all, and `deployment_verification_agent` structurally cannot
deploy or roll back.

### Testing and threat model (Parts 19–20)

Fifteen new test files, 87 new tests, 425 passing in total with all 338
Phase 1–5 tests unmodified and still green (full suite: `python3 -m
pytest -q`, ~9 minutes — most of that is Phase 3–5's own real-tooling
tests, unaffected by Phase 6). `test_cicd_e2e.py` is the real, unmocked
pipeline described in Part 15/16: a disposable git repo → real pytest →
real deterministic secret scanner → real static workflow discovery → a
real content-digest artifact → release gates computed from those real
results → a real local-fixture deployment → a real, separate
re-verification call → evidence read back from a freshly-opened
`StateStore`; plus the two required failure scenarios — a deployment that
fails verification, is classified, found rollback-eligible, and is
automatically rolled back with recovery confirmed by a second real
`verify()` call; and a production deployment that is correctly blocked on
human approval with the provider never contacted at all.

`test_cicd_threat_model.py` asserts, from actual source: no `cicd`/
`deployment` module calls an AI provider; workflow YAML is always
`safe_load`ed; nothing `eval`s/`exec`s/unpickles; no module besides the
one real `kubectl` wrapper imports `subprocess`, and even that wrapper
never builds argv via string interpolation or `shell=True`; every policy
action is a fixed literal; the emergency-rollback action name is switched
only on the platform's own reason-code constants, never on a CI log
string; artifact identity is a real hash, never random; no destructive
`terraform destroy`/`kubectl delete`/`helm delete` argv exists anywhere in
Phase 6 code; and Phase 5's destructive-infrastructure DENY rules are
unmodified.

### Progress, deployability, and CLI (Parts 17–18)

`config/roadmap.yaml`'s Phase 6 block now has thirteen real capabilities,
each gated by one of the test files above — no invented percentage
anywhere, per the same rule Phase 3's progress engine has enforced since
it was written. `progress/deployability.py` already treated Phase 6 as
one of the phases gating `PRODUCTION_CANDIDATE` before this phase began
(see `_LATER_PHASES`); nothing there needed to change. `aep status`/`aep
progress` gained an opt-in `--cicd-repo` flag (fast, no-network pipeline
discovery, following `--security-repo`/`--infra-repo`'s pattern exactly),
and two new standalone commands: `aep ci-status --repo PATH` and `aep
deploy-status --project ID` (reads real, durable deployment evidence back
out of `StateStore`). `test_cli_cicd_status.py` follows
`test_cli_status.py`'s "never call the status-payload builder against
this repo's own real roadmap" rule for the same reason: this file itself
gates a roadmap capability.
