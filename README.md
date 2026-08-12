# Autonomous Engineering & DevSecOps Platform

A provider-agnostic control plane for autonomous software engineering work:
task orchestration, durable state, a capability-scoped tool registry, a
deny-by-default policy engine, and an AI-provider abstraction, built so the
model is a replaceable reasoning component rather than the thing the
architecture is built around. Phase 2 adds a real GitHub integration: repo
discovery, branches, PRs, PR comments, checks/CI status, issues, and a full
autonomous diagnose → fix → push → re-check CI loop. Phase 3 adds real
dependency/CVE scanning and remediation (pip-audit/npm-audit, smallest-
safe-upgrade selection, a second real scan before ever claiming "fixed"),
plus a durable, data-derived progress/deployability system. Phase 4 adds
real multi-scanner security intelligence (gitleaks/semgrep/checkov) with
verified remediation, suppression and posture reporting. Phase 5 adds
infrastructure intelligence: Terraform/Kubernetes/Helm discovery and
analysis, risk-weighted prioritization, validated repository-level
remediation, drift detection, and a read-only cloud adapter architecture.

Full design rationale, threat model, data model, and an honest phase-by-phase
status table are in **[ARCHITECTURE.md](./ARCHITECTURE.md)** (§23 Phase 2,
§24 Phase 3, §25 Phase 4, §26 Phase 5). This README is just "how do I run
it."

**This document intentionally contains no completion percentage.** Per an
explicit platform rule (Phase 3 Part C), progress is never hardcoded into a
doc — it's computed live from real test execution and the roadmap data file.
Run `aep status` / `aep progress` (see below), or read
[`config/roadmap.yaml`](./config/roadmap.yaml) directly, for the current
number.

## What's actually implemented here (Phase 1)

- **Orchestrator + Task Engine** — dependency-aware task graph, a real state
  machine (`PENDING → READY → RUNNING → SUCCEEDED/FAILED/...`), durable
  SQLite-backed state so a crashed process resumes from exactly where it
  left off (`src/aep/state_store.py`, `src/aep/orchestrator.py`).
- **Tool Registry** — git / filesystem / shell tools with real subprocess
  and filesystem I/O, capability-scoped per agent, every call audited
  (`src/aep/tool_registry.py`, `src/aep/tools/`).
- **AI Provider abstraction** — `AIProvider` protocol with a working offline
  `MockProvider` (used by all tests, no network/API key required) and an
  optional real `AnthropicProvider`; a `ModelRouter` handles per-task-type
  routing, fallback, and a hard token budget (`src/aep/providers/`).
- **Policy Engine** — declarative YAML rules, ALLOW/DENY/REQUIRE_APPROVAL/WARN,
  deny-by-default (`src/aep/policy.py`, `config/policy.yaml`).
- **Failure classification & recovery** — transient/security/test/etc.
  classification, exponential backoff, and a per-`(project, task_type)`
  circuit breaker (`src/aep/failure.py`).
- **A first real security gate**: a deterministic secret scanner
  (`src/aep/agents/security_agent.py`, `src/aep/redaction.py`) that blocks a
  task graph — not a WARN — when it finds a likely credential, and the same
  redaction logic keeps secrets out of prompts and the audit log.
- **Recon, Code, and Testing agents** operating on a real local git
  repository (branch/commit/diff), with real pytest execution.

What's specified but **not** implemented as running code — cloud/Kubernetes/
CI-CD adapters, SAST/SCA/IaC scanners beyond the secret pattern scanner, a
worker-pool supervisor for real 24/7 concurrency — is listed explicitly in
ARCHITECTURE.md §21-22, because this sandbox has no cloud credentials, no
live cluster, and no durable host to prove those against honestly.

## What's actually implemented here (Phase 2 — GitHub)

- **A real GitHub REST API client** (`src/aep/github/client.py`) — repo
  discovery, branches, commits, PR list/get/create/update, PR files,
  PR/issue comments, combined status, check-runs, issues, workflow runs and
  jobs. Speaks the actual documented endpoints; only the HTTP transport is
  swappable (real `requests`, or a test fake — same pattern as `AIProvider`).
- **A GitHub tool** in the same capability-scoped registry as git/filesystem/
  shell, plus a real `git push` capability that authenticates via a
  short-lived `GIT_ASKPASS` credential helper so the token never touches
  argv, logs, or Task state (`src/aep/tools/github_tool.py`).
- **A secret mechanism** (`src/aep/secrets.py`) — the GitHub token is never
  a literal config/payload value; it's resolved per-call from an
  environment-variable-backed `SecretManager`.
- **Four new agents**: `PushAgent`, `PullRequestAgent` (dedups against open
  PRs by branch before creating), `MonitorCIAgent` (reads real check-run
  state; polling is the *existing* retry/backoff mechanism, not a new
  loop), `DiagnoseCIFailureAgent` (pulls real failed-check/job evidence,
  asks the model for a fix description, comments on the PR, hands off to a
  fresh fix/verify/push chain).
- **A full autonomous CI loop**: discover → branch → implement → verify →
  commit → push → open PR → inspect CI → diagnose a real failure → fix →
  push again → re-check → green (or `BLOCKED_ON_APPROVAL` after
  `max_ci_loops` genuine attempts) — built entirely from Phase 1's existing
  `follow_up_tasks` mechanism; no new orchestrator construct.
- **Policy enforcement reused, not reinvented**: `github.push` is gated by
  the same policy engine, evaluated the same way, as `git.push` was in
  Phase 1 — protected branches denied, force-push requires human approval.

This work also found and fixed two real bugs in the Phase 1 core (a
circuit-breaker miscount that would wrongly quarantine a legitimately
polling task, and a policy gate that re-blocked an already-approved task)
plus one in the new GitHub client (branch names containing `/` broke
ref-based URL paths) — all three are detailed with regression tests in
ARCHITECTURE.md §23.

**Sandbox limitation, stated plainly**: this environment's egress proxy
returns 403 for `api.github.com` unless a repository is explicitly
authorized through a mechanism not exposed as a tool in this session, and no
GitHub credential/connector was available. The client/tool/agent code is
real and unmodified either way; the end-to-end demonstration here uses a
small stateful fake of the GitHub REST responses
(`tests/github_fakes.py`) plus a real local bare git repository standing in
for GitHub's git storage. Pointing this at a real repo needs only
`AEP_SECRET_GITHUB_TOKEN` and an `owner`/`repo` — no code changes.

## Quickstart

```bash
cd aep-platform
pip install -e .[dev]                       # add [dev,anthropic] for the anthropic SDK,
                                             # [dependency-scanning] for pip-audit
pytest -v                                   # full suite (338 tests as of Phase 5); most are fully
                                             # offline (MockProvider + fake GitHub transport, local
                                             # git/filesystem) - the dependency-scanning tests shell
                                             # out to real pip-audit/npm/gitleaks/semgrep/checkov and
                                             # are skipped, not faked, if those aren't installed
```

Run the demo end-to-end via the CLI against a throwaway repo:

```bash
mkdir -p /tmp/demo && cd /tmp/demo
git init -b main . && git config user.email a@b.com && git config user.name aep
printf 'def add(a, b):\n    return a - b  # bug\n' > app.py
printf 'from app import add\ndef test_add():\n    assert add(2, 3) == 5\n' > test_app.py
git add -A && git commit -m init

cd /path/to/aep-platform
python -m aep.cli --db /tmp/demo_state.db run-fix-bug \
  --project demo --repo /tmp/demo --file app.py \
  --description "add() subtracts instead of adding"
python -m aep.cli --db /tmp/demo_state.db status --project demo
python -m aep.cli --db /tmp/demo_state.db events --project demo
```

Without `ANTHROPIC_API_KEY` set, `code_fix` runs through the `MockProvider`
and returns a generic acknowledgment string rather than a real patch (so the
subsequent test run will legitimately fail — that's the deterministic
`TestingAgent` doing its job, not a bug). To see a real fix applied, either
export `ANTHROPIC_API_KEY` (routes `code_fix` through `AnthropicProvider`
automatically — see `build_router(use_anthropic=True, ...)` in
`src/aep/bootstrap.py`) or pass canned responses programmatically the way the
test suite does (`bootstrap.build_orchestrator(..., mock_canned={...})`).

**Keep the state DB outside the repo it's operating on.** `security_scan`
lists and reads every file under `project_root`; a stray `.db`/binary file
inside the repo is skipped cleanly (fixed after this was caught by a manual
end-to-end run during development — see the `filesystem.read` handler),
but there's no reason to put your durable state where a scan has to step
around it.

### Run the GitHub PR/CI loop demo

Against a real GitHub repo (needs a token with repo + actions scopes):

```bash
export AEP_SECRET_GITHUB_TOKEN=ghp_xxxxxxxx
python -c "
from aep.bootstrap import build_orchestrator
from aep.github.planner import plan_github_fix_and_pr
from aep.models import ProjectConfig

project = ProjectConfig(id='demo', name='demo', repo_path='/path/to/local/clone', policy_path='config/policy.yaml')
orch = build_orchestrator(db_path='gh_state.db', project=project, enable_github=True, use_anthropic=True)
plan_github_fix_and_pr(orch, project_id='demo', project_root='/path/to/local/clone',
                        target_file='app.py', bug_description='...',
                        owner='your-org', repo='your-repo')
orch.run_to_completion('demo')
"
```

Without a real token/repo (this sandbox), run the same flow against the
local fixture used by the test suite — `tests/test_github_ci_loop.py` is
runnable directly and prints nothing by design (it's a pytest test); to see
the full step-by-step trace, evidence, git log, and fake-PR/comment state
printed to stdout, see the standalone script pattern used during
development (reproduced in ARCHITECTURE.md §23's demonstration, or just
copy `tests/test_github_ci_loop.py::_setup`/`_build_orch` into a script and
add `print()`s around `run_to_completion`).

## What's actually implemented here (Phase 3 — Dependency & CVE Intelligence)

- **Real dependency manifest discovery** across four ecosystems
  (`src/aep/dependency/manifests.py`) — Python/Node.js/Go/container, not
  Python-only.
- **Real vulnerability scanning**: `pip-audit` for `requirements.txt`
  (verified against a real, currently-published CVE) and `npm audit` for
  `package.json` (verified against a real npm advisory). Go/container
  scanners are architected (`govulncheck`/`trivy` adapters exist) but
  honestly marked unverified in this sandbox — see ARCHITECTURE.md §24 for
  exactly why.
- **Smallest-safe-upgrade remediation planning** (`dependency/remediation.py`)
  — never jumps to "latest"; refuses to guess when there's no published fix
  or the fix-version strings aren't parseable, escalating those to a
  durable, queryable `BLOCKED_ON_APPROVAL` task instead.
- **Real remediation**: rewrites the actual manifest, commits, installs the
  upgraded package, runs the real test suite, then runs the **same real
  scanner again** and only reports a finding resolved if that second scan
  confirms it — see `DependencyCVEAgent`'s `rescan` mode.
- **Feeds the existing GitHub push/PR/CI workflow** (§23) unmodified — if
  CI fails afterward, the existing diagnose/fix loop takes over; dependency
  remediation itself never touches CI diagnosis.
- **A durable, data-derived progress/deployability system**
  (`src/aep/progress/`, `config/roadmap.yaml`) — `aep status` / `aep
  progress` compute phase/capability status and one of six deployability
  levels from a live test run, never a hardcoded number.

**Sandbox limitation, stated plainly**: `pip-audit`'s default backend
queries `pypi.org` (reachable here); a direct `osv.dev` client would not
work in this sandbox (confirmed unreachable). Go/container scanning needs
`proxy.golang.org` (blocked, 403) and a `trivy`/`grype` binary (absent) —
both are implemented as real adapters, just unverified here; see
ARCHITECTURE.md §24.

## What's actually implemented here (Phase 4 — Security Intelligence)

- **Real multi-scanner security intelligence**: `gitleaks` (secrets),
  `semgrep` against a bundled local ruleset (SAST — semgrep's remote
  registry is unreachable in this sandbox), and `checkov` (Terraform/IaC
  misconfiguration), all verified against real fixtures. Container
  scanning (`trivy`) is architected but **confirmed BLOCKED** — see
  ARCHITECTURE.md §25 for the two-independent-paths-exhausted evidence
  (no binary, and Docker Hub itself is registry-blocked even with a
  working local daemon).
- **A normalized `SecurityFinding` model** spanning all four categories
  (`src/aep/security/models.py`) — richer than Phase 3's
  `VulnerabilityFinding` (category, confidence, resource, status,
  false-positive state, verification linkage).
- **Real, narrow, verified-shape remediation** — never "blindly modify
  code based only on scanner text": a hardcoded secret is only rewritten
  to an environment-variable reference when it matches an exact
  `NAME = "literal"` assignment shape (and the raw value is structurally
  guaranteed to never appear in any stored plan/evidence field, enforced
  by an assertion, not just care); one specific `subprocess(shell=True)`
  SAST pattern is auto-fixed; one specific public-S3-ACL IaC finding is
  auto-fixed (adding a real `aws_s3_bucket_public_access_block` resource).
  Everything outside those exact shapes — including the open-ingress
  security-group finding from the same IaC fixture — is escalated to a
  human, never guessed at.
- **Severity-driven policy** via the *existing* `PolicyEngine`/
  `config/policy.yaml`: CRITICAL findings are **always** escalated, even
  when a mechanical fix exists, so an unresolved CRITICAL never reaches an
  automatic PR; HIGH gets an automatic fix attempt where safe; LOW/INFO
  are tracked, never auto-remediated.
- **A durable, append-only false-positive suppression model**
  (`aep security-suppress`) — a suppression is never a silent deletion;
  `aep security-suppressions` lists every one ever recorded, including
  revoked/expired ones.
- **Security posture reporting** (`aep security-status`, or
  `aep status --security-repo PATH`) in the exact Secrets/SAST/
  Dependencies/IaC/Containers PASS-or-severity-count format, with an
  explicit `NOT_READY`/`READY` readiness verdict and why.

**Sandbox limitations, stated plainly**: semgrep's remote rule registry
(`semgrep.dev`) is unreachable, so only the bundled local ruleset in
`security/rules/semgrep_rules.yaml` is used (six rules, real CWE coverage,
not semgrep's full registry). Trivy/container scanning is BLOCKED via two
independently-exhausted paths (no installable binary, and Docker Hub is
registry-blocked even though the Docker daemon itself can run locally) —
see ARCHITECTURE.md §25.

## What's actually implemented here (Phase 5 — Infrastructure Intelligence)

- **Real infrastructure discovery** (`src/aep/infra/discovery.py`) —
  a normalized, provider-agnostic inventory across Terraform roots vs
  modules vs state config, Helm charts, Kubernetes manifests, Kustomize,
  Dockerfiles, compose files, cloud/environment config, GitOps (ArgoCD/
  Flux), and CI workflows that actually touch infrastructure. Environment
  (production/staging/dev) is inferred from path conventions with a
  recorded confidence, and defaults to `unknown` rather than guessing.
- **Real Terraform and Kubernetes analysis** — checkov's Kubernetes
  policy set (privileged/hostNetwork/hostPID/capabilities/root/limits/
  probes/wildcard RBAC), plus native analysis for the gaps it doesn't
  cover (NodePort and public-LB exposure, hostPort, committed Secrets,
  ingress without TLS, missing NetworkPolicy), plus python-hcl2-backed
  Terraform analysis for configuration-level risks that aren't properties
  of any resource (hardcoded provider credentials, `local`/unencrypted
  state backends, unpinned providers).
- **Three-state validation** — `ran` / `passed` / `blocked`. A validator
  that could not run is **never** counted as a pass, and a change that
  cannot be validated is reverted rather than committed. This matters
  concretely here: `terraform fmt`, `terraform validate`, `helm lint` and
  `helm template` are all BLOCKED in this sandbox, so real HCL2 structural
  parsing and real `kubernetes-validate` schema checks (bundled schemas,
  no cluster needed) do the work that can be done, and the evidence says
  exactly which validators did not run.
- **A risk model that weights production and blast radius** — findings are
  scored by environment × blast radius × exploitability and can only ever
  be **escalated**, never demoted, so a mis-inferred environment can't
  hide a real finding.
- **Safe, deterministic remediation** — privileged/hostNetwork/hostPID/
  capabilities/root/resource limits, backend encryption, provider pinning.
  Ambiguous IAM and network policy is always escalated to a human. So is
  **every CRITICAL finding**, even ones the platform could fix
  mechanically.
- **Drift detection** — desired (repository) vs actual (live) state,
  reporting drift, unmanaged resources and security-relevant differences,
  producing a plan for a human. It never reconciles.
- **A read-only-by-construction cloud adapter architecture** — the
  contract has no create/update/delete verb at all, and every call passes
  an explicit read-only allowlist. AWS is fully implemented via boto3 with
  an injectable client factory; Azure/GCP/OCI ship no adapter rather than
  stubs, and report `NOT_IMPLEMENTED` with a reason.

**Sandbox limitations, stated plainly**: the `terraform`, `helm` and
`kubectl` binaries cannot be installed here (their download hosts are
unreachable through the egress proxy), and there are no cloud credentials
or reachable cloud endpoints. Two traps found and handled rather than
inherited: `checkov --framework helm` reports **0 findings and exit code
0** when the `helm` binary is missing (so this platform checks for the
binary first and reports BLOCKED); and this sandbox exports its **egress
proxy's** credentials as `AWS_ACCESS_KEY_ID`, which boto3 happily
resolves — so the AWS adapter proves authentication with a real
`sts:GetCallerIdentity` round-trip instead of trusting credential
presence. See ARCHITECTURE.md §26.

**No live infrastructure is ever touched.** Phase 5 edits repository files
only. `terraform apply`, production IAM/network changes and credential
rotation are REQUIRE_APPROVAL; live resource deletion is DENY. This
platform has never contacted a real cloud account, and nothing in it
claims Kubernetes or cloud functionality is production-ready.

## What's actually implemented here (Phase 6 — CI/CD & Deployment Intelligence)

- **Provider-agnostic CI abstraction, one real provider** — GitHub
  Actions, built entirely on the EXISTING `github/client.py` transport-
  injection pattern (no second HTTP client). GitLab CI/Jenkins/generic are
  architecturally supported (`cicd/providers/registry.py`) and
  deliberately not stubbed.
- **Real, no-network pipeline discovery** — `.github/workflows/*.yml`
  parsed with `yaml.safe_load` into a normalized model: build/test/
  security/artifact/deploy/approval/rollback jobs, triggers, `needs`
  graphs, and GitHub `environment:` approval gates. Works even when the
  live Actions API doesn't (see below).
- **CI failure classification** — code/dependency/build/CI-configuration/
  infrastructure/deployment/health/network/external-service/flaky/unknown,
  each driving a different next action; code/test/build/dependency/flaky
  failures are routed into the EXISTING Phase 2 fix-verify-push loop,
  everything else is escalated rather than blindly retried.
- **Build artifacts that are never "deployable" by default** — a real
  `sha256` content digest for identity, unsigned-and-says-so provenance, a
  real CycloneDX SBOM for Python dependencies, and `is_deployable` is only
  `True` once both the security-scan and test gates are recorded PASSED.
- **An explicit release-gate engine** — SOURCE/DEPENDENCIES/SECURITY/
  INFRASTRUCTURE/CI/ARTIFACT/APPROVAL/DEPLOYMENT, each defaulting to
  `NOT_RUN` (never counted as passing) until a real result is supplied.
- **A deployment abstraction with one fully-implemented provider** — a
  real, deterministic, disk-backed local fixture (`LOCAL_FIXTURE`, never
  claimed as live) plus a fully-architected Kubernetes provider that
  honestly reports `UNAVAILABLE` in this sandbox (no `kubectl`, no
  cluster). `deploy → observe → verify → decide` is enforced structurally:
  a deployment is never `VERIFIED` without a separate, real
  `provider.verify()` call actually passing.
- **Policy-gated rollback** — CRITICAL rollout/health failures are
  rollback-eligible; a security-gate failure blocks the deployment instead
  (rollback doesn't fix a bad finding); an unrecognized failure requires
  approval. Production deployment/rollback is `REQUIRE_APPROVAL`; a
  narrowly-scoped `deployment.emergency_rollback` policy action is the one
  explicit automatic-rollback-in-production carve-out.
- **Durable, restart-surviving evidence** — every deployment attempt
  (gates, approval, rollout/verification/rollback status, final state) is
  written to the EXISTING `StateStore` and read back via
  `aep deploy-status`.

**Sandbox limitations, stated plainly**: `api.github.com/.../actions/runs`
returns `403` through this sandbox's egress proxy (live GitHub Actions is
BLOCKED); there is no `kubectl` binary and no cluster (live Kubernetes is
UNAVAILABLE); the Docker daemon is not running here either. Every one of
these is reported as exactly that — BLOCKED/UNAVAILABLE — nowhere in Phase
6 is a live deployment or live CI run claimed to have happened. See
ARCHITECTURE.md §27.

### Check platform status

```bash
aep status --project myproject      # human-readable: phase progress bars, current work, deployability
aep progress --project myproject    # same, with full per-capability detail
aep status --json                   # machine-readable, for a dashboard or the future autonomous supervisor
aep verify-phase --phase 1 --by "you"   # promote a COMPLETE phase to VERIFIED (refuses otherwise)

# Phase 4 - live security posture (opt-in, needs gitleaks/semgrep/checkov installed)
aep security-status --repo /path/to/target/repo
aep status --security-repo /path/to/target/repo   # folds posture into the platform-wide status payload
aep security-suppress --project myproject --finding-id <id> \
    --justification "test fixture, not a real credential" --reviewer you --evidence "manual review"
aep security-suppressions --project myproject     # every suppression ever recorded, incl. revoked/expired

# Phase 5 - infrastructure intelligence
aep infra-inventory --repo /path/to/repo          # read-only discovery only, no scanners needed
aep infra-status --repo /path/to/repo             # inventory + scanners + risk-ranked findings + posture
aep status --infra-repo /path/to/repo             # fold infrastructure into the platform-wide status
aep cloud-status --provider aws                   # adapter status; add --discover for READ-ONLY discovery

# Phase 6 - CI/CD & deployment intelligence
aep ci-status --repo /path/to/repo                # static, no-network CI/CD pipeline discovery
aep status --cicd-repo /path/to/repo              # fold pipeline discovery into the platform-wide status
aep deploy-status --project myproject             # every deployment attempt ever recorded, from durable evidence
```

`aep status`/`aep progress` re-run the real test suite every time they're
called (so the number is never stale or invented) — this currently takes
roughly a minute, dominated by the real network-backed dependency-scanning
and GitHub-loop tests. See ARCHITECTURE.md §24 for the trade-off.

(`aep status --project X` meant "list that project's tasks" before Phase
3; that's now `aep tasks --project X` — see ARCHITECTURE.md §24.)

## Repository layout

See ARCHITECTURE.md §20 for the full tree with descriptions. Tests live in
`tests/`; `tests/test_end_to_end_demo.py` (Phase 1) and
`tests/test_github_ci_loop.py` (Phase 2) are the two worth reading first —
both exercise a real git repo end-to-end, including runs where a detected
secret or a failing CI check correctly blocks/redirects the task graph.

## Security notes

- `config/` is a hard-denied filesystem path for every agent — no agent can
  ever rewrite its own policy file.
- `shell.run` only accepts an explicit allowlist of binaries
  (`pytest`, `python3`, `git`, `pip-audit`/`npm` added in Phase 3, and
  `gitleaks`/`semgrep`/`checkov` added in Phase 4) with argument lists
  (never a shell string). `trivy` is deliberately NOT allowlisted — it's
  BLOCKED in this sandbox and this platform never invokes a binary it has
  already determined is unavailable. Phase 5 adds no new binaries: its
  Terraform, Helm and Kubernetes-schema analysis all run in-process.
- **Infrastructure config is treated as untrusted input** (Phase 5) —
  neither infra agent calls an AI provider (so a malicious manifest has no
  prompt to inject into), no `infra/` module imports `subprocess` or uses
  `shell=True`, YAML is always `safe_load`ed, nothing `eval`s or unpickles
  configuration, and policy action strings are fixed literals so a crafted
  resource name can't forge a different policy decision.
- **Cloud access is read-only by construction** (Phase 5) — the adapter
  contract contains no create/update/delete verb, and every API call
  passes an explicit read-only allowlist that also rejects credential-
  minting operations like `get_session_token` and `get_secret_value`.
- **A detected secret's raw value is never printed, logged, or persisted
  anywhere** (Phase 4) — every scanner/remediation code path that touches
  a raw credential value only ever derives a redacted preview or a
  structural fact about it (e.g. "looks like a real credential, flag for
  rotation"), enforced by an assertion at plan-construction time, not just
  convention. `SecurityAgent`'s policy-action strings are always fixed
  literals, never built from scanner output or repository content, so
  neither can forge a different policy decision — see ARCHITECTURE.md
  §25's threat-modeling section.
- `git.push`/`git.branch`/`github.push` to `main`/`master` is an
  unconditional policy `DENY`; the only path to `main` is a human-reviewed
  PR merge. Force-pushing requires explicit human approval regardless of
  branch.
- The GitHub token is resolved per-call from a `SecretManager`
  (`AEP_SECRET_GITHUB_TOKEN` by default) — never stored in a Task, a
  ProjectConfig, or a YAML file — and is pushed to git via a short-lived
  `GIT_ASKPASS` helper rather than a URL, so it never appears in argv/`ps`.
- Every tool call and policy decision is written to an append-only event
  log with secrets redacted before persistence; GitHub-specific secret
  shapes (`ghp_...`, `github_pat_...`, credential-embedded URLs) are in the
  redaction pattern list alongside AWS/Slack/generic-assignment patterns.
- **CI output and workflow files are treated as untrusted input** (Phase
  6) — workflow YAML is always `safe_load`ed and never executed; job/step
  names and log text are only ever read as plain strings for
  classification, never interpolated into a command or a policy-action
  string; the only module that shells out for a real deployment
  (`deployment/kubernetes_provider.py`) builds its argv as a fixed list,
  never a string built from repository/CI content.
- **Deployment policy cannot be overridden by a workflow file or a model**
  (Phase 6) — `deployment.deploy`/`deployment.rollback`/
  `deployment.emergency_rollback` are fixed action-string literals
  evaluated by the EXISTING `PolicyEngine`; production deployment and
  rollback are `REQUIRE_APPROVAL`, infrastructure destroy stays `DENY`
  from Phase 5, and nothing in Phase 6 weakens those rules.

## Next steps

The roadmap is data, not prose (Phase 3 Part G) — see
[`config/roadmap.yaml`](./config/roadmap.yaml) for the current 9-phase
breakdown with per-capability detail, or run `aep progress` for the live,
computed view. In short: Phases 4 (Security Intelligence), 5
(Infrastructure Intelligence) and 6 (CI/CD & Deployment Intelligence) are
real and largely complete, but none can ever read fully `COMPLETE` in this
sandbox — container scanning, Helm rendering, the Terraform CLI, live
cloud verification, live GitHub Actions, and live Kubernetes are all
genuinely `blocked`/`UNAVAILABLE` here (see ARCHITECTURE.md §25–§27).
Those are honest environment constraints, not missing work. Next up:
Phase 7 (runtime observability — metrics/log ingestion, incident
correlation back to the task/PR/commit that caused it), Phase 8 (a real
worker-pool/supervisor for 24/7 operation), Phase 9 (cross-project
learning, predictive remediation).
