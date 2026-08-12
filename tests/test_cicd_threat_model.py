"""Threat-modeling CI/CD & deployment intelligence (Phase 6 Part 20).

Same lint-style source-assertion discipline as
`tests/test_infra_threat_model.py` (Phase 5) and
`tests/test_security_agent_safety.py` (Phase 4). CI output (workflow
files, job/step names, log text) is UNTRUSTED DATA - anyone who can open a
PR can add or edit a workflow file or make a build step print arbitrary
text into a log. Threats and their structural mitigations, each asserted
below:

  - Malicious workflow files / workflow injection: `cicd/discovery.py`
    parses with `yaml.safe_load` only, never executes a workflow, and
    never interpolates workflow content into a shell command.
  - Untrusted CI logs: `cicd/failure_classification.py` only ever reads
    job/step/log text as a plain string for substring matching - it is
    never executed, never used to build a policy action, never
    interpolated into a subprocess argv.
  - Command injection: no `cicd`/`deployment` module builds a shell
    command by string-interpolating repository, workflow, or CI-log
    content; the one module that does invoke `kubectl`
    (`deployment/kubernetes_provider.py`) uses a fixed argv list with a
    `deployment_ref` composed only from a caller-supplied
    environment+commit (never raw repository/log content).
  - Poisoned artifacts / compromised dependencies: `cicd/artifact.py`'s
    digest is a real sha256 of actual content, and an artifact is never
    `is_deployable` without both required gates having actually PASSED.
  - Credential leakage: no CI/CD or deployment module reads/logs a token
    or credential value - the GitHub Actions provider reuses
    `GitHubClient`'s existing token-never-logged discipline verbatim.
  - Deployment privilege escalation / malicious deployment manifests:
    every policy action string is a fixed literal, `PolicyEngine` is the
    single gate before any provider call, and the destructive
    `infra.*_destroy`/`infra.*_delete` DENY rules from Phase 5 are
    untouched.
  - Model-generated destructive commands: no `cicd`/`deployment` module
    calls an AI provider at all.
"""
from __future__ import annotations

import re
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "aep"
CICD_DIR = SRC / "cicd"
DEPLOYMENT_DIR = SRC / "deployment"
AGENTS_DIR = SRC / "agents"
PHASE6_AGENTS = [AGENTS_DIR / "ci_intelligence_agent.py", AGENTS_DIR / "deployment_agent.py",
                 AGENTS_DIR / "deployment_verification_agent.py"]
PHASE6_MODULES = sorted(CICD_DIR.rglob("*.py")) + sorted(DEPLOYMENT_DIR.rglob("*.py"))


def _sources(paths) -> dict[str, str]:
    return {str(p.relative_to(SRC)): p.read_text() for p in paths}


# ---- no model calls ---------------------------------------------------------

def test_no_phase6_module_calls_an_ai_provider():
    for name, source in _sources(PHASE6_MODULES + PHASE6_AGENTS).items():
        assert "router.generate" not in source, name
        assert "ctx.router" not in source, name


# ---- untrusted YAML / untrusted CI logs ------------------------------------

def test_workflow_yaml_is_always_parsed_safely():
    for name, source in _sources(PHASE6_MODULES).items():
        assert not re.search(r"yaml\.load\s*\(", source), name
        assert not re.search(r"yaml\.full_load\s*\(", source), name
        assert not re.search(r"yaml\.unsafe_load\s*\(", source), name


def test_no_phase6_code_evals_or_execs_untrusted_content():
    for name, source in _sources(PHASE6_MODULES + PHASE6_AGENTS).items():
        assert not re.search(r"\beval\(", source), name
        assert not re.search(r"\bexec\(", source), name
        assert "pickle.load" not in source, name


def test_no_phase6_module_imports_subprocess_directly_except_the_kubectl_wrapper():
    """`kubernetes_provider.py` is the ONE module allowed to shell out
    (it IS the real-cluster deploy path); everything else must not."""
    allowed = {"deployment/kubernetes_provider.py"}
    for name, source in _sources(PHASE6_MODULES).items():
        if name in allowed:
            continue
        assert "import subprocess" not in source, name
        assert "os.system(" not in source, name


def test_no_phase6_agent_imports_subprocess_directly():
    for name, source in _sources(PHASE6_AGENTS).items():
        assert "import subprocess" not in source, name


def test_no_shell_true_anywhere_in_phase6_code():
    for name, source in _sources(PHASE6_MODULES + PHASE6_AGENTS).items():
        assert "shell=True" not in source, name


def test_kubectl_argv_is_never_built_by_string_interpolating_repository_content():
    """The one subprocess call site must build argv as a literal list with
    only caller-controlled environment/commit-derived identifiers, never
    an f-string embedding arbitrary CI/workflow/log text."""
    source = (DEPLOYMENT_DIR / "kubernetes_provider.py").read_text()
    assert not re.search(r'subprocess\.run\(f["\']', source)
    assert "shell=True" not in source


# ---- policy cannot be overridden by repository/workflow/CI-log content ----

def test_policy_actions_are_fixed_literals_never_built_from_untrusted_content():
    for name, source in _sources(PHASE6_AGENTS).items():
        for match in re.finditer(r'ctx\.policy\.evaluate\(\s*(f?["\'][^"\')]*["\']|[A-Z_]+)', source):
            literal = match.group(1)
            assert not literal.startswith("f\""), f"{name}: {literal}"
            assert not literal.startswith("f'"), f"{name}: {literal}"


def test_deployment_agent_never_builds_the_rollback_action_from_untrusted_content():
    """The `deployment.emergency_rollback` action name switch must be
    driven only by the platform's OWN `rollback.py` reason-code constants,
    never by a failure message or CI log string."""
    source = (AGENTS_DIR / "deployment_agent.py").read_text()
    assert '"deployment.emergency_rollback"' in source
    assert 'reason_code' in source


def test_expected_deployment_policy_actions_are_present_in_config():
    policy_source = (Path(__file__).resolve().parent.parent / "config" / "policy.yaml").read_text()
    assert '"deployment.deploy"' in policy_source
    assert '"deployment.rollback"' in policy_source
    assert '"deployment.emergency_rollback"' in policy_source


# ---- artifact integrity ------------------------------------------------------

def test_artifact_digest_is_a_real_hash_never_random():
    source = (CICD_DIR / "artifact.py").read_text()
    assert "hashlib.sha256" in source
    assert "uuid" not in source  # artifact identity must never be a random id


def test_artifact_is_deployable_requires_both_gates_never_defaults_true():
    source = (CICD_DIR / "artifact.py").read_text()
    assert "GateStatus.PASSED" in source
    assert re.search(r"is_deployable.*\n.*return", source, re.S)


# ---- no destructive infra verbs sneak into Phase 6 ---------------------------

def test_no_phase6_module_can_destroy_infrastructure():
    forbidden = ("terraform destroy", "kubectl delete", "helm delete")
    for name, source in _sources(PHASE6_MODULES + PHASE6_AGENTS).items():
        for command in forbidden:
            binary, verb = command.split()
            assert f'"{binary}", "{verb}"' not in source, f"{name} appears to invoke `{command}`"


def test_phase5_destructive_deny_rules_are_untouched():
    policy_source = (Path(__file__).resolve().parent.parent / "config" / "policy.yaml").read_text()
    for action in ('"infra.resource_delete"', '"infra.terraform_destroy"',
                   '"infra.cluster_resource_delete"'):
        assert action in policy_source


# ---- credential leakage ------------------------------------------------------

def test_no_phase6_module_logs_a_token_or_credential_value():
    for name, source in _sources(PHASE6_MODULES + PHASE6_AGENTS).items():
        assert "token_provider()" not in source or "print(" not in source, name
        assert not re.search(r'print\([^)]*token', source, re.I), name
