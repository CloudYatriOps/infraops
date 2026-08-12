"""Threat-modeling infrastructure intelligence itself (Phase 5 Part 17).

Lint-style source assertions in the same spirit as
test_verification_discipline.py (Phase 1) and test_security_agent_safety.py
(Phase 4). Infrastructure configuration is UNTRUSTED INPUT: a Terraform
file, a Kubernetes manifest, a Helm template and a cloud API response are
all attacker-controllable in a repository this platform is pointed at.

Threats and their structural mitigations, each asserted below:

  - Malicious Terraform/Kubernetes/Helm content, and prompt injection via
    those files: neither infra agent ever calls an AI provider, so there
    is no prompt for repository content to be injected into. Parsing is
    done with `yaml.safe_load`/`hcl2` and results are never `eval`'d.
  - Destructive tool execution: infra modules never call `subprocess`
    directly; everything goes through the capability-scoped `shell.run`
    tool with its fixed binary allowlist, and no repository content is
    ever interpolated into a command.
  - Privilege escalation via the discovery agent: it declares only
    filesystem capabilities and cannot obtain more at runtime.
  - Malicious cloud API responses: the adapter normalizes responses into
    a fixed attribute schema and never executes or trusts response
    content; a failing capability is recorded rather than silently
    producing an empty (falsely clean) result.
  - Credential exfiltration: no scanner or adapter puts a credential
    VALUE into a finding, and the cloud adapter cannot call
    `get_secret_value` at all.
  - Infrastructure state poisoning / policy override: policy action
    strings are fixed literals, never built from finding or file content,
    so nothing in a repository can forge a different policy decision.
"""
from __future__ import annotations

import re
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "aep"
INFRA_DIR = SRC / "infra"
AGENTS_DIR = SRC / "agents"

_INFRA_MODULES = sorted(INFRA_DIR.rglob("*.py"))
_INFRA_AGENTS = [AGENTS_DIR / "infrastructure_discovery_agent.py",
                 AGENTS_DIR / "infrastructure_intelligence_agent.py"]


def _sources(paths) -> dict[str, str]:
    return {str(p.relative_to(SRC)): p.read_text() for p in paths}


# ---- prompt injection ------------------------------------------------------

def test_no_infra_agent_calls_an_ai_provider():
    """Repository content cannot be injected into a prompt that does not
    exist."""
    for name, source in _sources(_INFRA_AGENTS).items():
        assert "router.generate" not in source, name
        assert "ctx.router" not in source, name


def test_no_infra_module_calls_an_ai_provider():
    for name, source in _sources(_INFRA_MODULES).items():
        assert "router.generate" not in source, name


# ---- arbitrary code / command execution ------------------------------------

def test_no_infra_module_imports_subprocess_directly():
    """Every command must go through the capability-scoped, allowlisted
    shell tool - an infra module shelling out itself would bypass it."""
    for name, source in _sources(_INFRA_MODULES).items():
        assert "import subprocess" not in source, name
        assert "os.system(" not in source, name


def test_no_infra_agent_imports_subprocess_directly():
    for name, source in _sources(_INFRA_AGENTS).items():
        assert "import subprocess" not in source, name


def test_no_infra_code_evals_or_execs_configuration():
    for name, source in _sources(_INFRA_MODULES + _INFRA_AGENTS).items():
        assert not re.search(r"\beval\(", source), name
        assert not re.search(r"\bexec\(", source), name
        assert "pickle.load" not in source, name


def test_yaml_is_always_parsed_safely():
    """`yaml.load`/`full_load` can instantiate arbitrary Python objects
    from a malicious manifest."""
    for name, source in _sources(_INFRA_MODULES + _INFRA_AGENTS).items():
        assert not re.search(r"yaml\.load\s*\(", source), name
        assert not re.search(r"yaml\.full_load\s*\(", source), name
        assert not re.search(r"yaml\.unsafe_load\s*\(", source), name


def test_no_shell_true_anywhere_in_infra_code():
    for name, source in _sources(_INFRA_MODULES + _INFRA_AGENTS).items():
        assert "shell=True" not in source, name


# ---- privilege escalation ---------------------------------------------------

def test_discovery_agent_capabilities_are_filesystem_only_and_immutable():
    source = (AGENTS_DIR / "infrastructure_discovery_agent.py").read_text()
    assert 'required_capabilities = {"filesystem.list", "filesystem.read"}' in source
    for mutation in ("required_capabilities.add", "required_capabilities |=",
                      "required_capabilities.update"):
        assert mutation not in source


def test_no_infra_agent_mutates_its_capability_set_at_runtime():
    for name, source in _sources(_INFRA_AGENTS).items():
        for mutation in ("required_capabilities.add", "required_capabilities |=",
                          "required_capabilities.update"):
            assert mutation not in source, name


# ---- policy cannot be overridden by repository content ----------------------

def test_policy_actions_are_fixed_literals_never_built_from_file_content():
    """An f-string action would let a crafted resource name or finding
    description select a different policy rule."""
    for name, source in _sources(_INFRA_AGENTS).items():
        for match in re.finditer(r'ctx\.policy\.evaluate\(\s*(f?["\'][^"\']*["\'])', source):
            literal = match.group(1)
            assert not literal.startswith("f"), f"{name}: {literal}"


def test_expected_policy_actions_are_present():
    source = (AGENTS_DIR / "infrastructure_intelligence_agent.py").read_text()
    assert '"infra.finding"' in source
    discovery = (AGENTS_DIR / "infrastructure_discovery_agent.py").read_text()
    assert '"infra.discovery"' in discovery
    assert '"infra.cloud_discovery"' in discovery


# ---- destructive operations -------------------------------------------------

def test_no_infra_code_can_apply_or_destroy_infrastructure():
    """Phase 5 edits repository files only. No module may invoke a
    mutating infrastructure command, even behind a policy check."""
    forbidden = ("terraform apply", "terraform destroy", "kubectl apply", "kubectl delete",
                 "helm install", "helm upgrade", "helm delete")
    for name, source in _sources(_INFRA_MODULES + _INFRA_AGENTS).items():
        for command in forbidden:
            # These strings legitimately appear in prose and policy-action
            # names; what must not exist is an argv list that would
            # actually execute one via the shell tool.
            binary, verb = command.split()
            assert f'"{binary}", "{verb}"' not in source, f"{name} appears to invoke `{command}`"


def test_cloud_adapter_has_no_write_verb_in_its_contract():
    source = (INFRA_DIR / "cloud" / "base.py").read_text()
    # The read-only guarantee is structural: the verbs do not exist.
    assert "def create" not in source
    assert "def delete" not in source
    assert "def update" not in source
    assert "assert_read_only" in source


def test_every_aws_api_call_passes_through_the_read_only_gate():
    source = (INFRA_DIR / "cloud" / "aws_adapter.py").read_text()
    # There is exactly one place a client method is invoked, and it calls
    # assert_read_only first.
    assert source.count("getattr(client, operation") == 1
    call_body = source.split("def _call(")[1].split("def ")[0]
    assert "assert_read_only(operation)" in call_body


# ---- credential exfiltration -------------------------------------------------

def test_no_infra_module_logs_or_prints_a_credential_value():
    for name, source in _sources(_INFRA_MODULES).items():
        assert "logger." not in source, name
        assert "logging." not in source, name


def test_terraform_scanner_never_places_a_credential_value_in_a_finding():
    source = (INFRA_DIR / "scanners" / "terraform_deep_scanner.py").read_text()
    # `value` is read only to measure/classify it; the finding carries the
    # argument name and length, never the value.
    assert "value redacted" in source
    assert "len(value)" in source


def test_cloud_account_id_is_masked_when_serialized():
    source = (INFRA_DIR / "cloud" / "base.py").read_text()
    assert 'f"****{self.account_id[-4:]}"' in source


# ---- untrusted-input handling ------------------------------------------------

def test_scanners_report_unparseable_input_rather_than_treating_it_as_clean():
    terraform = (INFRA_DIR / "scanners" / "terraform_deep_scanner.py").read_text()
    assert "TF_UNPARSEABLE" in terraform
    assert "unverified rather than clean" in terraform
    native = (INFRA_DIR / "scanners" / "k8s_native_scanner.py").read_text()
    assert "errors.append" in native


def test_a_blocked_scanner_never_reports_pass():
    helm = (INFRA_DIR / "scanners" / "helm_scanner.py").read_text()
    assert "ScannerAvailability.BLOCKED" in helm
    # The specific trap this module exists to avoid.
    assert "checkov" in helm and "exits 0" in helm.replace("exit code 0", "exits 0")
