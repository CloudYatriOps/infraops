"""Threat-modeling operations intelligence itself (Phase 7 Part 13/spec
final bullet). Lint-style source assertions, same spirit and same checks
as tests/test_infra_threat_model.py and tests/test_cicd_threat_model.py.

Operational events, logs, and CI/deployment evidence pulled into this
subsystem are UNTRUSTED INPUT: an event's `detail`/`source`/`service`
fields could contain attacker-influenced text (e.g. a crafted log line).

Threats and their structural mitigations, each asserted below:
  - No operations module/agent calls an AI provider - no prompt for
    event/log/evidence content to be injected into.
  - No operations module imports subprocess/os.system or calls eval/exec -
    correlation/RCA/remediation planning is pure data transformation.
  - Every policy action passed to `ctx.policy.evaluate()` /
    `evaluate_with_policy()` is a fixed string literal from the
    remediation catalog, never built from event/incident/log content -
    the exact mechanism that prevents a crafted event from forging a
    different policy decision.
  - No destructive argv (`kubectl delete`, `terraform destroy`, etc.)
    appears anywhere in this subsystem - Phase 7 never applies/destroys
    infrastructure directly.
  - Incident memory (Part 9) is read as ADVISORY evidence only - nothing
    in the agent lets a historical remediation string be executed
    directly without a fresh policy check.
"""
from __future__ import annotations

import re
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "aep"
OPS_DIR = SRC / "operations"
AGENT_FILE = SRC / "agents" / "operations_intelligence_agent.py"
TOOL_FILE = SRC / "tools" / "operations_tool.py"

_OPS_MODULES = sorted(OPS_DIR.rglob("*.py")) + [AGENT_FILE, TOOL_FILE]


def _sources() -> dict[str, str]:
    return {str(p.relative_to(SRC)): p.read_text() for p in _OPS_MODULES}


def test_no_operations_module_calls_an_ai_provider():
    for name, source in _sources().items():
        assert "router.generate" not in source, name
        assert "ctx.router" not in source, name


def test_no_operations_module_imports_subprocess_or_shells_out():
    for name, source in _sources().items():
        assert "import subprocess" not in source, name
        assert "os.system(" not in source, name
        assert "shell=True" not in source, name


def test_no_operations_module_evals_or_execs():
    for name, source in _sources().items():
        assert not re.search(r"\beval\(", source), name
        assert not re.search(r"\bexec\(", source), name
        assert "pickle.load" not in source, name


def test_no_operations_module_uses_unsafe_yaml_loading():
    for name, source in _sources().items():
        assert not re.search(r"yaml\.load\s*\(", source), name
        assert not re.search(r"yaml\.full_load\s*\(", source), name
        assert not re.search(r"yaml\.unsafe_load\s*\(", source), name


def test_policy_actions_passed_to_evaluate_are_fixed_literals():
    """Every `ctx.policy.evaluate(...)` and `evaluate_with_policy(...)`
    call must pass a plain string literal - never an f-string built from
    incident/event/log content, or a crafted event could forge a
    different policy outcome."""
    pattern = re.compile(r'(?:ctx\.policy\.evaluate|evaluate_with_policy)\(\s*(?:policy,\s*)?'
                          r'(f?["\'][^"\']*["\'])')
    for name, source in _sources().items():
        for match in pattern.finditer(source):
            literal = match.group(1)
            assert not literal.startswith("f"), f"{name}: {literal}"


def test_remediation_catalog_actions_are_all_fixed_operations_dot_literals():
    remediation_source = (OPS_DIR / "remediation.py").read_text()
    for action in re.findall(r'"(operations\.[a-z_]+)"', remediation_source):
        assert re.fullmatch(r"operations\.[a-z_]+", action), action


def test_no_destructive_infrastructure_verbs_anywhere_in_operations_code():
    forbidden = ("terraform apply", "terraform destroy", "kubectl apply", "kubectl delete",
                 "helm install", "helm upgrade", "helm delete")
    for name, source in _sources().items():
        for command in forbidden:
            binary, verb = command.split()
            assert f'"{binary}", "{verb}"' not in source, f"{name} appears to invoke `{command}`"


def test_incident_memory_is_read_only_advisory_not_executed():
    agent_source = AGENT_FILE.read_text()
    # The agent only ever reads similar-incident data into evidence text -
    # it never takes the historical `remediation_used` string and calls it
    # as an action/command.
    assert "similar_result" in agent_source
    assert "exec(" not in agent_source
    assert "eval(" not in agent_source


def test_operations_tool_never_exposes_raw_state_store_to_an_agent():
    tool_source = TOOL_FILE.read_text()
    assert "class StateStore" not in tool_source
    agent_source = AGENT_FILE.read_text()
    assert "ctx.store" not in agent_source


def test_no_operations_module_logs_or_prints_credential_values():
    for name, source in _sources().items():
        assert "logger." not in source, name
        assert "logging." not in source, name
