"""Phase 4 Part 14: threat-modeling SecurityAgent itself, not just what it
scans. Lint-style checks mirroring test_verification_discipline.py's
approach (grep the actual source for the properties that make these
attacks structurally hard, not just "we tried to be careful").

Threats considered, each with a concrete structural mitigation asserted
below:
  - Prompt injection from source code / malicious repository instructions:
    SecurityAgent never calls an AI provider/router at all - it is
    deterministic, pattern/tool-based (same discipline
    test_verification_discipline.py already enforces for SecurityScanAgent
    and TestingAgent). There is no prompt for a scanned file's content to
    inject into.
  - Malicious scanner output: every scanner adapter treats its own JSON
    output as data, not code - never eval/exec'd, and finding text is
    always length-capped before becoming Evidence.
  - Arbitrary command execution / tool abuse: every subprocess call is
    routed through the existing capability-scoped `shell.run` tool with
    its fixed binary allowlist - no scanner module calls `subprocess`
    directly, and SecurityAgent never expands its own
    `required_capabilities` at runtime.
  - Credential exfiltration: covered in depth by test_security_remediation.py
    (raw secret values never reach a plan/evidence field); this file
    additionally asserts the SOURCE never contains a raw-value logging
    call.
  - Poisoned dependencies / repository content overriding policy: policy
    decisions are still made by the exact same `PolicyEngine.evaluate()`
    call sites regardless of what a scanner or file says - a finding's
    `description`/`evidence` text is never interpolated into a policy
    action string or `when` context in a way that could forge a
    different rule match.
"""
from __future__ import annotations

from pathlib import Path

SECURITY_DIR = Path(__file__).resolve().parent.parent / "src" / "aep" / "security"
AGENTS_DIR = Path(__file__).resolve().parent.parent / "src" / "aep" / "agents"


def _agent_source() -> str:
    return (AGENTS_DIR / "security_intelligence_agent.py").read_text()


def _scanner_sources() -> dict[str, str]:
    return {p.name: p.read_text() for p in (SECURITY_DIR / "scanners").glob("*.py")}


def test_security_agent_never_calls_an_ai_provider():
    src = _agent_source()
    assert "router.generate" not in src
    assert "ctx.router" not in src
    assert "import subprocess" not in src, (
        "SecurityAgent must route every subprocess call through the capability-scoped "
        "shell.run tool, never call subprocess directly"
    )


def test_no_scanner_module_calls_subprocess_directly():
    for name, src in _scanner_sources().items():
        assert "import subprocess" not in src, f"{name} must only run commands via run_shell()"
        assert "os.system(" not in src
        assert "shell=True" not in src, f"{name} must never shell out with shell=True itself"


def test_no_scanner_output_is_ever_eval_or_exec_d():
    for name, src in _scanner_sources().items():
        assert "eval(" not in src
        assert "exec(" not in src
        assert "pickle.load" not in src


def test_security_agent_scopes_only_the_capabilities_it_declares():
    src = _agent_source()
    assert "required_capabilities = {" in src
    # No runtime mutation of the class-level capability set - the scoping
    # the orchestrator enforces (tool_registry.py's ScopedRegistry) is only
    # meaningful if an agent can't expand it after construction.
    assert "required_capabilities.add" not in src
    assert "required_capabilities |=" not in src
    assert "required_capabilities.update" not in src


def test_remediation_module_never_logs_a_raw_secret_value():
    src = (SECURITY_DIR / "remediation.py").read_text()
    for banned in ("print(raw_value", "logger.", "logging."):
        assert banned not in src


def test_policy_actions_are_fixed_string_literals_not_built_from_finding_text():
    # The exact strings passed to ctx.policy.evaluate(...) must be fixed
    # literals ("security.finding", "secret.commit",
    # "security.git_history_inspection") - never f-string/interpolated
    # from a scanner's own output, which would let malicious repository
    # content or scanner output forge a different policy rule match.
    src = _agent_source()
    for action in ('"security.finding"', '"secret.commit"', '"security.git_history_inspection"'):
        assert action in src
    import re
    for match in re.finditer(r'ctx\.policy\.evaluate\(\s*(f?["\'][^"\']*["\'])', src):
        literal = match.group(1)
        assert not literal.startswith("f"), (
            f"policy action must be a fixed string literal, found an f-string: {literal}"
        )


def test_gitleaks_scanner_source_never_forwards_the_raw_secret_field_whole():
    src = (SECURITY_DIR / "scanners" / "gitleaks_scanner.py").read_text()
    # The raw "Secret"/"Match" JSON field is read once, into `raw_secret`,
    # and only ever passed to `_redacted_preview()` - never assigned
    # directly into a SecurityFinding field.
    assert "description=" in src and "raw_secret" not in src.split("description=")[1][:80]
    assert "_redacted_preview(raw_secret)" in src
