"""Stage B Part 16: cross-checks `known_capabilities.REAL_TOOL_CAPABILITIES`
(a literal enumeration, kept that way so self-validation has zero network/
DB dependency - see that module's docstring) against a live-wired
`ToolRegistry` built the exact same way `bootstrap.build_tool_registry`
builds one for the real orchestrator, so the enumeration cannot silently
drift from what the platform actually registers."""
from __future__ import annotations

from aep.bootstrap import build_tool_registry
from aep.skills.known_capabilities import REAL_TOOL_CAPABILITIES


def test_known_tool_capabilities_are_a_subset_of_the_live_registry_without_github_or_store():
    """`build_tool_registry()` with no store/github enables git/filesystem/
    shell only - a strict subset check here (not equality) because
    github/deployment/operations tools are conditionally registered."""
    registry = build_tool_registry(enable_github=False, store=None)
    live = registry.all_capabilities()
    base_capabilities = {c for c in REAL_TOOL_CAPABILITIES
                          if c.split(".")[0] in ("git", "filesystem", "shell")}
    assert base_capabilities <= live, base_capabilities - live


def test_known_tool_capabilities_include_github_capabilities_when_github_enabled():
    from aep.secrets import EnvSecretManager
    import os
    os.environ.setdefault("GITHUB_TOKEN", "test-token-not-real")
    registry = build_tool_registry(enable_github=True, github_secret_manager=EnvSecretManager(), store=None)
    live = registry.all_capabilities()
    github_capabilities = {c for c in REAL_TOOL_CAPABILITIES if c.startswith("github.")}
    assert github_capabilities <= live, github_capabilities - live


def test_recon_and_test_run_are_real_policy_actions_not_tool_registry_capabilities():
    """`recon.inspect`/`test.run` are real POLICY action names
    (config/policy.yaml's allow bucket), not ToolRegistry capability
    strings - deliberately NOT in `REAL_TOOL_CAPABILITIES` (that set is
    tool-capability strings only). Confirmed here so the distinction is
    honest and tested, not just asserted in a docstring."""
    from aep.skills.known_capabilities import real_policy_actions
    actions = real_policy_actions("config/policy.yaml")
    assert "recon.inspect" in actions
    assert "test.run" in actions
    from aep.skills.known_capabilities import REAL_TOOL_CAPABILITIES
    assert "recon.inspect" not in REAL_TOOL_CAPABILITIES
    assert "test.run" not in REAL_TOOL_CAPABILITIES
