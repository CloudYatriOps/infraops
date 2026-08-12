"""Lint-style check for ARCHITECTURE.md §14 (Verification Philosophy):
every agent must ground its evidence in an actual tool call, and CodeAgent
specifically must never let a model's own claim be the only evidence for a
successful mutation - it must be paired with tool-verified evidence (the
git commit result), not just accepted as true because the model said so.
"""
from pathlib import Path

AGENTS_DIR = Path(__file__).resolve().parent.parent / "src" / "aep" / "agents"


def _source(name: str) -> str:
    return (AGENTS_DIR / name).read_text()


def test_every_agent_calls_a_real_tool():
    for name in ("recon_agent.py", "code_agent.py", "testing_agent.py", "security_agent.py"):
        src = _source(name)
        assert "ctx.tools.call(" in src, f"{name} must ground its behavior in a real tool call"


def test_code_agent_pairs_model_evidence_with_tool_evidence():
    src = _source("code_agent.py")
    assert "model_call" in src, "CodeAgent should record that a model call happened"
    assert "git.commit" in src, "CodeAgent must also record real git evidence, not just the model's claim"
    # The success path must depend on the tool result, not the model result.
    assert "success=commit_result[\"ok\"]" in src.replace("'", '"'), (
        "task success must be driven by the git tool's real result, not the model's text"
    )


def test_testing_agent_never_asks_the_model_if_tests_passed():
    src = _source("testing_agent.py")
    assert "router.generate" not in src, "TestingAgent must not ask a model whether tests passed"
    assert "shell.run" in src


def test_security_agent_is_deterministic_pattern_based():
    src = _source("security_agent.py")
    assert "router.generate" not in src, "secret detection must be deterministic, not model-judged"
    assert "find_secrets" in src
