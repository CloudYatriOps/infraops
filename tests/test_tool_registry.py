import pytest

from aep.events import EventLogger
from aep.models import RiskLevel
from aep.state_store import StateStore
from aep.tool_registry import PermissionError as ToolPermissionError
from aep.tool_registry import Tool, ToolRegistry


def _dummy_tool(name="dummy", caps=None) -> Tool:
    caps = caps or {f"{name}.read"}
    return Tool(name=name, capabilities=caps, risk=RiskLevel.LOW,
                description="test tool", handler=lambda cap, **kw: {"ok": True, "cap": cap})


def test_register_and_call(tmp_path):
    registry = ToolRegistry()
    registry.register(_dummy_tool())
    store = StateStore(str(tmp_path / "s.db"))
    logger = EventLogger(store)

    scoped = registry.scoped_for({"dummy.read"}, actor="agent-x", project_id="p1", logger=logger)
    result = scoped.call("dummy.read", task_id="t1")
    assert result == {"ok": True, "cap": "dummy.read"}

    events = store.query_events(project_id="p1", task_id="t1")
    assert events[0].action == "tool_call"
    assert events[0].decision == "EXECUTED"
    store.close()


def test_capability_outside_scope_is_denied_and_logged(tmp_path):
    registry = ToolRegistry()
    registry.register(_dummy_tool(name="git", caps={"git.commit", "git.push_local"}))
    store = StateStore(str(tmp_path / "s.db"))
    logger = EventLogger(store)

    scoped = registry.scoped_for({"git.commit"}, actor="code_agent", project_id="p1", logger=logger)
    with pytest.raises(ToolPermissionError):
        scoped.call("git.push_local", task_id="t1")

    events = store.query_events(project_id="p1", task_id="t1")
    assert events[0].action == "tool_call_denied"
    assert events[0].decision == "DENY"
    store.close()


def test_duplicate_capability_registration_raises():
    registry = ToolRegistry()
    registry.register(_dummy_tool(name="a", caps={"shared.cap"}))
    with pytest.raises(ValueError):
        registry.register(_dummy_tool(name="b", caps={"shared.cap"}))


def test_scoped_for_rejects_unknown_capability():
    registry = ToolRegistry()
    registry.register(_dummy_tool())
    with pytest.raises(ValueError):
        registry.scoped_for({"nonexistent.cap"}, actor="x", project_id="p1")


def test_secret_redacted_in_tool_call_event(tmp_path):
    registry = ToolRegistry()
    registry.register(_dummy_tool())
    store = StateStore(str(tmp_path / "s.db"))
    logger = EventLogger(store)
    scoped = registry.scoped_for({"dummy.read"}, actor="agent-x", project_id="p1", logger=logger)

    scoped.call("dummy.read", task_id="t1", content="AWS_SECRET_ACCESS_KEY: \"" + "A" * 40 + "\"")

    events = store.query_events(project_id="p1", task_id="t1")
    inputs = events[0].details["inputs"]
    assert "REDACTED" in inputs["content"]
    assert ("A" * 40) not in inputs["content"]
    store.close()
