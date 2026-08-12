import subprocess
from pathlib import Path

import pytest

from aep.events import EventLogger
from aep.github.client import HttpResponse
from aep.secrets import StaticSecretManager
from aep.state_store import StateStore
from aep.tool_registry import ToolRegistry
from aep.tools.github_tool import ALL_CAPABILITIES, build_github_tool


def _fake_transport_factory(response: HttpResponse):
    def transport(method, url, headers, params, json_body, timeout):
        return response
    return transport


def test_read_capability_round_trips_through_client(tmp_path):
    secret_manager = StaticSecretManager({"github_token": "test-token"})
    transport = _fake_transport_factory(HttpResponse(200, {"full_name": "acme/widgets"}))
    tool = build_github_tool(secret_manager, transport=transport)

    registry = ToolRegistry()
    registry.register(tool)
    store = StateStore(str(tmp_path / "s.db"))
    scoped = registry.scoped_for({"github.get_repo"}, actor="recon", project_id="p1",
                                  logger=EventLogger(store))
    result = scoped.call("github.get_repo", task_id="t1", owner="acme", repo="widgets")
    assert result == {"ok": True, "data": {"full_name": "acme/widgets"}}
    store.close()


def test_all_declared_capabilities_are_handled():
    """Every capability the Tool advertises must have a routing branch in
    the handler - guards against adding a capability to ALL_CAPABILITIES
    (and therefore to some agent's required_capabilities) without actually
    wiring it, which would only surface at runtime as a confusing
    ValueError deep inside a task run."""
    import inspect

    from aep.tools import github_tool as github_tool_module

    source = inspect.getsource(github_tool_module._build_handler)
    for cap in ALL_CAPABILITIES:
        assert f'"{cap}"' in source, f"capability {cap} is declared but not routed in the handler"


def test_push_branch_to_local_remote_never_leaks_token(tmp_path):
    """push_branch with an explicit remote_url (the local-fixture path) must
    not touch the secret manager at all - and even so, we verify no token
    substring from the manager ever appears in the tool's result."""
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)

    local = tmp_path / "local"
    local.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(local)], check=True)
    subprocess.run(["git", "-C", str(local), "config", "user.email", "a@b.com"], check=True)
    subprocess.run(["git", "-C", str(local), "config", "user.name", "aep"], check=True)
    (local / "f.txt").write_text("hello\n")
    subprocess.run(["git", "-C", str(local), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(local), "commit", "-q", "-m", "init"], check=True)
    subprocess.run(["git", "-C", str(local), "checkout", "-q", "-b", "feature"], check=True)

    secret_manager = StaticSecretManager({"github_token": "SHOULD-NEVER-APPEAR"})
    tool = build_github_tool(secret_manager, transport=lambda *a, **k: HttpResponse(200, {}))
    registry = ToolRegistry()
    registry.register(tool)
    scoped = registry.scoped_for({"github.push_branch"}, actor="push_agent", project_id="p1")

    result = scoped.call("github.push_branch", repo_path=str(local), branch_name="feature",
                          remote_url=str(remote))
    assert result["ok"] is True
    assert "SHOULD-NEVER-APPEAR" not in result["stdout"]
    assert "SHOULD-NEVER-APPEAR" not in result["stderr"]

    # And the push actually happened for real.
    branches = subprocess.run(["git", "-C", str(remote), "branch"], capture_output=True, text=True).stdout
    assert "feature" in branches


def test_push_branch_constructs_authenticated_url_when_no_remote_override(tmp_path, monkeypatch):
    """Without remote_url, push_branch must resolve the token via the
    SecretManager and never place it in argv - verified by capturing the
    subprocess.run call."""
    import aep.tools.github_tool as github_tool_module

    captured = {}
    real_run = subprocess.run

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["env"] = kwargs.get("env", {})
        # Don't actually try to reach github.com - just report failure cleanly.
        class FakeProc:
            returncode = 1
            stdout = ""
            stderr = "could not resolve host (expected: no real network in this test)"
        return FakeProc()

    monkeypatch.setattr(github_tool_module.subprocess, "run", fake_run)

    secret_manager = StaticSecretManager({"github_token": "REAL-TOKEN-VALUE"})
    tool = build_github_tool(secret_manager, transport=lambda *a, **k: HttpResponse(200, {}))
    registry = ToolRegistry()
    registry.register(tool)
    scoped = registry.scoped_for({"github.push_branch"}, actor="push_agent", project_id="p1")

    result = scoped.call("github.push_branch", repo_path="/tmp/whatever",
                          branch_name="aep/fix-1", owner="acme", repo="widgets")

    # Token must never appear in the constructed argv...
    assert not any("REAL-TOKEN-VALUE" in a for a in captured["args"])
    # ...it must be passed via a short-lived subprocess environment instead.
    assert captured["env"].get("AEP_GIT_ASKPASS_TOKEN") == "REAL-TOKEN-VALUE"
    assert "GIT_ASKPASS" in captured["env"]
    # And the result the caller/event-log sees never contains it either.
    assert "REAL-TOKEN-VALUE" not in str(result)
