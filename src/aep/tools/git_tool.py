"""Real git operations against a local working-tree repo.

This is Phase 1's git integration: it operates on an actual repository on
disk via `git` subprocess calls (no mocked git behavior). A `GitHostAdapter`
(specified in ARCHITECTURE.md §15) would layer PR create/update/list for a
real host (GitHub/GitLab) on top of this without changing CodeAgent.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from ..models import RiskLevel
from ..tool_registry import Tool


class GitCommandError(RuntimeError):
    pass


def _run(repo_path: str, args: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(
        ["git", "-C", repo_path, *args],
        capture_output=True, text=True, timeout=30,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _handler(capability: str, **kwargs) -> dict:
    repo_path = kwargs["repo_path"]
    if capability == "git.branch":
        branch_name = kwargs["branch_name"]
        code, out, err = _run(repo_path, ["checkout", "-b", branch_name])
        if code != 0:
            # branch may already exist; try plain checkout
            code, out, err = _run(repo_path, ["checkout", branch_name])
        return {"ok": code == 0, "stdout": out, "stderr": err, "branch": branch_name}

    if capability == "git.current_branch":
        code, out, err = _run(repo_path, ["rev-parse", "--abbrev-ref", "HEAD"])
        return {"ok": code == 0, "branch": out.strip(), "stderr": err}

    if capability == "git.commit":
        message = kwargs["message"]
        _run(repo_path, ["add", "-A"])
        code, out, err = _run(repo_path, ["commit", "-m", message])
        return {"ok": code == 0, "stdout": out, "stderr": err}

    if capability == "git.diff":
        code, out, err = _run(repo_path, ["diff", "HEAD~1" if kwargs.get("against_last") else "--cached"])
        return {"ok": code == 0, "diff": out, "stderr": err}

    if capability == "git.push_local":
        # Pushes to a local bare "remote" directory to simulate a push
        # without requiring network/credentials. Policy (git.push, branch=X)
        # must be evaluated by the caller BEFORE this is invoked.
        remote_path = kwargs["remote_path"]
        branch_name = kwargs["branch_name"]
        code, out, err = _run(repo_path, ["push", remote_path, branch_name])
        return {"ok": code == 0, "stdout": out, "stderr": err}

    if capability == "git.log":
        code, out, err = _run(repo_path, ["log", "--oneline", "-n", str(kwargs.get("n", 5))])
        return {"ok": code == 0, "log": out, "stderr": err}

    raise ValueError(f"unsupported capability for git tool: {capability}")


def build_git_tool() -> Tool:
    return Tool(
        name="git",
        capabilities={
            "git.branch", "git.current_branch", "git.commit",
            "git.diff", "git.push_local", "git.log",
        },
        risk=RiskLevel.MEDIUM,
        description="Real git operations (branch/commit/diff/local-push) against a local repo path.",
        handler=_handler,
    )
