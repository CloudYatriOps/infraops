"""Pushes the local feature branch to GitHub.

Policy enforcement for this agent is deliberately done through the
orchestrator's existing generic policy gate (Task.payload["policy_action"] /
["policy_context"], see orchestrator.py `_apply_generic_policy_gate` and
ARCHITECTURE.md §8) rather than a hand-rolled check inside the agent: the
planner that builds this task (src/aep/github/planner.py) always sets
policy_action="github.push" with the branch name and force flag in context,
so `config/policy.yaml`'s existing rule shape (deny push to protected
branches, require approval for force-push) is enforced *before* this agent
ever runs - identical mechanism already covered by
tests/test_end_to_end_demo.py::test_direct_push_to_main_is_denied_by_policy_gate.
"""
from __future__ import annotations

from datetime import datetime, timezone

from ..models import Evidence, FailureClass, Task, TaskResult
from .base import Agent, AgentContext


class PushAgent:
    name = "push_agent"
    required_capabilities = {"github.push_branch"}

    def run(self, task: Task, ctx: AgentContext) -> TaskResult:
        repo_path = task.payload["project_root"]
        branch_name = task.payload["branch_name"]
        owner = task.payload.get("owner")
        repo = task.payload.get("repo")
        remote_url = task.payload.get("remote_url")  # test/local-fixture override
        force = bool(task.payload.get("force", False))

        kwargs = {"repo_path": repo_path, "branch_name": branch_name, "force": force}
        if remote_url:
            kwargs["remote_url"] = remote_url
        else:
            kwargs["owner"] = owner
            kwargs["repo"] = repo

        result = ctx.tools.call("github.push_branch", task_id=task.id, **kwargs)

        evidence = Evidence(
            source="github.push", captured_at=datetime.now(timezone.utc).isoformat(),
            exit_code=0 if result["ok"] else 1,
            summary=(result["stdout"] + "\n" + result["stderr"])[-500:],
        )
        return TaskResult(
            success=result["ok"],
            evidence=[evidence],
            message=f"pushed {branch_name}" if result["ok"] else f"push failed for {branch_name}",
            failure_class=None if result["ok"] else FailureClass.TOOL,
        )
