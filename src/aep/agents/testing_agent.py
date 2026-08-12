"""Runs the real test suite via the shell tool and parses the real exit
code/output. Never asks the model whether tests passed (ARCHITECTURE.md
§14 Verification Philosophy)."""
from __future__ import annotations

from datetime import datetime, timezone

from ..models import Evidence, FailureClass, Task, TaskResult
from .base import Agent, AgentContext


class TestingAgent:
    name = "testing_agent"
    required_capabilities = {"shell.run"}

    def run(self, task: Task, ctx: AgentContext) -> TaskResult:
        project_root = task.payload["project_root"]
        test_args = task.payload.get("test_args", ["pytest", "-q"])

        result = ctx.tools.call(
            "shell.run", task_id=task.id,
            args=test_args, cwd=project_root, timeout=60,
        )
        evidence = Evidence(
            source="pytest", captured_at=datetime.now(timezone.utc).isoformat(),
            exit_code=result["exit_code"],
            summary=(result["stdout"] + "\n" + result["stderr"])[-1000:],
        )
        success = result["ok"]
        return TaskResult(
            success=success,
            evidence=[evidence],
            message="tests passed" if success else "tests failed",
            failure_class=None if success else FailureClass.TEST,
        )
