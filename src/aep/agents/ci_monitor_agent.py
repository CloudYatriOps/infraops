"""Polls GitHub check-runs for a branch until CI resolves, or hands off to
diagnosis when it fails, or gives up (BLOCKED_ON_APPROVAL) after too many
fix attempts.

This agent never asks the model whether CI passed (ARCHITECTURE.md §14):
"pending" / "failing" / "green" is read directly from GitHub's check-runs
API. The retry-until-resolved polling behavior is not a hand-rolled loop -
it's the *existing* FailureClassifier/backoff machinery (ARCHITECTURE.md
§9): returning success=False with failure_class=TRANSIENT makes the
orchestrator re-run this exact task after a backoff, which is exactly
"poll again later." Task.max_attempts controls how many times it will poll
before giving up on a request that never surfaces a check at all.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from ..models import Evidence, FailureClass, Task, TaskResult
from .base import Agent, AgentContext

FAILING_CONCLUSIONS = {"failure", "timed_out", "cancelled", "action_required"}


def _new_id() -> str:
    return str(uuid.uuid4())


class MonitorCIAgent:
    name = "ci_monitor_agent"
    required_capabilities = {"github.list_pull_requests", "github.list_check_runs"}

    def run(self, task: Task, ctx: AgentContext) -> TaskResult:
        owner = task.payload["owner"]
        repo = task.payload["repo"]
        branch_name = task.payload["branch_name"]
        max_ci_loops = task.payload.get("max_ci_loops", 3)
        ci_loop_iteration = task.payload.get("ci_loop_iteration", 0)

        pr_list = ctx.tools.call("github.list_pull_requests", task_id=task.id,
                                  owner=owner, repo=repo, state="open",
                                  head=f"{owner}:{branch_name}")["data"]
        pr_number = pr_list[0]["number"] if pr_list else None

        checks = ctx.tools.call("github.list_check_runs", task_id=task.id,
                                 owner=owner, repo=repo, ref=branch_name)["data"]
        runs = checks.get("check_runs", [])

        incomplete = [r for r in runs if r.get("status") != "completed"]
        failed = [r for r in runs if r.get("status") == "completed"
                  and r.get("conclusion") in FAILING_CONCLUSIONS]

        summary = f"{len(runs)} check(s): " + ", ".join(
            f"{r['name']}={r.get('conclusion') or r.get('status')}" for r in runs
        ) if runs else "no checks reported yet"
        evidence = Evidence(source="github.checks", captured_at=datetime.now(timezone.utc).isoformat(),
                             exit_code=0 if not failed and not incomplete else 1, summary=summary)

        if not runs or incomplete:
            return TaskResult(success=False, evidence=[evidence], failure_class=FailureClass.TRANSIENT,
                               message="CI still pending")

        if not failed:
            return TaskResult(success=True, evidence=[evidence], message="CI green")

        if ci_loop_iteration >= max_ci_loops:
            return TaskResult(
                success=False, evidence=[evidence], failure_class=FailureClass.HUMAN_REQUIRED,
                message=f"CI failing after {ci_loop_iteration} automated fix attempt(s); "
                        f"genuinely blocked, needs a human (failing checks: "
                        f"{[r['name'] for r in failed]})",
            )

        diagnose_task = Task(
            id=_new_id(), type="diagnose_ci_failure", project_id=task.project_id,
            owner_agent="ci_diagnose_agent",
            payload={
                **{k: v for k, v in task.payload.items() if k != "max_ci_loops"},
                "pr_number": pr_number,
                "failed_checks": [
                    {"name": r["name"], "conclusion": r.get("conclusion"),
                     "summary": (r.get("output") or {}).get("summary", ""),
                     "text": (r.get("output") or {}).get("text", "")}
                    for r in failed
                ],
                "ci_loop_iteration": ci_loop_iteration + 1,
                "max_ci_loops": max_ci_loops,
            },
        )
        return TaskResult(
            success=True, evidence=[evidence],
            message=f"CI failing ({[r['name'] for r in failed]}); handing off to diagnosis "
                    f"(attempt {ci_loop_iteration + 1}/{max_ci_loops})",
            follow_up_tasks=[diagnose_task],
        )
