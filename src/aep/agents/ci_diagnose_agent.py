"""Turns a CI failure into a concrete fix attempt.

Real evidence in, model proposal out (ARCHITECTURE.md §0/§14): the failing
check names/output (gathered by MonitorCIAgent) and the workflow run's job
list (fetched here via a real tool call) are the *facts*; the AIProvider
call only proposes a plain-English bug_description for CodeAgent to act on
- it never decides on its own that anything is fixed. Posts a PR comment so
the loop is visible to a human watching the PR, then hands off to a fresh
code_fix -> security_scan -> run_tests -> push -> monitor_ci chain (reusing
the exact same chain-builder the initial plan uses).
"""
from __future__ import annotations

from datetime import datetime, timezone

from ..github.planner import build_fix_verify_push_chain
from ..models import Evidence, Task, TaskResult
from ..providers.base import GenerationRequest
from .base import Agent, AgentContext


class DiagnoseCIFailureAgent:
    name = "ci_diagnose_agent"
    required_capabilities = {"github.list_workflow_runs", "github.list_workflow_run_jobs",
                              "github.comment_on_pr"}

    def run(self, task: Task, ctx: AgentContext) -> TaskResult:
        owner = task.payload["owner"]
        repo = task.payload["repo"]
        branch_name = task.payload["branch_name"]
        project_root = task.payload["project_root"]
        target_file = task.payload["target_file"]
        pr_number = task.payload.get("pr_number")
        failed_checks = task.payload.get("failed_checks", [])
        ci_loop_iteration = task.payload["ci_loop_iteration"]
        max_ci_loops = task.payload["max_ci_loops"]
        base_branch = task.payload.get("base_branch", "main")
        remote_url = task.payload.get("remote_url")

        job_detail_lines: list[str] = []
        runs = ctx.tools.call("github.list_workflow_runs", task_id=task.id,
                               owner=owner, repo=repo, branch=branch_name)["data"]
        workflow_runs = runs.get("workflow_runs", [])
        if workflow_runs:
            latest_run = workflow_runs[0]
            jobs = ctx.tools.call("github.list_workflow_run_jobs", task_id=task.id,
                                   owner=owner, repo=repo, run_id=latest_run["id"])["data"]
            for job in jobs.get("jobs", []):
                if job.get("conclusion") == "failure":
                    failed_steps = [s["name"] for s in job.get("steps", [])
                                    if s.get("conclusion") == "failure"]
                    job_detail_lines.append(f"job '{job['name']}' failed at step(s): {failed_steps}")

        failure_context = "\n".join(
            [f"check '{c['name']}' ({c['conclusion']}): {c['summary']}" for c in failed_checks]
            + job_detail_lines
        ) or "CI reported a failure with no further detail available."

        diagnosis = ctx.router.generate(GenerationRequest(
            task_type="diagnose_ci_failure",
            system_prompt="You are a careful software engineer diagnosing a CI failure. "
                           "Given the failing check/job output below, describe in one sentence "
                           "the specific code change needed to fix it.",
            user_prompt=f"Failing CI output for branch {branch_name}:\n{failure_context}",
        ))
        bug_description = diagnosis.text.strip()

        if pr_number is not None:
            ctx.tools.call(
                "github.comment_on_pr", task_id=task.id, owner=owner, repo=repo, number=pr_number,
                body=(f"🤖 Automated CI diagnosis (attempt {ci_loop_iteration}/{max_ci_loops}): "
                      f"{failure_context}\n\nProposed fix: {bug_description}\n\n"
                      f"Pushing a new commit to `{branch_name}` and re-checking CI."),
            )

        evidence = [
            Evidence(source="github.workflow_jobs", captured_at=datetime.now(timezone.utc).isoformat(),
                     exit_code=1, summary=failure_context[:500]),
            Evidence(source="ci_diagnose_agent.model_call", captured_at=datetime.now(timezone.utc).isoformat(),
                     exit_code=0, summary=f"model={diagnosis.model} proposed: {bug_description[:200]}"),
        ]

        follow_up = build_fix_verify_push_chain(
            project_id=task.project_id, project_root=project_root, target_file=target_file,
            bug_description=bug_description, branch_name=branch_name, owner=owner, repo=repo,
            remote_url=remote_url, base_branch=base_branch,
            ci_loop_iteration=ci_loop_iteration, max_ci_loops=max_ci_loops,
        )

        return TaskResult(
            success=True, evidence=evidence,
            message=f"diagnosed CI failure, proposed fix: {bug_description}",
            follow_up_tasks=follow_up,
        )
