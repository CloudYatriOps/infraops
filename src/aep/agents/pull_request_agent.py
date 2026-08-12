"""Creates or updates a pull request for a feature branch.

Per the original master prompt's PR-workflow requirement ("inspect existing
PRs before creating duplicates"): this agent always lists open PRs for the
branch first and updates the existing one instead of opening a second PR
for the same head branch.
"""
from __future__ import annotations

from datetime import datetime, timezone

from ..models import Evidence, FailureClass, Task, TaskResult
from .base import Agent, AgentContext


class PullRequestAgent:
    name = "pull_request_agent"
    required_capabilities = {"github.list_pull_requests", "github.create_pull_request",
                              "github.update_pull_request", "github.comment_on_pr"}

    def run(self, task: Task, ctx: AgentContext) -> TaskResult:
        owner = task.payload["owner"]
        repo = task.payload["repo"]
        branch_name = task.payload["branch_name"]
        base_branch = task.payload.get("base_branch", "main")
        title = task.payload.get("title", f"aep: {branch_name}")
        body = task.payload.get("body", "Automated change proposed by the Autonomous "
                                          "Engineering Platform. See commit history and "
                                          "CI status for details.")
        comment = task.payload.get("comment")

        existing = ctx.tools.call(
            "github.list_pull_requests", task_id=task.id,
            owner=owner, repo=repo, state="open", head=f"{owner}:{branch_name}",
        )["data"]

        if existing:
            pr = existing[0]
            update_result = ctx.tools.call(
                "github.update_pull_request", task_id=task.id,
                owner=owner, repo=repo, number=pr["number"], body=body,
            )
            pr_data = update_result["data"]
            action = "updated"
        else:
            create_result = ctx.tools.call(
                "github.create_pull_request", task_id=task.id,
                owner=owner, repo=repo, title=title, head=branch_name, base=base_branch, body=body,
            )
            pr_data = create_result["data"]
            action = "created"

        if comment:
            ctx.tools.call("github.comment_on_pr", task_id=task.id,
                            owner=owner, repo=repo, number=pr_data["number"], body=comment)

        evidence = Evidence(
            source="github.pull_request", captured_at=datetime.now(timezone.utc).isoformat(),
            exit_code=0,
            summary=f"{action} PR #{pr_data['number']} ({branch_name} -> {base_branch}): {pr_data.get('html_url', '')}",
        )
        return TaskResult(
            success=True,
            evidence=[evidence],
            artifacts=[pr_data.get("html_url", "")],
            message=f"{action} pull request #{pr_data['number']}",
        )
