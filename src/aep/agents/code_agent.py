"""Applies a code change: reads current file content, asks the AIProvider
for corrected content given a bug description, writes it back, then commits
on a feature branch. The model only ever *proposes* text; every mutation
(write, commit) goes through the tool registry so it's policy-checked and
audited like any other agent action."""
from __future__ import annotations

from datetime import datetime, timezone

from ..models import Evidence, FailureClass, RiskLevel, Task, TaskResult
from ..providers.base import GenerationRequest
from .base import Agent, AgentContext


class CodeAgent:
    name = "code_agent"
    required_capabilities = {
        "filesystem.read", "filesystem.write",
        "git.branch", "git.commit", "git.current_branch",
    }

    def run(self, task: Task, ctx: AgentContext) -> TaskResult:
        project_root = task.payload["project_root"]
        target_file = task.payload["target_file"]
        bug_description = task.payload["bug_description"]
        branch_name = task.payload.get("branch_name", f"aep/fix-{task.id[:8]}")

        # Policy check BEFORE creating a branch/committing at all.
        decision = ctx.policy.evaluate("git.branch", {"branch": branch_name})
        if decision.decision.value == "DENY":
            return TaskResult(success=False, failure_class=FailureClass.SECURITY,
                               message=f"policy denied branch creation: {decision.reason}")

        current = ctx.tools.call("filesystem.read", task_id=task.id,
                                  project_root=project_root, path=target_file)
        if not current["ok"]:
            return TaskResult(success=False, failure_class=FailureClass.CODE,
                               message=f"could not read {target_file}")

        result = ctx.router.generate(GenerationRequest(
            task_type="code_fix",
            system_prompt="You are a careful software engineer. Given a file's "
                           "current content and a bug description, return the "
                           "full corrected file content only.",
            user_prompt=f"Bug: {bug_description}\n\nCurrent content of {target_file}:\n{current['content']}",
        ))
        fixed_content = result.text

        ctx.tools.call("git.branch", task_id=task.id, repo_path=project_root, branch_name=branch_name)
        write_result = ctx.tools.call("filesystem.write", task_id=task.id,
                                       project_root=project_root, path=target_file,
                                       content=fixed_content)
        commit_result = ctx.tools.call("git.commit", task_id=task.id, repo_path=project_root,
                                        message=f"aep: fix - {bug_description[:72]}")

        evidence = [
            Evidence(source="code_agent.model_call", captured_at=datetime.now(timezone.utc).isoformat(),
                     exit_code=0, summary=f"model={result.model} tokens_in={result.input_tokens} "
                                           f"tokens_out={result.output_tokens}"),
            Evidence(source="git.commit", captured_at=datetime.now(timezone.utc).isoformat(),
                     exit_code=0 if commit_result["ok"] else 1, summary=commit_result["stdout"][:500]),
        ]
        return TaskResult(
            success=commit_result["ok"],
            evidence=evidence,
            artifacts=[write_result.get("path", target_file)],
            message=f"applied fix to {target_file} on branch {branch_name}",
            failure_class=None if commit_result["ok"] else FailureClass.TOOL,
        )
