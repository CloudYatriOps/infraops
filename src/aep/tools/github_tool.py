"""GitHub capabilities exposed through the existing tool registry.

Every read/write REST capability goes through `GitHubClient` (real API
surface - see src/aep/github/client.py). `github.push_branch` is the one
capability that isn't a REST call: it's a real `git push` over HTTPS using
a short-lived GIT_ASKPASS credential helper so the token never appears in
argv (visible via `ps`) or in any returned/logged string.

The whole tool is registered at RiskLevel.HIGH (matching the shell tool's
"most dangerous capability sets the tool's risk" convention) because it can
push commits and open PRs against an external system; individual agents
still only ever get the specific capability strings they declare.
"""
from __future__ import annotations

import os
import stat
import subprocess
import tempfile
from typing import Optional

from ..github.client import GitHubClient, Transport
from ..models import RiskLevel
from ..redaction import redact, redact_literal
from ..secrets import SecretManager
from ..tool_registry import Tool

READ_CAPABILITIES = {
    "github.get_repo", "github.list_branches", "github.get_branch",
    "github.list_commits", "github.get_commit",
    "github.list_pull_requests", "github.get_pull_request", "github.list_pr_files",
    "github.list_pr_comments", "github.get_combined_status", "github.list_check_runs",
    "github.list_issues", "github.list_workflow_runs", "github.get_workflow_run",
    "github.list_workflow_run_jobs",
}
WRITE_CAPABILITIES = {
    "github.create_pull_request", "github.update_pull_request", "github.comment_on_pr",
    "github.create_issue", "github.push_branch",
}
ALL_CAPABILITIES = READ_CAPABILITIES | WRITE_CAPABILITIES


def _push_branch(secret_manager: SecretManager, token_secret_name: str, **kwargs) -> dict:
    repo_path = kwargs["repo_path"]
    branch_name = kwargs["branch_name"]
    remote_url = kwargs.get("remote_url")
    force = bool(kwargs.get("force", False))

    env = os.environ.copy()
    askpass_path: Optional[str] = None
    token_value: Optional[str] = None
    try:
        if not remote_url:
            owner = kwargs["owner"]
            repo = kwargs["repo"]
            token_value = secret_manager.get(token_secret_name)
            # Username-only URL: git will invoke GIT_ASKPASS for the password
            # rather than needing the token embedded in the URL (and
            # therefore in argv / `ps`).
            remote_url = f"https://x-access-token@github.com/{owner}/{repo}.git"
            fd, askpass_path = tempfile.mkstemp(prefix="aep_askpass_")
            with os.fdopen(fd, "w") as f:
                f.write('#!/bin/sh\necho "$AEP_GIT_ASKPASS_TOKEN"\n')
            os.chmod(askpass_path, stat.S_IRWXU)
            env["GIT_ASKPASS"] = askpass_path
            env["AEP_GIT_ASKPASS_TOKEN"] = token_value

        args = ["git", "-C", repo_path, "push"]
        if force:
            args.append("--force")
        args += [remote_url, f"{branch_name}:{branch_name}"]

        proc = subprocess.run(args, capture_output=True, text=True, timeout=30, env=env)
        stdout, stderr = proc.stdout, proc.stderr
        if token_value:
            stdout = redact_literal(stdout, token_value)
            stderr = redact_literal(stderr, token_value)
        return {"ok": proc.returncode == 0, "stdout": redact(stdout), "stderr": redact(stderr)}
    finally:
        if askpass_path and os.path.exists(askpass_path):
            os.remove(askpass_path)


def _build_handler(client: GitHubClient, secret_manager: SecretManager, token_secret_name: str):
    def _handler(capability: str, **kwargs) -> dict:
        if capability == "github.get_repo":
            return {"ok": True, "data": client.get_repo(kwargs["owner"], kwargs["repo"])}
        if capability == "github.list_branches":
            return {"ok": True, "data": client.list_branches(kwargs["owner"], kwargs["repo"])}
        if capability == "github.get_branch":
            return {"ok": True, "data": client.get_branch(kwargs["owner"], kwargs["repo"], kwargs["branch"])}
        if capability == "github.list_commits":
            return {"ok": True, "data": client.list_commits(
                kwargs["owner"], kwargs["repo"], sha=kwargs.get("sha"), path=kwargs.get("path"))}
        if capability == "github.get_commit":
            return {"ok": True, "data": client.get_commit(kwargs["owner"], kwargs["repo"], kwargs["sha"])}
        if capability == "github.list_pull_requests":
            return {"ok": True, "data": client.list_pull_requests(
                kwargs["owner"], kwargs["repo"], state=kwargs.get("state", "open"),
                head=kwargs.get("head"), base=kwargs.get("base"))}
        if capability == "github.get_pull_request":
            return {"ok": True, "data": client.get_pull_request(kwargs["owner"], kwargs["repo"], kwargs["number"])}
        if capability == "github.create_pull_request":
            return {"ok": True, "data": client.create_pull_request(
                kwargs["owner"], kwargs["repo"], title=kwargs["title"], head=kwargs["head"],
                base=kwargs["base"], body=kwargs.get("body", ""))}
        if capability == "github.update_pull_request":
            fields = {k: v for k, v in kwargs.items() if k not in ("owner", "repo", "number")}
            return {"ok": True, "data": client.update_pull_request(kwargs["owner"], kwargs["repo"],
                                                                     kwargs["number"], **fields)}
        if capability == "github.list_pr_files":
            return {"ok": True, "data": client.list_pr_files(kwargs["owner"], kwargs["repo"], kwargs["number"])}
        if capability == "github.comment_on_pr":
            return {"ok": True, "data": client.create_issue_comment(
                kwargs["owner"], kwargs["repo"], kwargs["number"], kwargs["body"])}
        if capability == "github.list_pr_comments":
            return {"ok": True, "data": client.list_issue_comments(kwargs["owner"], kwargs["repo"], kwargs["number"])}
        if capability == "github.get_combined_status":
            return {"ok": True, "data": client.get_combined_status(kwargs["owner"], kwargs["repo"], kwargs["ref"])}
        if capability == "github.list_check_runs":
            return {"ok": True, "data": client.list_check_runs(kwargs["owner"], kwargs["repo"], kwargs["ref"])}
        if capability == "github.list_issues":
            return {"ok": True, "data": client.list_issues(kwargs["owner"], kwargs["repo"], kwargs.get("state", "open"))}
        if capability == "github.create_issue":
            return {"ok": True, "data": client.create_issue(kwargs["owner"], kwargs["repo"],
                                                              kwargs["title"], kwargs.get("body", ""))}
        if capability == "github.list_workflow_runs":
            return {"ok": True, "data": client.list_workflow_runs(kwargs["owner"], kwargs["repo"], kwargs.get("branch"))}
        if capability == "github.get_workflow_run":
            return {"ok": True, "data": client.get_workflow_run(kwargs["owner"], kwargs["repo"], kwargs["run_id"])}
        if capability == "github.list_workflow_run_jobs":
            return {"ok": True, "data": client.list_workflow_run_jobs(kwargs["owner"], kwargs["repo"], kwargs["run_id"])}
        if capability == "github.push_branch":
            return _push_branch(secret_manager, token_secret_name, **kwargs)
        raise ValueError(f"unsupported capability for github tool: {capability}")
    return _handler


def build_github_tool(secret_manager: SecretManager, transport: Optional[Transport] = None,
                       base_url: str = "https://api.github.com",
                       token_secret_name: str = "github_token") -> Tool:
    client = GitHubClient(
        token_provider=lambda: secret_manager.get(token_secret_name),
        base_url=base_url, transport=transport,
    )
    return Tool(
        name="github",
        capabilities=set(ALL_CAPABILITIES),
        risk=RiskLevel.HIGH,
        description="Real GitHub REST API operations (discovery, branches, commits, PRs, "
                     "comments, checks, issues, workflow runs) plus a token-authenticated "
                     "git push; credentials are resolved per-call from the SecretManager and "
                     "never appear in inputs/outputs that get logged.",
        handler=_build_handler(client, secret_manager, token_secret_name),
    )
