"""Builds GitHub-flavored task graphs on top of the existing Orchestrator.

Deliberately NOT a method on Orchestrator: GitHub is a vendor adapter, and
per ARCHITECTURE.md's own principle ("keep project/vendor-specific logic
outside the core"), the orchestrator core (src/aep/orchestrator.py) is not
touched by Phase 2 at all. This module only calls the orchestrator's
existing, already-tested public methods (`submit_graph`).
"""
from __future__ import annotations

import uuid
from typing import Optional

from ..models import Task, TaskStatus
from ..orchestrator import Orchestrator


def _new_id() -> str:
    return str(uuid.uuid4())


def build_push_task(project_id: str, project_root: str, branch_name: str,
                     owner: Optional[str] = None, repo: Optional[str] = None,
                     remote_url: Optional[str] = None, force: bool = False,
                     dependencies: Optional[list[str]] = None,
                     max_attempts: int = 3) -> Task:
    """A push task with the generic orchestrator policy gate wired in
    (ARCHITECTURE.md §8): 'git.push' is DENIED for protected branches and
    REQUIRE_APPROVAL when force=True, evaluated centrally by the
    orchestrator *before* PushAgent ever runs - see push_agent.py's
    docstring and config/policy.yaml."""
    payload = {
        "project_root": project_root, "branch_name": branch_name, "force": force,
        "policy_action": "github.push", "policy_context": {"branch": branch_name, "force": force},
    }
    if remote_url:
        payload["remote_url"] = remote_url
    else:
        payload["owner"] = owner
        payload["repo"] = repo
    return Task(id=_new_id(), type="push_branch", project_id=project_id, owner_agent="push_agent",
                dependencies=dependencies or [], payload=payload, max_attempts=max_attempts)


def build_fix_verify_push_chain(project_id: str, project_root: str, target_file: str,
                                 bug_description: str, branch_name: str,
                                 owner: Optional[str], repo: Optional[str],
                                 remote_url: Optional[str], base_branch: str,
                                 ci_loop_iteration: int, max_ci_loops: int,
                                 start_dependencies: Optional[list[str]] = None) -> list[Task]:
    """code_fix -> security_scan -> run_tests -> push_branch -> monitor_ci,
    the same shape plan_fix_bug already uses for the very first attempt,
    reused here for every CI-failure fix iteration. Building this in one
    place keeps DiagnoseCIFailureAgent's follow_up_tasks (see
    agents/ci_diagnose_agent.py) from duplicating the wiring."""
    code_fix = Task(id=_new_id(), type="code_fix", project_id=project_id, owner_agent="code_agent",
                     dependencies=start_dependencies or [],
                     payload={"project_root": project_root, "target_file": target_file,
                              "bug_description": bug_description, "branch_name": branch_name})
    sec_scan = Task(id=_new_id(), type="security_scan", project_id=project_id,
                     owner_agent="security_scan_agent", dependencies=[code_fix.id],
                     payload={"project_root": project_root})
    run_tests = Task(id=_new_id(), type="run_tests", project_id=project_id,
                      owner_agent="testing_agent", dependencies=[sec_scan.id],
                      payload={"project_root": project_root})
    push = build_push_task(project_id, project_root, branch_name, owner=owner, repo=repo,
                            remote_url=remote_url, dependencies=[run_tests.id])
    monitor = Task(id=_new_id(), type="monitor_ci", project_id=project_id,
                    owner_agent="ci_monitor_agent", dependencies=[push.id],
                    max_attempts=8,  # polling needs more attempts than a normal task
                    payload={"owner": owner, "repo": repo, "branch_name": branch_name,
                             "ci_loop_iteration": ci_loop_iteration, "max_ci_loops": max_ci_loops,
                             # MonitorCIAgent itself doesn't need these, but it must carry
                             # them forward into any diagnose_ci_failure follow-up it
                             # schedules (see ci_monitor_agent.py) - this is the fix for a
                             # real bug caught by the end-to-end test, where the diagnose
                             # task crashed with KeyError('project_root') because the
                             # monitor task's own payload never carried it.
                             "project_root": project_root, "target_file": target_file,
                             "base_branch": base_branch, "remote_url": remote_url})
    return [code_fix, sec_scan, run_tests, push, monitor]


def plan_github_fix_and_pr(orchestrator: Orchestrator, project_id: str, project_root: str,
                            target_file: str, bug_description: str,
                            owner: Optional[str] = None, repo: Optional[str] = None,
                            remote_url: Optional[str] = None, base_branch: str = "main",
                            branch_name: Optional[str] = None, pr_title: Optional[str] = None,
                            pr_body: Optional[str] = None, max_ci_loops: int = 3) -> list[str]:
    """The full request-driven Phase 2 flow: recon -> code fix -> security
    scan -> local tests -> push -> open/update PR -> monitor CI (which
    self-extends into a diagnose/fix/push/monitor loop via follow_up_tasks
    on failure - see ci_monitor_agent.py and ci_diagnose_agent.py)."""
    branch_name = branch_name or f"aep/fix-{uuid.uuid4().hex[:8]}"

    recon = Task(id=_new_id(), type="recon", project_id=project_id, owner_agent="recon",
                 payload={"project_root": project_root})
    chain = build_fix_verify_push_chain(
        project_id, project_root, target_file, bug_description, branch_name,
        owner, repo, remote_url, base_branch, ci_loop_iteration=0, max_ci_loops=max_ci_loops,
        start_dependencies=[recon.id],
    )
    code_fix, sec_scan, run_tests, push, monitor = chain
    pr_task = Task(
        id=_new_id(), type="create_pull_request", project_id=project_id,
        owner_agent="pull_request_agent", dependencies=[push.id],
        payload={"owner": owner, "repo": repo, "branch_name": branch_name, "base_branch": base_branch,
                 "title": pr_title or f"aep: {bug_description[:60]}",
                 "body": pr_body or f"Automated fix for: {bug_description}"},
    )
    # monitor_ci should run after both the push AND the PR exist (it looks
    # the PR up by branch), so re-point its dependency at the PR task
    # instead of the push task the generic chain builder wired it to.
    monitor.dependencies = [pr_task.id]

    return orchestrator.submit_graph(project_id, [recon, *chain[:-1], pr_task, monitor])
