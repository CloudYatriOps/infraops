"""Builds security-remediation task chains on top of the existing
orchestrator/GitHub task graph - Phase 4's counterpart to
`dependency/planner.py` (which itself mirrors `github/planner.py`).
Nothing here touches `orchestrator.py`.

DISCOVER/NORMALIZE/PRIORITIZE happen inside `SecurityAgent`
(mode="scan"). REMEDIATE/TEST/RESCAN/PR/CI is this chain:
security_remediate -> run_tests (the existing TestingAgent, unmodified) ->
security_rescan -> push_branch -> create_pull_request -> monitor_ci (the
existing GitHub agents, unmodified). Exactly like Phase 3's
`build_remediation_chain`, if CI fails MonitorCIAgent's existing hand-off
to diagnose/fix takes over automatically - nothing here reimplements CI
diagnosis.
"""
from __future__ import annotations

import uuid
from typing import Optional

from ..github.planner import build_push_task
from ..models import Task


def _new_id() -> str:
    return str(uuid.uuid4())


def _pr_body(remediations: list[dict]) -> str:
    lines = [
        "Automated security remediation.",
        "",
        "| category | file | finding | severity |",
        "|---|---|---|---|",
    ]
    for r in remediations:
        f = r["finding"]
        lines.append(f"| {f['category']} | {f.get('file', 'n/a')} | {f['rule_id'] or f['id']} | "
                      f"{f['severity']} |")
    lines.append("")
    lines.append("Verified by a second, independent scan of each finding's original scanner "
                  "after remediation (see task evidence) and by the project's existing test suite "
                  "before this PR was opened. No finding above was marked resolved until both "
                  "checks passed. Secret literals (if any) are never printed anywhere in this PR, "
                  "the commit, or the platform's audit log - only redacted previews.")
    return "\n".join(lines)


def build_security_remediation_chain(project_id: str, project_root: str, branch_name: str,
                                      remediations: list[dict],
                                      owner: Optional[str] = None, repo: Optional[str] = None,
                                      remote_url: Optional[str] = None, base_branch: str = "main",
                                      include_github: bool = True, max_ci_loops: int = 3,
                                      start_dependencies: Optional[list[str]] = None) -> list[Task]:
    remediate = Task(id=_new_id(), type="security_remediate", project_id=project_id,
                      owner_agent="security_agent", dependencies=start_dependencies or [],
                      payload={"mode": "remediate", "project_root": project_root,
                               "branch_name": branch_name, "remediations": remediations})
    run_tests = Task(id=_new_id(), type="run_tests", project_id=project_id,
                      owner_agent="testing_agent", dependencies=[remediate.id],
                      payload={"project_root": project_root,
                               "test_args": ["python3", "-m", "pytest", "-q"]})
    rescan = Task(id=_new_id(), type="security_rescan", project_id=project_id,
                   owner_agent="security_agent", dependencies=[run_tests.id],
                   payload={"mode": "rescan", "project_root": project_root,
                            "remediations": remediations})
    chain: list[Task] = [remediate, run_tests, rescan]

    if not include_github:
        return chain

    push = build_push_task(project_id, project_root, branch_name, owner=owner, repo=repo,
                            remote_url=remote_url, dependencies=[rescan.id])
    pr_task = Task(
        id=_new_id(), type="create_pull_request", project_id=project_id,
        owner_agent="pull_request_agent", dependencies=[push.id],
        payload={"owner": owner, "repo": repo, "branch_name": branch_name, "base_branch": base_branch,
                 "title": f"aep: security remediation ({len(remediations)} finding(s))",
                 "body": _pr_body(remediations)},
    )
    monitor = Task(
        id=_new_id(), type="monitor_ci", project_id=project_id, owner_agent="ci_monitor_agent",
        dependencies=[pr_task.id], max_attempts=8,
        payload={"owner": owner, "repo": repo, "branch_name": branch_name,
                 "ci_loop_iteration": 0, "max_ci_loops": max_ci_loops,
                 "project_root": project_root,
                 "target_file": remediations[0]["finding"].get("file") or "app.py",
                 "base_branch": base_branch, "remote_url": remote_url},
    )
    chain.extend([push, pr_task, monitor])
    return chain


def plan_security_scan(orchestrator, project_id: str, project_root: str,
                        owner: Optional[str] = None, repo: Optional[str] = None,
                        remote_url: Optional[str] = None, base_branch: str = "main",
                        branch_name: Optional[str] = None, max_ci_loops: int = 3,
                        categories: Optional[list[str]] = None) -> list[str]:
    """Entry point mirroring `dependency.planner.plan_dependency_scan`'s
    shape: submit one `security_scan` task; everything downstream
    (remediation/escalation/test/rescan/PR/CI-loop) is produced
    dynamically by SecurityAgent's `follow_up_tasks` - no new orchestrator
    primitive. Active (non-expired, non-revoked) suppressions for this
    project are read from the store ONCE here and passed into the task
    payload, so `SecurityAgent` never needs direct StateStore access
    (it only gets what `AgentContext` exposes, same as every other agent)."""
    from .suppressions import list_suppressions

    branch_name = branch_name or f"aep/sec-fix-{uuid.uuid4().hex[:8]}"
    suppressions = [s.__dict__ for s in list_suppressions(orchestrator.store, project_id)]
    scan_task = Task(
        id=_new_id(), type="security_scan", project_id=project_id, owner_agent="security_agent",
        payload={"mode": "scan", "project_root": project_root,
                 "owner": owner, "repo": repo, "remote_url": remote_url,
                 "base_branch": base_branch, "branch_name": branch_name,
                 "max_ci_loops": max_ci_loops, "categories": categories,
                 "suppressions": suppressions},
    )
    return orchestrator.submit_graph(project_id, [scan_task])
