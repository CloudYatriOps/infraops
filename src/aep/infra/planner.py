"""Infrastructure remediation task chains (Phase 5 Part 11).

Same shape as `dependency/planner.py` (Phase 3) and `security/planner.py`
(Phase 4), reusing `github/planner.py::build_push_task` directly. Nothing
here touches `orchestrator.py` - Part 11: "Do not create an independent
orchestration system."

The chain is `infra_remediate -> run_tests -> infra_rescan [-> push_branch
-> create_pull_request -> monitor_ci]`. Validation is NOT a separate task:
it happens inside `infra_remediate` immediately after each file is
written, so an unvalidatable change is reverted before it is ever
committed (Part 10). Splitting it into its own task would mean committing
first and validating afterwards, which is the wrong order for a gate whose
job is to prevent a bad commit.
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
        "Automated infrastructure security remediation.",
        "",
        "| rule | resource | file | base | priority | risk | fix |",
        "|---|---|---|---|---|---|---|",
    ]
    for item in remediations:
        finding, risk, plan = item["finding"], item.get("risk", {}), item["plan"]
        lines.append(
            f"| {finding.get('rule_id')} | {finding.get('resource')} | {plan.get('file')} | "
            f"{finding.get('severity')} | {risk.get('priority_severity', '-')} | "
            f"{risk.get('score', '-')} | `{plan.get('fix')}` |"
        )
    caveats = sorted({item["plan"].get("caveat", "") for item in remediations
                       if item["plan"].get("caveat")})
    lines.append("")
    lines.append("Each change above was applied to repository files only - **no live "
                  "infrastructure was touched, and no `terraform apply` was run**. Every change "
                  "was re-validated after being written and a change that could not be validated "
                  "was reverted rather than committed. A second, independent scan confirmed each "
                  "finding is gone before this PR was opened.")
    if caveats:
        lines.append("")
        lines.append("**Reviewer notes:**")
        for caveat in caveats:
            lines.append(f"- {caveat}")
    lines.append("")
    lines.append("Findings that required human judgement (ambiguous IAM/network policy, "
                  "unrecognized structural shapes) were deliberately NOT auto-fixed and are "
                  "tracked as separate approval-required tasks.")
    return "\n".join(lines)


def build_infra_remediation_chain(project_id: str, project_root: str, branch_name: str,
                                   remediations: list[dict],
                                   owner: Optional[str] = None, repo: Optional[str] = None,
                                   remote_url: Optional[str] = None, base_branch: str = "main",
                                   include_github: bool = True, max_ci_loops: int = 3,
                                   start_dependencies: Optional[list[str]] = None) -> list[Task]:
    remediate = Task(
        id=_new_id(), type="infra_remediate", project_id=project_id,
        owner_agent="infrastructure_intelligence_agent", dependencies=start_dependencies or [],
        payload={"mode": "remediate", "project_root": project_root, "branch_name": branch_name,
                 "remediations": remediations},
    )
    run_tests = Task(
        id=_new_id(), type="run_tests", project_id=project_id, owner_agent="testing_agent",
        dependencies=[remediate.id],
        payload={"project_root": project_root, "test_args": ["python3", "-m", "pytest", "-q"]},
    )
    rescan = Task(
        id=_new_id(), type="infra_rescan", project_id=project_id,
        owner_agent="infrastructure_intelligence_agent", dependencies=[run_tests.id],
        payload={"mode": "rescan", "project_root": project_root, "remediations": remediations},
    )
    chain: list[Task] = [remediate, run_tests, rescan]

    if not include_github:
        return chain

    push = build_push_task(project_id, project_root, branch_name, owner=owner, repo=repo,
                            remote_url=remote_url, dependencies=[rescan.id])
    pull_request = Task(
        id=_new_id(), type="create_pull_request", project_id=project_id,
        owner_agent="pull_request_agent", dependencies=[push.id],
        payload={"owner": owner, "repo": repo, "branch_name": branch_name,
                 "base_branch": base_branch,
                 "title": f"aep: infrastructure security remediation "
                          f"({len(remediations)} finding(s))",
                 "body": _pr_body(remediations)},
    )
    monitor = Task(
        id=_new_id(), type="monitor_ci", project_id=project_id, owner_agent="ci_monitor_agent",
        dependencies=[pull_request.id], max_attempts=8,
        payload={"owner": owner, "repo": repo, "branch_name": branch_name,
                 "ci_loop_iteration": 0, "max_ci_loops": max_ci_loops,
                 "project_root": project_root,
                 "target_file": remediations[0]["plan"].get("file") or "main.tf",
                 "base_branch": base_branch, "remote_url": remote_url},
    )
    chain.extend([push, pull_request, monitor])
    return chain


def plan_infrastructure_scan(orchestrator, project_id: str, project_root: str,
                              owner: Optional[str] = None, repo: Optional[str] = None,
                              remote_url: Optional[str] = None, base_branch: str = "main",
                              branch_name: Optional[str] = None, max_ci_loops: int = 3,
                              cloud_provider: Optional[str] = None,
                              with_discovery: bool = True) -> list[str]:
    """Entry point mirroring `plan_dependency_scan`/`plan_security_scan`.
    Submits a read-only `infra_discover` task (when requested) followed by
    `infra_scan`; everything downstream is produced dynamically by
    `InfrastructureIntelligenceAgent`'s `follow_up_tasks` - no new
    orchestrator primitive."""
    branch_name = branch_name or f"aep/infra-fix-{uuid.uuid4().hex[:8]}"
    tasks: list[Task] = []

    discover_id: list[str] = []
    if with_discovery:
        discover = Task(
            id=_new_id(), type="infra_discover", project_id=project_id,
            owner_agent="infrastructure_discovery_agent",
            payload={"project_root": project_root, "cloud_provider": cloud_provider},
        )
        tasks.append(discover)
        discover_id = [discover.id]

    scan = Task(
        id=_new_id(), type="infra_scan", project_id=project_id,
        owner_agent="infrastructure_intelligence_agent", dependencies=discover_id,
        payload={"mode": "scan", "project_root": project_root, "owner": owner, "repo": repo,
                 "remote_url": remote_url, "base_branch": base_branch, "branch_name": branch_name,
                 "max_ci_loops": max_ci_loops},
    )
    tasks.append(scan)
    return orchestrator.submit_graph(project_id, tasks)
