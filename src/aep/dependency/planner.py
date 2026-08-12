"""Builds dependency-remediation task chains on top of the existing
orchestrator/GitHub task graph - the same "vendor/workflow wiring lives
outside the core" pattern as `github/planner.py`. Nothing here touches
`orchestrator.py`.

DISCOVER/UNDERSTAND happen inside `DependencyCVEAgent` (mode="scan").
REMEDIATE/TEST/RESCAN/PR/CI is this chain: dependency_remediate -> run_tests
(the existing TestingAgent, unmodified) -> dependency_rescan -> push_branch
-> create_pull_request -> monitor_ci (the existing GitHub agents,
unmodified). If CI fails, MonitorCIAgent's *existing* handoff to
diagnose_ci_failure -> build_fix_verify_push_chain (github/planner.py,
unmodified) takes over automatically - this module does not reimplement
CI diagnosis.
"""
from __future__ import annotations

import uuid
from typing import Optional

from ..github.planner import build_push_task
from ..models import Task


def _new_id() -> str:
    return str(uuid.uuid4())


def _pr_body(plans_payload: list[dict]) -> str:
    lines = [
        "Automated dependency security remediation.",
        "",
        "| package | from | to | finding(s) |",
        "|---|---|---|---|",
    ]
    for p in plans_payload:
        lines.append(f"| {p['package']} | {p['from_version']} | {p['to_version']} | "
                      f"{', '.join(p['finding_ids'])} |")
    lines.append("")
    lines.append("Verified by a second dependency scan after the upgrade (see task evidence) "
                  "and by the project's existing test suite before this PR was opened. This PR "
                  "was not opened, and the finding(s) above were not marked resolved, until both "
                  "checks passed.")
    return "\n".join(lines)


def build_remediation_chain(project_id: str, project_root: str, branch_name: str,
                             plans_payload: list[dict],
                             owner: Optional[str] = None, repo: Optional[str] = None,
                             remote_url: Optional[str] = None, base_branch: str = "main",
                             include_github: bool = True, max_ci_loops: int = 3,
                             start_dependencies: Optional[list[str]] = None) -> list[Task]:
    remediate = Task(id=_new_id(), type="dependency_remediate", project_id=project_id,
                      owner_agent="dependency_cve_agent", dependencies=start_dependencies or [],
                      payload={"mode": "remediate", "project_root": project_root,
                               "branch_name": branch_name, "plans": plans_payload})
    run_tests = Task(id=_new_id(), type="run_tests", project_id=project_id,
                      owner_agent="testing_agent", dependencies=[remediate.id],
                      # Explicit `python3 -m pytest` rather than TestingAgent's
                      # bare-`pytest` default: the remediation step installs
                      # the upgraded package via `python3 -m pip install`
                      # (see dependency_cve_agent.py::_install_upgraded_packages),
                      # so the test run needs the SAME interpreter to see it.
                      # In an environment where `pytest` is a separately
                      # managed tool install (isolated from `python3`'s own
                      # site-packages - true in this sandbox), a bare
                      # `pytest` invocation would run tests against whatever
                      # was installed *before* remediation, silently
                      # defeating the point of "run tests after upgrading" -
                      # a real gap found via a manual end-to-end run during
                      # Phase 3 development, not a unit test.
                      payload={"project_root": project_root,
                               "test_args": ["python3", "-m", "pytest", "-q"]})
    rescan = Task(id=_new_id(), type="dependency_rescan", project_id=project_id,
                   owner_agent="dependency_cve_agent", dependencies=[run_tests.id],
                   payload={"mode": "rescan", "project_root": project_root, "plans": plans_payload})
    chain: list[Task] = [remediate, run_tests, rescan]

    if not include_github:
        return chain

    push = build_push_task(project_id, project_root, branch_name, owner=owner, repo=repo,
                            remote_url=remote_url, dependencies=[rescan.id])
    pr_task = Task(
        id=_new_id(), type="create_pull_request", project_id=project_id,
        owner_agent="pull_request_agent", dependencies=[push.id],
        payload={"owner": owner, "repo": repo, "branch_name": branch_name, "base_branch": base_branch,
                 "title": f"aep: dependency security remediation ({len(plans_payload)} package(s))",
                 "body": _pr_body(plans_payload)},
    )
    monitor = Task(
        id=_new_id(), type="monitor_ci", project_id=project_id, owner_agent="ci_monitor_agent",
        dependencies=[pr_task.id], max_attempts=8,
        payload={"owner": owner, "repo": repo, "branch_name": branch_name,
                 "ci_loop_iteration": 0, "max_ci_loops": max_ci_loops,
                 "project_root": project_root,
                 # If CI fails for a reason unrelated to the bump itself, the
                 # *existing* generic diagnose/fix loop needs a target_file
                 # to act on - the first remediated manifest is the most
                 # relevant candidate.
                 "target_file": plans_payload[0]["manifest_path"],
                 "base_branch": base_branch, "remote_url": remote_url},
    )
    chain.extend([push, pr_task, monitor])
    return chain


def plan_dependency_scan(orchestrator, project_id: str, project_root: str,
                          owner: Optional[str] = None, repo: Optional[str] = None,
                          remote_url: Optional[str] = None, base_branch: str = "main",
                          branch_name: Optional[str] = None, max_ci_loops: int = 3) -> list[str]:
    """Entry point mirroring `github.planner.plan_github_fix_and_pr`'s
    shape: submit one `dependency_scan` task; everything downstream
    (remediation, test, rescan, PR, CI-loop) is produced dynamically by
    DependencyCVEAgent's `follow_up_tasks`, exactly like Phase 2's CI
    diagnose loop - no new orchestrator primitive."""
    branch_name = branch_name or f"aep/dep-fix-{uuid.uuid4().hex[:8]}"
    scan_task = Task(
        id=_new_id(), type="dependency_scan", project_id=project_id,
        owner_agent="dependency_cve_agent",
        payload={"mode": "scan", "project_root": project_root,
                 "owner": owner, "repo": repo, "remote_url": remote_url,
                 "base_branch": base_branch, "branch_name": branch_name,
                 "max_ci_loops": max_ci_loops},
    )
    return orchestrator.submit_graph(project_id, [scan_task])
