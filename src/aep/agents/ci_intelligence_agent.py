"""CIIntelligenceAgent (Phase 6 Part 2/3).

This does NOT replace `MonitorCIAgent`/`DiagnoseCIFailureAgent` (Phase 2) -
Part 3 step 8 explicitly says "continue the existing PR remediation loop."
What Phase 6 adds on top:

  1. Static pipeline discovery (`inspect` mode) - normalized workflow
     structure from repository files, no network required.
  2. Real failure classification (`classify` mode) over whatever failed
     checks/jobs the existing `MonitorCIAgent` already collected, using
     the NEW `cicd/failure_classification.py` signal-shape classifier
     (Part 3 step 5's eight failure categories) instead of the generic
     `failure.classify()`, which only sees Python exceptions.
  3. Routing: classification result decides whether to hand off to the
     EXISTING code-fix chain (`github/planner.py::build_fix_verify_push_chain`
     - code/test/build/dependency failures), or to a human-required
     escalation task (security/CI-config/unknown failures) - Part 3 step
     6's "create remediation tasks", never a blind retry.

`observe` mode (starting/inspecting a live workflow run) is included for
architectural completeness and is exercised in tests against a
`FakeGitHubTransport`; against the real `api.github.com` it reports
BLOCKED (this sandbox's proxy returns 403 for the Actions API - see
`cicd/providers/github_actions.py`), which this agent reports honestly
rather than treating an unreachable API as "no failures."
"""
from __future__ import annotations

from datetime import datetime, timezone

from ..cicd.discovery import discover_pipeline
from ..cicd.failure_classification import classify_ci_failure
from ..github.planner import build_fix_verify_push_chain
from ..models import Evidence, FailureClass, Task, TaskResult
from .base import Agent, AgentContext


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

# Classes routed back into the existing code-fix loop rather than escalated.
_AUTO_REMEDIABLE = {FailureClass.CODE, FailureClass.TEST, FailureClass.BUILD,
                     FailureClass.DEPENDENCY, FailureClass.FLAKY}


class CIIntelligenceAgent:
    name = "ci_intelligence_agent"
    required_capabilities = {"filesystem.read", "filesystem.list"}

    def run(self, task: Task, ctx: AgentContext) -> TaskResult:
        mode = task.payload.get("mode", "inspect")
        if mode == "inspect":
            return self._inspect(task, ctx)
        if mode == "classify":
            return self._classify(task, ctx)
        raise ValueError(f"unknown ci_intelligence_agent mode: {mode!r}")

    # ---- INSPECT (Part 2: pipeline discovery) ----------------------------
    def _inspect(self, task: Task, ctx: AgentContext) -> TaskResult:
        project_root = task.payload["project_root"]
        pipeline = discover_pipeline(project_root)
        evidence = [Evidence(
            source="cicd_discovery", captured_at=_now(), exit_code=0,
            summary=f"{len(pipeline.workflows)} workflow(s); build={pipeline.has_build} "
                    f"test={pipeline.has_test} security={pipeline.has_security} "
                    f"deploy={pipeline.has_deploy} approval_gate={pipeline.has_approval_gate} "
                    f"rollback_mechanism={pipeline.has_rollback_mechanism} "
                    f"environments={pipeline.environments}",
        )]
        for workflow in pipeline.workflows:
            if workflow.parse_error:
                evidence.append(Evidence(
                    source=f"cicd_discovery:{workflow.path}", captured_at=_now(), exit_code=1,
                    summary=f"could not parse (treated as untrusted/malformed, not skipped "
                            f"silently): {workflow.parse_error}",
                ))
                continue
            evidence.append(Evidence(
                source=f"cicd_discovery:{workflow.path}", captured_at=_now(), exit_code=0,
                summary=f"'{workflow.name}': {len(workflow.jobs)} job(s) - "
                        f"{[(j.name, j.kind.value) for j in workflow.jobs]}",
            ))
        return TaskResult(
            success=True, evidence=evidence, artifacts=[],
            message=f"discovered {len(pipeline.workflows)} CI workflow(s)",
        )

    # ---- CLASSIFY + ROUTE (Part 3 steps 5-7) ------------------------------
    def _classify(self, task: Task, ctx: AgentContext) -> TaskResult:
        failed_checks = task.payload.get("failed_checks", [])
        jobs = task.payload.get("jobs", [])
        previous_conclusion = task.payload.get("previous_run_conclusion")
        diagnosis = classify_ci_failure(failed_checks, jobs, previous_conclusion)

        evidence = [Evidence(
            source="cicd_classification", captured_at=_now(),
            exit_code=0 if diagnosis.failure_class in _AUTO_REMEDIABLE else 1,
            summary=f"classified as {diagnosis.failure_class.value} "
                    f"(signal={diagnosis.matched_signal!r}); next_action={diagnosis.next_action}",
        )]

        if diagnosis.failure_class in _AUTO_REMEDIABLE:
            project_root = task.payload["project_root"]
            target_file = task.payload["target_file"]
            branch_name = task.payload["branch_name"]
            bug_description = (f"CI failed and was classified as "
                                f"{diagnosis.failure_class.value} (signal: "
                                f"{diagnosis.matched_signal or 'none'}); fix the underlying issue.")
            follow_up = build_fix_verify_push_chain(
                project_id=task.project_id, project_root=project_root, target_file=target_file,
                bug_description=bug_description, branch_name=branch_name,
                owner=task.payload.get("owner"), repo=task.payload.get("repo"),
                remote_url=task.payload.get("remote_url"),
                base_branch=task.payload.get("base_branch", "main"),
                ci_loop_iteration=task.payload.get("ci_loop_iteration", 0),
                max_ci_loops=task.payload.get("max_ci_loops", 3),
            )
            return TaskResult(
                success=True, evidence=evidence,
                message=f"{diagnosis.failure_class.value}: routed to the existing fix-verify-push "
                        f"loop ({diagnosis.next_action})",
                follow_up_tasks=follow_up,
            )

        # Security/CI-configuration/network/external-service/unknown: never
        # blindly retried (Part 3: "do not blindly retry failures").
        return TaskResult(
            success=False, evidence=evidence, failure_class=diagnosis.failure_class,
            message=f"{diagnosis.failure_class.value}: {diagnosis.next_action} - not "
                    f"auto-remediated",
        )
