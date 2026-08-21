"""DeploymentAgent (Phase 6 Part 5/7/9/10/11).

The integrator: release gates -> policy -> deploy -> verify -> (rollback
if eligible) -> durable evidence. Every step's result is recorded in
`Evidence` and in a `DeploymentRecord` (Part 13), and every policy check
uses a FIXED action-string literal (`deployment.deploy` /
`deployment.rollback` / `deployment.emergency_rollback` -
`cicd/environment.py`/`src/aep/config/policy.yaml`) - never a string built from
the environment name, commit sha, or any other runtime value (Part 11/20).

This agent never decides "should this deploy" on its own judgement - it
only ever executes what `release_gates.evaluate_release_gates()` and
`ctx.policy.evaluate()` already decided. If either says no, nothing after
that point runs; there is no code path that reaches `deployment.deploy`
after a gate failed or policy denied/required approval.
"""
from __future__ import annotations

from datetime import datetime, timezone

from ..cicd.environment import DEPLOY_ACTION, ROLLBACK_ACTION, DeploymentEnvironment
from ..cicd.release_gates import evaluate_release_gates
from ..deployment.models import DeploymentRecord, DeploymentState, VerificationCheck
from ..deployment.rollback import classify_deployment_failure, plan_rollback
from ..models import Evidence, FailureClass, PolicyDecisionType, Task, TaskResult
from .base import Agent, AgentContext


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DeploymentAgent:
    name = "deployment_agent"
    required_capabilities = {
        "deployment.plan", "deployment.deploy", "deployment.verify", "deployment.rollback",
        "deployment.record_evidence",
    }

    def run(self, task: Task, ctx: AgentContext) -> TaskResult:
        mode = task.payload.get("mode", "deploy")
        if mode == "deploy":
            return self._deploy(task, ctx)
        if mode == "rollback":
            return self._rollback(task, ctx)
        raise ValueError(f"unknown deployment_agent mode: {mode!r}")

    def _record(self, ctx: AgentContext, task: Task, record: DeploymentRecord) -> None:
        ctx.tools.call("deployment.record_evidence", task_id=task.id, project_id=task.project_id,
                        record=record.to_dict())

    # ---- DEPLOY -----------------------------------------------------------
    def _deploy(self, task: Task, ctx: AgentContext) -> TaskResult:
        environment = task.payload["environment"]
        commit_sha = task.payload["commit_sha"]
        artifact_id = task.payload["artifact_id"]
        gates_input = task.payload.get("gates", {})
        infra_required = task.payload.get("infra_required", False)

        evidence: list[Evidence] = []
        gate_result = evaluate_release_gates(infra_required=infra_required, **gates_input)
        evidence.append(Evidence(
            source="release_gates", captured_at=_now(),
            exit_code=0 if gate_result.all_required_passed else 1,
            summary=("all required release gates passed" if gate_result.all_required_passed
                      else f"BLOCKED - {'; '.join(gate_result.blockers)}"),
        ))
        record = DeploymentRecord(
            task_id=task.id, commit_sha=commit_sha, artifact_id=artifact_id,
            environment=environment, release_gates_passed=gate_result.all_required_passed,
            approval_status="not_required", provider="", provider_status="",
        )
        if not gate_result.all_required_passed:
            record.final_state = DeploymentState.BLOCKED
            record.ended_at = _now()
            self._record(ctx, task, record)
            return TaskResult(
                success=False, evidence=evidence, failure_class=FailureClass.TOOL,
                message=f"deployment to {environment} BLOCKED - required release gate(s) not "
                        f"satisfied: {gate_result.blockers}",
            )

        # Fixed action-string literal (Part 11/20) - never built from
        # `environment`/`commit_sha`/anything else at runtime.
        decision = ctx.policy.evaluate(DEPLOY_ACTION, {"environment": environment})
        evidence.append(Evidence(
            source="policy", captured_at=_now(),
            exit_code=1 if decision.decision != PolicyDecisionType.ALLOW else 0,
            summary=f"{DEPLOY_ACTION} (environment={environment}) -> {decision.decision.value} "
                    f"({decision.reason})",
        ))
        if decision.decision == PolicyDecisionType.DENY:
            record.final_state = DeploymentState.BLOCKED
            record.approval_status = "denied"
            record.ended_at = _now()
            self._record(ctx, task, record)
            return TaskResult(success=False, evidence=evidence, failure_class=FailureClass.SECURITY,
                               message=f"deployment to {environment} DENIED by policy: "
                                       f"{decision.reason}")
        if decision.decision == PolicyDecisionType.REQUIRE_APPROVAL:
            record.final_state = DeploymentState.APPROVAL_PENDING
            record.approval_status = "pending"
            record.ended_at = _now()
            self._record(ctx, task, record)
            return TaskResult(
                success=False, evidence=evidence, failure_class=FailureClass.HUMAN_REQUIRED,
                message=f"deployment to {environment} requires human approval before proceeding "
                        f"({decision.reason})",
            )
        record.approval_status = "not_required" if decision.matched_rule else "not_required"

        plan_result = ctx.tools.call("deployment.plan", task_id=task.id, environment=environment,
                                      commit_sha=commit_sha, artifact_id=artifact_id)
        provider_name = plan_result["provider"]
        record.provider = provider_name
        deploy_result = ctx.tools.call("deployment.deploy", task_id=task.id,
                                        plan=plan_result["data"])
        outcome = deploy_result["data"]
        record.provider_status = outcome["provider_status"]
        record.rollout_status = outcome["rollout_status"]
        evidence.append(Evidence(
            source=f"deployment:{provider_name}", captured_at=_now(),
            exit_code=0 if outcome["success"] else 1,
            summary=f"provider_status={outcome['provider_status']} "
                    f"rollout_status={outcome['rollout_status']} - {outcome['detail'][:300]}",
        ))
        if not outcome["success"] or not outcome.get("deployment_ref"):
            record.final_state = DeploymentState.FAILED
            record.ended_at = _now()
            self._record(ctx, task, record)
            return TaskResult(success=False, evidence=evidence, failure_class=FailureClass.DEPLOYMENT,
                               message=f"deploy step failed: {outcome['detail']}")

        deployment_ref = outcome["deployment_ref"]
        verify_result = ctx.tools.call("deployment.verify", task_id=task.id,
                                        deployment_ref=deployment_ref)
        verify_data = verify_result["data"]
        record.verification_results = [VerificationCheck(**c) for c in verify_data["checks"]]
        evidence.append(Evidence(
            source="deployment_verification", captured_at=_now(),
            exit_code=0 if verify_data["passed"] else 1,
            summary=f"passed={verify_data['passed']}: "
                    + "; ".join(f"{c['name']}={c['passed']} ({c['detail']})"
                                for c in verify_data["checks"]),
        ))

        if verify_data["passed"]:
            record.final_state = DeploymentState.VERIFIED
            record.ended_at = _now()
            self._record(ctx, task, record)
            return TaskResult(success=True, evidence=evidence,
                               message=f"deployment to {environment} VERIFIED "
                                       f"(deployment_ref={deployment_ref})")

        # Verification failed: classify and decide rollback eligibility -
        # Part 10. Never a blind automatic rollback.
        reason_code = classify_deployment_failure(
            FailureClass.HEALTH, verification_passed=False, rollout_status=record.rollout_status)
        rollback_decision = plan_rollback(reason_code, environment)
        evidence.append(Evidence(
            source="rollback_planner", captured_at=_now(),
            exit_code=0 if rollback_decision.eligible else 1,
            summary=f"reason={rollback_decision.reason_code} eligible={rollback_decision.eligible} "
                    f"requires_approval={rollback_decision.requires_approval}: "
                    f"{rollback_decision.detail}",
        ))
        if not rollback_decision.eligible:
            record.final_state = DeploymentState.FAILED
            record.ended_at = _now()
            self._record(ctx, task, record)
            return TaskResult(success=False, evidence=evidence, failure_class=FailureClass.HEALTH,
                               message=f"deployment to {environment} FAILED verification and is "
                                       f"NOT rollback-eligible ({rollback_decision.detail}); "
                                       f"human required")

        rollback_action = ROLLBACK_ACTION
        rollback_context = {"environment": environment}
        if rollback_decision.requires_approval:
            rollback_action = "deployment.emergency_rollback"
            rollback_context = {"environment": environment, "reason": reason_code}
        rb_decision = ctx.policy.evaluate(rollback_action, rollback_context)
        evidence.append(Evidence(
            source="policy", captured_at=_now(),
            exit_code=0 if rb_decision.decision == PolicyDecisionType.ALLOW else 1,
            summary=f"{rollback_action} ({rollback_context}) -> {rb_decision.decision.value} "
                    f"({rb_decision.reason})",
        ))
        if rb_decision.decision != PolicyDecisionType.ALLOW:
            record.final_state = DeploymentState.FAILED
            record.rollback_status = "REQUIRES_APPROVAL"
            record.ended_at = _now()
            self._record(ctx, task, record)
            return TaskResult(
                success=False, evidence=evidence, failure_class=FailureClass.HUMAN_REQUIRED,
                message=f"deployment to {environment} FAILED verification; automatic rollback "
                        f"requires human approval ({rb_decision.reason})",
            )

        rollback_result = ctx.tools.call("deployment.rollback", task_id=task.id,
                                          deployment_ref=deployment_ref)
        rb_data = rollback_result["data"]
        evidence.append(Evidence(
            source=f"rollback:{provider_name}", captured_at=_now(),
            exit_code=0 if rb_data["success"] else 1, summary=rb_data["detail"][:300],
        ))
        record.rollback_status = "ROLLED_BACK" if rb_data["success"] else "ROLLBACK_FAILED"
        record.final_state = (DeploymentState.ROLLED_BACK if rb_data["success"]
                               else DeploymentState.FAILED)
        record.ended_at = _now()
        self._record(ctx, task, record)
        return TaskResult(
            success=rb_data["success"], evidence=evidence,
            failure_class=None if rb_data["success"] else FailureClass.DEPLOYMENT,
            message=(f"deployment to {environment} failed verification and was automatically "
                     f"rolled back ({rb_data['detail']})" if rb_data["success"] else
                     f"deployment to {environment} failed verification AND rollback failed: "
                     f"{rb_data['detail']}"),
        )

    # ---- explicit ROLLBACK mode (operator/test-triggered) ------------------
    def _rollback(self, task: Task, ctx: AgentContext) -> TaskResult:
        deployment_ref = task.payload["deployment_ref"]
        environment = task.payload["environment"]
        decision = ctx.policy.evaluate(ROLLBACK_ACTION, {"environment": environment})
        evidence = [Evidence(
            source="policy", captured_at=_now(),
            exit_code=0 if decision.decision == PolicyDecisionType.ALLOW else 1,
            summary=f"{ROLLBACK_ACTION} (environment={environment}) -> {decision.decision.value} "
                    f"({decision.reason})",
        )]
        if decision.decision != PolicyDecisionType.ALLOW:
            return TaskResult(success=False, evidence=evidence, failure_class=FailureClass.HUMAN_REQUIRED,
                               message=f"rollback of {deployment_ref} requires approval: "
                                       f"{decision.reason}")
        result = ctx.tools.call("deployment.rollback", task_id=task.id,
                                 deployment_ref=deployment_ref)
        data = result["data"]
        evidence.append(Evidence(source="rollback", captured_at=_now(),
                                  exit_code=0 if data["success"] else 1, summary=data["detail"][:300]))
        return TaskResult(success=data["success"], evidence=evidence,
                           failure_class=None if data["success"] else FailureClass.DEPLOYMENT,
                           message=data["detail"])
