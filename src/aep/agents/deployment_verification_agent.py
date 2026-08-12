"""DeploymentVerificationAgent (Phase 6 Part 9).

A narrower, standalone agent from `DeploymentAgent` on purpose (same
pattern as `InfrastructureDiscoveryAgent` vs
`InfrastructureIntelligenceAgent` in Phase 5): `DeploymentAgent` runs
verification as one step of its own deploy flow, but a deployment can also
need RE-verification on its own later (a scheduled post-deploy health
recheck, or an operator asking "is this still healthy?") without touching
`deployment.deploy`/`deployment.rollback` at all. This agent's capability
set is therefore read-only over the deployment provider: it can observe
rollout/verify, never deploy or roll back anything.

"A deployment is successful only when verification passes" (Part 9) is
enforced by never being the thing that marks a deployment VERIFIED itself
independent of a real `provider.verify()` call - there is no code path
here that returns success without that call having actually run.
"""
from __future__ import annotations

from datetime import datetime, timezone

from ..models import Evidence, FailureClass, Task, TaskResult
from .base import Agent, AgentContext


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DeploymentVerificationAgent:
    name = "deployment_verification_agent"
    required_capabilities = {"deployment.verify", "deployment.rollout_status"}

    def run(self, task: Task, ctx: AgentContext) -> TaskResult:
        deployment_ref = task.payload["deployment_ref"]

        status_result = ctx.tools.call("deployment.rollout_status", task_id=task.id,
                                        deployment_ref=deployment_ref)
        status_data = status_result["data"]
        evidence = [Evidence(
            source="deployment_rollout_status", captured_at=_now(),
            exit_code=0 if status_data.get("found") else 1,
            summary=f"deployment_ref={deployment_ref}: {status_data}",
        )]
        if not status_data.get("found"):
            return TaskResult(success=False, evidence=evidence, failure_class=FailureClass.DEPLOYMENT,
                               message=f"no deployment found for {deployment_ref} - cannot verify")

        verify_result = ctx.tools.call("deployment.verify", task_id=task.id,
                                        deployment_ref=deployment_ref)
        verify_data = verify_result["data"]
        evidence.append(Evidence(
            source="deployment_verification", captured_at=_now(),
            exit_code=0 if verify_data["passed"] else 1,
            summary=f"passed={verify_data['passed']}: "
                    + "; ".join(f"{c['name']}={c['passed']} ({c['detail']})"
                                for c in verify_data["checks"]),
        ))
        return TaskResult(
            success=verify_data["passed"], evidence=evidence,
            failure_class=None if verify_data["passed"] else FailureClass.HEALTH,
            message=f"deployment {deployment_ref} verification "
                    f"{'PASSED' if verify_data['passed'] else 'FAILED'}",
        )
