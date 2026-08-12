"""InfrastructureDiscoveryAgent (Phase 5 Part 1).

Read-only by construction AND by policy. By construction: it declares only
`filesystem.*` capabilities, so the capability-scoped `ScopedRegistry`
(Phase 1) makes it structurally incapable of running a shell command,
touching git, or calling GitHub - the tools simply are not in its scope.
By policy: it evaluates the existing `PolicyEngine` for
`infra.discovery` before doing anything, so an operator can turn even
read-only inventory off.

Optionally performs a live, read-only cloud discovery pass when a provider
is requested - via `infra/cloud/`, which enforces its own read-only
allowlist independently (defense in depth, not one gate trusted twice).
The result's REAL/MOCKED/UNAVAILABLE status is written into evidence
verbatim so no downstream reader can mistake an unreachable cloud for an
empty one.
"""
from __future__ import annotations

from datetime import datetime, timezone

from ..infra.discovery import discover_infrastructure
from ..models import Evidence, FailureClass, PolicyDecisionType, Task, TaskResult
from .base import Agent, AgentContext


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class InfrastructureDiscoveryAgent:
    name = "infrastructure_discovery_agent"
    # Deliberately the narrowest capability set of any agent in this
    # platform: no shell, no git, no github. Discovery cannot mutate
    # anything because it holds no tool that can.
    required_capabilities = {"filesystem.list", "filesystem.read"}

    def run(self, task: Task, ctx: AgentContext) -> TaskResult:
        project_root = task.payload["project_root"]

        decision = ctx.policy.evaluate("infra.discovery", {"read_only": True})
        evidence = [Evidence(
            source="policy", captured_at=_now(),
            exit_code=1 if decision.decision == PolicyDecisionType.DENY else 0,
            summary=f"infra.discovery (read_only=True) -> {decision.decision.value} "
                    f"({decision.reason})",
        )]
        if decision.decision == PolicyDecisionType.DENY:
            return TaskResult(success=False, evidence=evidence, failure_class=FailureClass.SECURITY,
                               message=f"policy denied infrastructure discovery: {decision.reason}")

        inventory = discover_infrastructure(project_root)
        summary = inventory.to_dict()
        evidence.append(Evidence(
            source="infra_discovery", captured_at=_now(), exit_code=0,
            summary=f"{summary['asset_count']} infrastructure asset(s): "
                    f"kinds={summary['kinds']}; provider hints={summary['provider_hints']}; "
                    f"environments={summary['environments']}",
        ))
        for asset in inventory.assets:
            evidence.append(Evidence(
                source=f"infra_asset:{asset.kind.value}", captured_at=_now(), exit_code=0,
                summary=f"{asset.path} [{asset.environment.value}/"
                        f"{asset.environment_confidence} confidence] {asset.detail}",
            ))
        for entry in inventory.unreadable:
            evidence.append(Evidence(
                source="infra_discovery:unreadable", captured_at=_now(), exit_code=0,
                summary=f"{entry['path']}: {entry['reason']} - discovered but NOT analyzed, so "
                        f"its contents are unverified rather than clean",
            ))

        cloud_provider = task.payload.get("cloud_provider")
        if cloud_provider:
            evidence.extend(self._discover_cloud(task, ctx, cloud_provider))

        return TaskResult(
            success=True, evidence=evidence,
            message=f"discovered {summary['asset_count']} infrastructure asset(s) across "
                    f"{len(summary['kinds'])} kind(s)",
            artifacts=[],
        )

    def _discover_cloud(self, task: Task, ctx: AgentContext, provider: str) -> list[Evidence]:
        """Live cloud discovery is READ-ONLY and separately policy-gated:
        even though `infra/cloud/` cannot perform a write operation, the
        decision to contact a real cloud account at all is its own policy
        question."""
        from ..infra.cloud import registry

        decision = ctx.policy.evaluate("infra.cloud_discovery",
                                        {"provider": provider, "read_only": True})
        evidence = [Evidence(
            source="policy", captured_at=_now(),
            exit_code=1 if decision.decision == PolicyDecisionType.DENY else 0,
            summary=f"infra.cloud_discovery (provider={provider}, read_only=True) -> "
                    f"{decision.decision.value} ({decision.reason})",
        )]
        if decision.decision == PolicyDecisionType.DENY:
            return evidence

        result = registry.discover(provider)
        evidence.append(Evidence(
            source=f"infra_cloud:{provider}", captured_at=_now(),
            exit_code=0 if result.is_real else 1,
            summary=f"cloud discovery status={result.status.value} "
                    f"(is_real={result.is_real}): {result.reason}",
        ))
        for resource in result.resources:
            evidence.append(Evidence(
                source=f"infra_cloud_resource:{provider}", captured_at=_now(), exit_code=0,
                summary=f"{resource.resource_id} ({resource.resource_type}): {resource.attributes}",
            ))
        for capability, error in (result.capabilities_failed or {}).items():
            evidence.append(Evidence(
                source=f"infra_cloud_failed:{provider}", captured_at=_now(), exit_code=1,
                summary=f"capability {capability} could not be read: {error} - reported rather "
                        f"than silently returning an empty (falsely clean) result",
            ))
        return evidence
