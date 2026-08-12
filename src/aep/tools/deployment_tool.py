"""Deployment capability exposed through the existing capability-scoped
tool registry (Phase 6 Part 7/9/13).

Every provider call (`plan`/`deploy`/`verify`/`rollback`) - real
consequences even for the local fixture provider, and potentially a real
cluster mutation for the Kubernetes provider - is routed through this
tool exactly the way `shell.run`/`git.*` already are, so it is
capability-scoped to `DeploymentAgent` and audited by the same
`EventLogger` every other tool call goes through (Part 9's "deployment
privilege escalation" threat is mitigated the same way arbitrary shell
execution already is: an agent that was never granted `deployment.deploy`
structurally cannot call it).

`record_evidence`/`list_evidence` reuse the platform's EXISTING
`StateStore` instance (the same one the orchestrator persists tasks to),
injected here rather than opened fresh - Part 13's "survives a process
restart" is true because it is the same durable SQLite file, not because
this module reimplements durability.
"""
from __future__ import annotations

from typing import Callable

from ..deployment.evidence import list_deployment_evidence, record_deployment
from ..deployment.models import DeploymentRecord
from ..deployment.provider import DeployPlan
from ..models import RiskLevel
from ..state_store import StateStore
from ..tool_registry import Tool

CAPABILITIES = {
    "deployment.plan", "deployment.deploy", "deployment.rollout_status", "deployment.verify",
    "deployment.rollback", "deployment.record_evidence", "deployment.list_evidence",
}


def _build_handler(store: StateStore, provider_factory: Callable[[], object]):
    def _handler(capability: str, **kwargs) -> dict:
        if capability == "deployment.plan":
            provider = provider_factory()
            plan = provider.plan(kwargs["environment"], kwargs["commit_sha"], kwargs["artifact_id"])
            return {"ok": True, "data": plan.to_dict(), "provider": provider.name}
        if capability == "deployment.deploy":
            provider = provider_factory()
            plan = DeployPlan(**kwargs["plan"])
            outcome = provider.deploy(plan)
            return {"ok": outcome.success, "data": outcome.to_dict()}
        if capability == "deployment.rollout_status":
            provider = provider_factory()
            return {"ok": True, "data": provider.rollout_status(kwargs["deployment_ref"])}
        if capability == "deployment.verify":
            provider = provider_factory()
            outcome = provider.verify(kwargs["deployment_ref"])
            return {"ok": outcome.passed, "data": outcome.to_dict()}
        if capability == "deployment.rollback":
            provider = provider_factory()
            outcome = provider.rollback(kwargs["deployment_ref"])
            return {"ok": outcome.success, "data": {"success": outcome.success,
                                                       "detail": outcome.detail}}
        if capability == "deployment.record_evidence":
            record = DeploymentRecord.from_dict(kwargs["record"])
            record_deployment(store, kwargs["project_id"], record)
            return {"ok": True}
        if capability == "deployment.list_evidence":
            records = list_deployment_evidence(store, kwargs["project_id"])
            return {"ok": True, "data": [r.to_dict() for r in records]}
        raise ValueError(f"unsupported capability for deployment tool: {capability}")
    return _handler


def build_deployment_tool(store: StateStore, provider_factory: Callable[[], object]) -> Tool:
    return Tool(
        name="deployment",
        capabilities=set(CAPABILITIES),
        risk=RiskLevel.HIGH,
        description="Deployment plan/deploy/verify/rollback through a provider-agnostic "
                     "DeploymentProvider, plus durable deployment evidence recording/listing "
                     "backed by the platform's existing StateStore.",
        handler=_build_handler(store, provider_factory),
    )
