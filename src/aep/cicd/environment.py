"""Deployment environment model (Phase 6 Part 6).

A sibling model to `infra.models.Environment` (Phase 5), not a reuse of
it: Phase 5's enum is a heuristic *inference* about where a repository
file probably lives (with a confidence score, `TEST`/`UNKNOWN` members
included) used for risk weighting; this one is an explicit, operator- or
task-payload-declared deployment target with exactly the three values the
Phase 6 spec names. Conflating the two would mean a mis-inferred
Phase 5 heuristic could silently select a production deployment policy -
exactly the kind of coupling `infra/risk.py`'s "escalation-only, never
trust the heuristic as ground truth" design avoids.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional


class DeploymentEnvironment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


# Policy action strings this environment model expects `PolicyEngine` to
# know about (declared in config/policy.yaml) - always fixed literals
# wherever they are passed to `ctx.policy.evaluate()`, per Part 11/20.
DEPLOY_ACTION = "deployment.deploy"
ROLLBACK_ACTION = "deployment.rollback"


@dataclass
class DeploymentTarget:
    """Everything one deployment attempt needs to know about *where* it is
    going, per Part 6: "Every deployment must know: environment, commit
    SHA, artifact, configuration, infrastructure version, deployment
    policy, approvals, verification checks." The last four of those are
    recorded on `deployment.models.DeploymentRecord`, produced once the
    deployment actually runs; this dataclass is the plan-time input."""
    environment: DeploymentEnvironment
    commit_sha: str
    artifact_id: str
    config_version: str = "unversioned"
    infrastructure_version: str = "unversioned"
    namespace: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["environment"] = self.environment.value
        return d


def policy_context(target: DeploymentTarget, approvals_obtained: bool = False) -> dict:
    """The context dict passed to `PolicyEngine.evaluate(DEPLOY_ACTION,
    ...)`. The action string itself is always the fixed `DEPLOY_ACTION`
    literal above - only this context dict varies with the target, never
    the action name (Part 11/20's "policy actions must always be fixed
    string literals" rule)."""
    return {"environment": target.environment.value, "approvals_obtained": approvals_obtained}
