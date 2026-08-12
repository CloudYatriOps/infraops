"""Deployment provider contract (Phase 6 Part 7).

`plan` / `deploy` / `status` / `verify` / `rollback` - the exact five
verbs the spec names. Every provider reports its own
`DeploymentProviderAvailability` the same way `infra/cloud/base.py` and
`cicd/providers/base.py` do, so a caller can never mistake a MOCKED or
UNAVAILABLE provider's "success" for a live one.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional, Protocol

from .models import VerificationCheck


class DeploymentProviderAvailability(str, Enum):
    AVAILABLE = "AVAILABLE"          # deploy(): actually reaches a real target
    LOCAL_FIXTURE = "LOCAL_FIXTURE"  # a real, deterministic local simulation - not live infra
    UNAVAILABLE = "UNAVAILABLE"      # required tooling/cluster missing
    BLOCKED = "BLOCKED"              # network/egress prevents reaching a real target


@dataclass
class DeployPlan:
    environment: str
    commit_sha: str
    artifact_id: str
    steps: list[str] = field(default_factory=list)
    dry_run: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DeployOutcome:
    success: bool
    provider: str
    provider_status: DeploymentProviderAvailability
    rollout_status: str
    detail: str
    deployment_ref: Optional[str] = None  # provider-specific handle used by status()/verify()/rollback()

    def to_dict(self) -> dict:
        d = asdict(self)
        d["provider_status"] = self.provider_status.value
        return d


@dataclass
class VerifyOutcome:
    passed: bool
    checks: list[VerificationCheck] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"passed": self.passed, "checks": [c.to_dict() for c in self.checks]}


@dataclass
class RollbackOutcome:
    success: bool
    detail: str


class DeploymentProvider(Protocol):
    name: str

    def status(self) -> tuple: ...  # (DeploymentProviderAvailability, reason)

    def plan(self, environment: str, commit_sha: str, artifact_id: str) -> DeployPlan: ...

    def deploy(self, plan: DeployPlan) -> DeployOutcome: ...

    def rollout_status(self, deployment_ref: str) -> dict: ...

    def verify(self, deployment_ref: str) -> VerifyOutcome: ...

    def rollback(self, deployment_ref: str) -> RollbackOutcome: ...
