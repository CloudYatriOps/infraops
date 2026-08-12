"""Normalized CI/CD pipeline model (Phase 6 Part 1/2).

`discovery.py` parses real `.github/workflows/*.yml` files (static,
in-process YAML parsing - `yaml.safe_load`, never executed) into these
dataclasses. This is deliberately independent of whether the live GitHub
Actions API is reachable: pipeline *structure* is a property of the
repository's own files, not of a network call, so discovery works even
when `providers.github_actions` reports BLOCKED.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional


class JobKind(str, Enum):
    """What a workflow job actually does, inferred from its name/steps -
    Part 2's "build jobs, test jobs, security jobs, artifact generation,
    deployment jobs" categories, plus two the platform needs to reason
    about safety: APPROVAL (a GitHub `environment:` with required
    reviewers) and ROLLBACK (a step that names rollback explicitly)."""
    BUILD = "build"
    TEST = "test"
    SECURITY = "security"
    ARTIFACT = "artifact"
    DEPLOY = "deploy"
    APPROVAL = "approval"
    ROLLBACK = "rollback"
    LINT = "lint"
    UNKNOWN = "unknown"


class CIRunConclusion(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    PENDING = "pending"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown"


class PipelineReadiness(str, Enum):
    """The nine-state lifecycle Part 0 of the spec asks the platform to
    distinguish, computed structurally from what a pipeline model and its
    latest run actually show - never inferred from "tests pass, therefore
    ready"."""
    CODE_READY = "CODE_READY"
    CI_READY = "CI_READY"
    STAGING_READY = "STAGING_READY"
    PRODUCTION_CANDIDATE = "PRODUCTION_CANDIDATE"
    PRODUCTION_READY = "PRODUCTION_READY"
    DEPLOYED = "DEPLOYED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"


@dataclass
class WorkflowJob:
    name: str
    kind: JobKind
    steps: list[str] = field(default_factory=list)
    needs: list[str] = field(default_factory=list)
    environment: Optional[str] = None  # GitHub Actions `environment:` block name, if any

    def to_dict(self) -> dict:
        d = asdict(self)
        d["kind"] = self.kind.value
        return d


@dataclass
class WorkflowDefinition:
    path: str
    name: str
    triggers: list[str] = field(default_factory=list)
    jobs: list[WorkflowJob] = field(default_factory=list)
    parse_error: Optional[str] = None  # untrusted file failed to parse safely - see discovery.py

    @property
    def job_kinds(self) -> set[JobKind]:
        return {j.kind for j in self.jobs}

    @property
    def has_deploy(self) -> bool:
        return JobKind.DEPLOY in self.job_kinds

    @property
    def has_approval_gate(self) -> bool:
        return any(j.environment for j in self.jobs) or JobKind.APPROVAL in self.job_kinds

    @property
    def has_rollback_mechanism(self) -> bool:
        return JobKind.ROLLBACK in self.job_kinds

    def to_dict(self) -> dict:
        return {
            "path": self.path, "name": self.name, "triggers": self.triggers,
            "jobs": [j.to_dict() for j in self.jobs], "parse_error": self.parse_error,
            "has_deploy": self.has_deploy, "has_approval_gate": self.has_approval_gate,
            "has_rollback_mechanism": self.has_rollback_mechanism,
        }


@dataclass
class PipelineModel:
    """One repository's normalized CI/CD picture - Part 2's "normalized
    pipeline model", built purely from static discovery (no network)."""
    workflows: list[WorkflowDefinition] = field(default_factory=list)

    @property
    def has_build(self) -> bool:
        return any(JobKind.BUILD in w.job_kinds for w in self.workflows)

    @property
    def has_test(self) -> bool:
        return any(JobKind.TEST in w.job_kinds for w in self.workflows)

    @property
    def has_security(self) -> bool:
        return any(JobKind.SECURITY in w.job_kinds for w in self.workflows)

    @property
    def has_deploy(self) -> bool:
        return any(w.has_deploy for w in self.workflows)

    @property
    def has_approval_gate(self) -> bool:
        return any(w.has_approval_gate for w in self.workflows)

    @property
    def has_rollback_mechanism(self) -> bool:
        return any(w.has_rollback_mechanism for w in self.workflows)

    @property
    def environments(self) -> list[str]:
        envs = {j.environment for w in self.workflows for j in w.jobs if j.environment}
        return sorted(envs)

    def to_dict(self) -> dict:
        return {
            "workflow_count": len(self.workflows),
            "workflows": [w.to_dict() for w in self.workflows],
            "has_build": self.has_build, "has_test": self.has_test,
            "has_security": self.has_security, "has_deploy": self.has_deploy,
            "has_approval_gate": self.has_approval_gate,
            "has_rollback_mechanism": self.has_rollback_mechanism,
            "environments": self.environments,
        }


class CIProviderAvailability(str, Enum):
    """Mirrors `security.models.ScannerAvailability` /
    `infra.cloud.base.CloudAdapterStatus` vocabulary on purpose - "can this
    be reached, and if not, why" means the same thing everywhere in this
    platform."""
    AVAILABLE = "AVAILABLE"
    MOCKED = "MOCKED"
    UNAVAILABLE = "UNAVAILABLE"
    BLOCKED = "BLOCKED"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"


@dataclass
class CIRun:
    provider: str
    run_id: int
    branch: str
    conclusion: CIRunConclusion
    jobs: list[dict] = field(default_factory=list)  # raw per-job {name, conclusion, steps}

    def to_dict(self) -> dict:
        d = asdict(self)
        d["conclusion"] = self.conclusion.value
        return d


@dataclass
class CIStatusResult:
    provider: str
    status: CIProviderAvailability
    reason: str
    run: Optional[CIRun] = None

    @property
    def is_real(self) -> bool:
        return self.status == CIProviderAvailability.AVAILABLE

    def to_dict(self) -> dict:
        return {
            "provider": self.provider, "status": self.status.value, "reason": self.reason,
            "is_real": self.is_real, "run": self.run.to_dict() if self.run else None,
        }
