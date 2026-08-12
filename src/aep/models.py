"""Core data model for the platform.

These are plain dataclasses persisted (as JSON-serializable dicts) by
StateStore. Keeping them free of any storage or provider dependency is what
lets tests construct them without a database.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class TaskStatus(str, Enum):
    PENDING = "PENDING"
    READY = "READY"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    RETRY_SCHEDULED = "RETRY_SCHEDULED"
    BLOCKED_ON_APPROVAL = "BLOCKED_ON_APPROVAL"
    CANCELLED = "CANCELLED"
    QUARANTINED = "QUARANTINED"

    @property
    def is_terminal(self) -> bool:
        return self in (
            TaskStatus.SUCCEEDED,
            TaskStatus.CANCELLED,
            TaskStatus.QUARANTINED,
        )


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class PolicyDecisionType(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    WARN = "WARN"


class FailureClass(str, Enum):
    TRANSIENT = "TRANSIENT"
    AUTH = "AUTH"
    SECURITY = "SECURITY"
    CODE = "CODE"
    TEST = "TEST"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    MODEL = "MODEL"
    TOOL = "TOOL"
    HUMAN_REQUIRED = "HUMAN_REQUIRED"
    # Phase 6 additions (CI/CD & Deployment Intelligence). Additive only -
    # every member above is unchanged and every existing `classify()`
    # branch/behavior is untouched. These distinguish CI/deployment failure
    # modes that Phase 1-5's classes were never asked to separate: a failed
    # `pip install` in a build step is not the same actionable problem as a
    # failed `pytest` step (TEST, already existed) or a Terraform apply
    # failure (INFRASTRUCTURE, already existed). See
    # `cicd/failure_classification.py` for where these are actually
    # produced - CI/deployment classification is signal-shape-based (job
    # name, step name, log text), same discipline as `failure.classify()`,
    # never "ask the model what went wrong."
    DEPENDENCY = "DEPENDENCY"              # dependency resolution/install failed
    BUILD = "BUILD"                        # compile/package/image build failed
    CI_CONFIGURATION = "CI_CONFIGURATION"  # bad workflow YAML, missing secret, runner mismatch
    DEPLOYMENT = "DEPLOYMENT"              # the deploy step itself failed (apply/rollout)
    HEALTH = "HEALTH"                      # post-deploy health/readiness check failed
    NETWORK = "NETWORK"                    # DNS/connectivity failure distinct from a 5xx
    EXTERNAL_SERVICE = "EXTERNAL_SERVICE"  # a third-party dependency (registry, SaaS) is down
    FLAKY = "FLAKY"                        # same job failed then passed with no code change
    UNKNOWN = "UNKNOWN"                    # no signal matched anything above - never guessed


def _json_default(o: Any) -> Any:
    if isinstance(o, Enum):
        return o.value
    raise TypeError(f"not JSON serializable: {o!r}")


@dataclass
class Evidence:
    source: str  # e.g. "pytest", "secret-scanner", "git"
    captured_at: str
    exit_code: Optional[int]
    summary: str
    raw_output_ref: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Task:
    id: str
    type: str
    project_id: str
    priority: int = 5
    risk: RiskLevel = RiskLevel.LOW
    status: TaskStatus = TaskStatus.PENDING
    dependencies: list[str] = field(default_factory=list)
    owner_agent: Optional[str] = None
    attempts: int = 0
    max_attempts: int = 3
    evidence: list[Evidence] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    approval_status: Optional[str] = None
    parent_task_id: Optional[str] = None
    payload: dict = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""

    def to_json(self) -> str:
        d = asdict(self)
        d["status"] = self.status.value
        d["risk"] = self.risk.value
        d["evidence"] = [e.to_dict() for e in self.evidence]
        return json.dumps(d, default=_json_default)

    @staticmethod
    def from_json(s: str) -> "Task":
        d = json.loads(s)
        d["status"] = TaskStatus(d["status"])
        d["risk"] = RiskLevel(d["risk"])
        d["evidence"] = [Evidence(**e) for e in d.get("evidence", [])]
        return Task(**d)


@dataclass
class TaskResult:
    success: bool
    evidence: list[Evidence] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    follow_up_tasks: list["Task"] = field(default_factory=list)
    failure_class: Optional[FailureClass] = None
    message: str = ""


@dataclass
class PolicyDecision:
    action: str
    decision: PolicyDecisionType
    matched_rule: Optional[str]
    reason: str


@dataclass
class Event:
    id: str
    actor: str
    action: str
    project_id: str
    task_id: Optional[str]
    decision: Optional[str]
    timestamp: str
    details: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=_json_default)

    @staticmethod
    def from_json(s: str) -> "Event":
        return Event(**json.loads(s))


@dataclass
class ProjectConfig:
    id: str
    name: str
    repo_path: str
    policy_path: str
    default_posture: str = "deny"  # "allow" | "deny" when no rule matches
    protected_branches: list[str] = field(default_factory=lambda: ["main", "master"])
    token_budget: Optional[int] = None
