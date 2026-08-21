"""Postgres-API-agnostic domain models for the Stage A persistence layer.

These are plain dataclasses - no psycopg2/SQL import here, so agent/
orchestrator code (once a later stage wires it up) can depend only on
these types and a Repository interface, never on raw SQL.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


def new_id() -> str:
    return str(uuid.uuid4())


def now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class ProjectRecord:
    id: str
    name: str
    repo_path: str
    policy_path: str
    default_posture: str = "deny"
    protected_branches: list[str] = field(default_factory=lambda: ["main", "master"])
    token_budget: Optional[int] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    # Migration 0008: "Delete Project" in the UI archives rather than
    # hard-deletes (tasks/findings/events reference projects.id with no
    # CASCADE, and scan history must never be blindly destroyed) - NULL
    # means active, same as every project created before this column
    # existed.
    archived_at: Optional[datetime] = None


@dataclass
class TaskRecord:
    id: str
    project_id: str
    type: str
    status: str = "PENDING"
    priority: int = 5
    risk: str = "low"
    dependencies: list[str] = field(default_factory=list)
    owner_agent: Optional[str] = None
    attempts: int = 0
    max_attempts: int = 3
    evidence: list[dict] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    approval_status: Optional[str] = None
    parent_task_id: Optional[str] = None
    payload: dict = field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


@dataclass
class EventRecord:
    id: str
    project_id: str
    actor: str
    action: str
    task_id: Optional[str] = None
    decision: Optional[str] = None
    details: dict = field(default_factory=dict)
    timestamp: Optional[datetime] = None


@dataclass
class LeaseRecord:
    task_id: str
    project_id: str
    worker_id: str
    acquired_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None


@dataclass
class FindingRecord:
    id: str
    project_id: str
    category: str
    severity: str
    status: str = "OPEN"
    resource: Optional[str] = None
    description: str = ""
    confidence: Optional[str] = None
    false_positive: bool = False
    task_id: Optional[str] = None
    evidence: dict = field(default_factory=dict)
    discovered_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


@dataclass
class MemoryRecord:
    """One row of the Stage A memory table. `advisory` is always True on
    anything returned from retrieval - callers must weigh it themselves;
    the memory layer never mutates a caller's decision (see
    MemoryRepository.retrieve's docstring)."""
    id: str
    memory_class: str
    source: str
    content: dict = field(default_factory=dict)
    project_scope: Optional[str] = None
    org_scope: Optional[str] = None  # deferred - no orgs modeled in Stage A
    embedding: Optional[list[float]] = None
    fingerprint: Optional[str] = None
    evidence_ref: Optional[str] = None
    confidence: float = 0.5
    lifecycle_state: str = "ACTIVE"
    superseded_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


@dataclass
class WorkerRecord:
    worker_id: str
    supervisor_id: str
    status: str = "IDLE"
    last_heartbeat: Optional[datetime] = None
    started_at: Optional[datetime] = None
    restart_count: int = 0


@dataclass
class ProjectLockRecord:
    project_id: str
    worker_id: str
    task_id: str
    acquired_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None


@dataclass
class ScheduleRecord:
    job_id: str
    project_id: str
    job_type: str
    interval_seconds: float
    next_run_at: Optional[datetime] = None
    last_run_at: Optional[datetime] = None
    last_status: Optional[str] = None
    consecutive_failures: int = 0


@dataclass
class SkillRecord:
    """Stable identity row for a canonical AEP skill (Stage B Part 1/3).
    Mirrors `skills.models.Skill` - a thin dataclass with no SQL/AI
    dependency of its own; `SkillRegistry` is what enforces meaning."""
    skill_id: str
    name: str
    description: str = ""
    purpose: str = ""
    scope: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


@dataclass
class SkillDependencyRecord:
    depends_on_skill_id: str
    version_constraint: str = "*"


@dataclass
class SkillVersionRecord:
    """One immutable, published snapshot of a skill's procedure. Mirrors
    `skills.models.SkillVersion`. `id` is the row's own uuid; identity for
    lookup purposes is the (skill_id, version) pair, unique-constrained at
    the DB level."""
    skill_id: str
    version: str
    risk_level: str = "low"
    description: str = ""
    purpose: str = ""
    scope: str = ""
    capabilities: list[str] = field(default_factory=list)
    allowed_tools: list[str] = field(default_factory=list)
    prohibited_actions: list[str] = field(default_factory=list)
    required_checks: list[str] = field(default_factory=list)
    verification_rules: list[str] = field(default_factory=list)
    dependencies: list[SkillDependencyRecord] = field(default_factory=list)
    escalation_rules: list[str] = field(default_factory=list)
    approval_requirements: list[str] = field(default_factory=list)
    input_contract: dict = field(default_factory=dict)
    output_contract: dict = field(default_factory=dict)
    examples: list[dict] = field(default_factory=list)
    lifecycle_state: str = "draft"
    compatibility_metadata: dict = field(default_factory=dict)
    id: Optional[str] = None
    created_at: Optional[datetime] = None
    published_at: Optional[datetime] = None
    deprecated_at: Optional[datetime] = None


MEMORY_CLASSES = (
    "PROJECT_MEMORY",
    "ENGINEERING_MEMORY",
    "SECURITY_MEMORY",
    "OPERATIONAL_MEMORY",
    "ARCHITECTURAL_MEMORY",
    "USER_ORG_MEMORY",
)
