"""Deployment data model (Phase 6 Part 6/13).

`DeploymentRecord` is the durable evidence unit Part 13 asks for: "task
ID, commit SHA, artifact, environment, release gates, approval,
deployment start/end, rollout status, verification results, rollback
status, final state." It is persisted the same way every other durable
fact in this platform is persisted - as an `Event` appended to the
EXISTING `StateStore` (see `evidence.py`) - not a new database file, so it
survives a process restart for free (Part 13's requirement) using
machinery Phase 1 already made durable and crash-safe.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class DeploymentState(str, Enum):
    """The full lifecycle named in the Phase 6 objective, plus the states
    every deployment attempt must be classifiable into at any point in
    time. `PLANNED` is this module's own addition (before `DEPLOYED`) so a
    deployment that policy blocked before ever running has a state other
    than one implying it happened."""
    PLANNED = "PLANNED"
    APPROVAL_PENDING = "APPROVAL_PENDING"
    DEPLOYED = "DEPLOYED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    BLOCKED = "BLOCKED"  # policy or release-gate denial - never attempted


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class VerificationCheck:
    name: str
    passed: bool
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DeploymentRecord:
    task_id: str
    commit_sha: str
    artifact_id: str
    environment: str
    release_gates_passed: bool
    approval_status: str  # "not_required" | "pending" | "granted" | "denied"
    provider: str
    provider_status: str  # REAL | MOCKED | UNAVAILABLE | BLOCKED - see provider.py
    started_at: str = field(default_factory=_now)
    ended_at: Optional[str] = None
    rollout_status: str = "NOT_STARTED"
    verification_results: list[VerificationCheck] = field(default_factory=list)
    rollback_status: str = "NOT_ATTEMPTED"
    final_state: DeploymentState = DeploymentState.PLANNED
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["final_state"] = self.final_state.value
        d["verification_results"] = [v.to_dict() for v in self.verification_results]
        return d

    @staticmethod
    def from_dict(d: dict) -> "DeploymentRecord":
        d = dict(d)
        d["final_state"] = DeploymentState(d["final_state"])
        d["verification_results"] = [VerificationCheck(**v) for v in d.get("verification_results", [])]
        return DeploymentRecord(**d)
