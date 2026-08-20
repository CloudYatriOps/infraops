"""Worker lifecycle (Phase 8 Part 1/2/3).

A Worker claims exactly one task at a time via a durable lease
(`StateStore.acquire_lease`), and if the task is a mutating one for a
project, ALSO acquires the durable per-project lock
(`StateStore.acquire_project_lock`) so two workers never mutate the same
repo concurrently. Heartbeats are written to the same durable store the
supervisor's watchdog reads (`health.py`), so a crashed worker is
detectable and its lease/lock eventually expire safely.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Callable, Optional

from ..state_store import StateStore

MUTATING_JOB_TYPES = {
    "code_modification", "dependency_upgrade", "git_commit",
    "infrastructure_mutation", "deployment",
}


@dataclass
class ClaimResult:
    claimed: bool
    reason: str


class Worker:
    """One worker in the pool. `run_once` claims at most one due job/task
    and executes it via the supplied dispatch callable."""

    def __init__(self, supervisor_id: str, store: StateStore, lease_ttl_s: float = 30.0,
                 worker_id: Optional[str] = None):
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex[:8]}"
        self.supervisor_id = supervisor_id
        self.store = store
        self.lease_ttl_s = lease_ttl_s
        self.store.register_worker(self.worker_id, supervisor_id)

    def heartbeat(self, status: str = "IDLE") -> None:
        self.store.heartbeat_worker(self.worker_id, status)

    def claim_task(self, job: dict) -> ClaimResult:
        """Attempt to durably claim one job/task. Enforces:
          - no duplicate execution (lease)
          - one mutating workflow at a time per project (project lock, only
            for job types classified as mutating)
        """
        task_id = job["job_id"]
        project_id = job["project_id"]
        if not self.store.acquire_lease(task_id, project_id, self.worker_id, self.lease_ttl_s):
            return ClaimResult(False, "lease held by another worker")
        if job.get("job_type") in MUTATING_JOB_TYPES:
            if not self.store.acquire_project_lock(project_id, self.worker_id, task_id, self.lease_ttl_s):
                self.store.release_lease(task_id, self.worker_id)
                return ClaimResult(False, "project lock held by another worker")
        return ClaimResult(True, "claimed")

    def release_task(self, job: dict) -> None:
        task_id = job["job_id"]
        project_id = job["project_id"]
        self.store.release_lease(task_id, self.worker_id)
        if job.get("job_type") in MUTATING_JOB_TYPES:
            self.store.release_project_lock(project_id, self.worker_id)

    def run_once(self, job: dict, dispatch: Callable[[dict], object]) -> Optional[object]:
        self.heartbeat("BUSY")
        claim = self.claim_task(job)
        if not claim.claimed:
            self.heartbeat("IDLE")
            return None
        try:
            self.store.renew_lease(job["job_id"], self.worker_id, self.lease_ttl_s)
            result = dispatch(job)
            return result
        finally:
            self.release_task(job)
            self.heartbeat("IDLE")

    def shutdown(self) -> None:
        """Graceful shutdown: release anything held, mark stopped."""
        self.heartbeat("STOPPED")
