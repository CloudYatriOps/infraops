"""Repository interfaces for the Stage A persistence layer.

Two implementations exist for each interface:
  * `postgres.PostgresXRepository` - real psycopg2-backed implementation.
  * `fake.FakeXRepository` - in-memory test double, same interface,
    used by fast unit tests that must run with zero network/Postgres
    dependency.

Agent/orchestrator code should depend only on these ABCs (a later stage's
concern to actually wire up) - no raw SQL may leak past `db/postgres.py`.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from .models import (
    EventRecord,
    FindingRecord,
    LeaseRecord,
    MemoryRecord,
    ProjectLockRecord,
    ProjectRecord,
    ScheduleRecord,
    SkillRecord,
    SkillVersionRecord,
    TaskRecord,
    WorkerRecord,
)


class ProjectRepository(ABC):
    @abstractmethod
    def save(self, project: ProjectRecord) -> None: ...

    @abstractmethod
    def get(self, project_id: str) -> Optional[ProjectRecord]: ...

    @abstractmethod
    def list(self) -> list[ProjectRecord]: ...


class TaskRepository(ABC):
    @abstractmethod
    def save(self, task: TaskRecord) -> None: ...

    @abstractmethod
    def get(self, task_id: str) -> Optional[TaskRecord]: ...

    @abstractmethod
    def list(self, project_id: Optional[str] = None, status: Optional[str] = None) -> list[TaskRecord]: ...


class EventRepository(ABC):
    @abstractmethod
    def append(self, event: EventRecord) -> None: ...

    @abstractmethod
    def query(self, project_id: Optional[str] = None, task_id: Optional[str] = None) -> list[EventRecord]: ...


class LeaseRepository(ABC):
    @abstractmethod
    def acquire(self, task_id: str, project_id: str, worker_id: str, ttl_seconds: float) -> bool: ...

    @abstractmethod
    def release(self, task_id: str, worker_id: str) -> None: ...

    @abstractmethod
    def list(self) -> list[LeaseRecord]: ...


class FindingRepository(ABC):
    @abstractmethod
    def save(self, finding: FindingRecord) -> None: ...

    @abstractmethod
    def list(self, project_id: Optional[str] = None, severity: Optional[str] = None) -> list[FindingRecord]: ...


class MemoryRepository(ABC):
    @abstractmethod
    def save(self, memory: MemoryRecord) -> None: ...

    @abstractmethod
    def retrieve(
        self,
        memory_class: Optional[str] = None,
        project_scope: Optional[str] = None,
        embedding: Optional[list[float]] = None,
        top_k: int = 5,
    ) -> list[tuple[MemoryRecord, bool]]:
        """Returns (record, advisory_flag) pairs. `advisory_flag` is
        ALWAYS True - the memory layer never claims authority over a
        caller's decision; it only ever hands back candidate context for
        the caller to weigh alongside current evidence. Retrieval must
        never mutate any decision state itself."""
        ...

    @abstractmethod
    def supersede(self, old_id: str, new_record: MemoryRecord) -> None:
        """Marks `old_id` SUPERSEDED and points it at `new_record.id` -
        never deletes the old row (audit trail preserved)."""
        ...


class ProjectLockRepository(ABC):
    """Per-project mutating-work lock: at most one worker may hold the
    lock for a given project_id at a time. Mirrors `LeaseRepository`'s
    interface shape/semantics but keyed by project_id instead of
    task_id, matching `StateStore.acquire_project_lock`'s behavior:
    the same worker may re-acquire/renew (idempotent), a different
    worker is refused while a non-expired lock is held by someone
    else, and an expired lock may be taken over by anyone."""

    @abstractmethod
    def acquire(self, project_id: str, worker_id: str, task_id: str, ttl_seconds: float) -> bool: ...

    @abstractmethod
    def release(self, project_id: str, worker_id: str) -> None: ...

    @abstractmethod
    def list(self) -> list[ProjectLockRecord]: ...


class WorkerRepository(ABC):
    """Runtime worker registration/heartbeat bookkeeping, mirroring
    `StateStore.register_worker`/`heartbeat_worker`/`list_workers`/
    `remove_worker` (Phase 8's `runtime_workers` table concept)."""

    @abstractmethod
    def register(self, worker_id: str, supervisor_id: str) -> None:
        """Insert a new worker as IDLE, or if already known, reset to
        IDLE and bump restart_count (matches StateStore.register_worker's
        ON CONFLICT ... restart_count+1 semantics)."""
        ...

    @abstractmethod
    def heartbeat(self, worker_id: str, status: str) -> None: ...

    @abstractmethod
    def list(self, supervisor_id: Optional[str] = None) -> list[WorkerRecord]: ...

    @abstractmethod
    def remove(self, worker_id: str) -> None: ...


class ScheduleRepository(ABC):
    """Durable recurring-job schedule, mirroring `StateStore.upsert_schedule`/
    `due_schedules`/`list_schedules`/`record_schedule_run` (Phase 8's
    `runtime_schedules` table concept). `upsert` must be a true
    insert-if-unseen: it must NEVER reset `next_run_at` of a job that
    already exists (so a restart never re-fires a schedule early or
    duplicates it)."""

    @abstractmethod
    def upsert(self, job_id: str, project_id: str, job_type: str,
               interval_seconds: float, next_run_at: Optional[object] = None) -> None: ...

    @abstractmethod
    def due(self, now_: Optional[object] = None) -> list[ScheduleRecord]: ...

    @abstractmethod
    def list(self) -> list[ScheduleRecord]: ...

    @abstractmethod
    def record_run(self, job_id: str, success: bool, interval_seconds: float,
                   jitter_seconds: float = 0.0) -> None: ...


class FailureCounterRepository(ABC):
    """Circuit-breaker consecutive-failure/quarantine bookkeeping,
    mirroring `StateStore.record_failure`/`reset_failure_counter`/
    `is_quarantined`, backed by the `failure_counters` table added in
    migration 0003."""

    @abstractmethod
    def record_failure(self, project_id: str, task_type: str, threshold: int) -> bool:
        """Increment consecutive-failure counter; returns True if the
        counter has now reached/exceeded `threshold` (and marks the
        row quarantined)."""
        ...

    @abstractmethod
    def reset(self, project_id: str, task_type: str) -> None: ...

    @abstractmethod
    def is_quarantined(self, project_id: str, task_type: str) -> bool: ...


class SkillRepository(ABC):
    """Stable skill-identity rows (Stage B Part 3). `save` is get-or-create
    only via `SkillRegistry.register_skill` - this ABC itself does not
    forbid an update, but nothing in the platform calls `save` twice for
    the same `skill_id` with different content; identity metadata is
    expected to be stable."""

    @abstractmethod
    def save(self, skill: SkillRecord) -> None: ...

    @abstractmethod
    def get(self, skill_id: str) -> Optional[SkillRecord]: ...

    @abstractmethod
    def list(self) -> list[SkillRecord]: ...


class SkillVersionRepository(ABC):
    """Immutable published skill version rows (Stage B Part 3/4). `save`
    must be a true INSERT of a NEW (skill_id, version) row - never an
    UPDATE of an existing one. The real Postgres implementation enforces
    this both at the application layer (`ON CONFLICT DO NOTHING` +
    rowcount check, raising if the row already existed) and at the
    database layer (a trigger rejects any UPDATE that changes a published
    row's content - see migration 0006)."""

    @abstractmethod
    def save(self, version: SkillVersionRecord) -> None: ...

    @abstractmethod
    def get(self, skill_id: str, version: str) -> Optional[SkillVersionRecord]: ...

    @abstractmethod
    def list_for_skill(self, skill_id: str) -> list[SkillVersionRecord]: ...

    @abstractmethod
    def mark_deprecated(self, skill_id: str, version: str) -> None: ...
