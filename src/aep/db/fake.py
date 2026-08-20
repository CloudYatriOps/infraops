"""In-memory fake repository implementations - zero network/Postgres
dependency, used by fast unit tests. Same interfaces as db/postgres.py's
real implementations, so tests can be written once against the ABC and
run in both modes where useful."""
from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
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
    now,
)
from .repositories import (
    EventRepository,
    FailureCounterRepository,
    FindingRepository,
    LeaseRepository,
    MemoryRepository,
    ProjectLockRepository,
    ProjectRepository,
    ScheduleRepository,
    SkillRepository,
    SkillVersionRepository,
    TaskRepository,
    WorkerRepository,
)


class FakeProjectRepository(ProjectRepository):
    def __init__(self) -> None:
        self._data: dict[str, ProjectRecord] = {}

    def save(self, project: ProjectRecord) -> None:
        project.updated_at = now()
        if not project.created_at:
            project.created_at = project.updated_at
        self._data[project.id] = project

    def get(self, project_id: str) -> Optional[ProjectRecord]:
        return self._data.get(project_id)

    def list(self) -> list[ProjectRecord]:
        return list(self._data.values())


class FakeTaskRepository(TaskRepository):
    def __init__(self) -> None:
        self._data: dict[str, TaskRecord] = {}

    def save(self, task: TaskRecord) -> None:
        task.updated_at = now()
        if not task.created_at:
            task.created_at = task.updated_at
        self._data[task.id] = task

    def get(self, task_id: str) -> Optional[TaskRecord]:
        return self._data.get(task_id)

    def list(self, project_id: Optional[str] = None, status: Optional[str] = None) -> list[TaskRecord]:
        out = list(self._data.values())
        if project_id:
            out = [t for t in out if t.project_id == project_id]
        if status:
            out = [t for t in out if t.status == status]
        return out


class FakeEventRepository(EventRepository):
    def __init__(self) -> None:
        self._data: list[EventRecord] = []

    def append(self, event: EventRecord) -> None:
        if not event.timestamp:
            event.timestamp = now()
        self._data.append(event)

    def query(self, project_id: Optional[str] = None, task_id: Optional[str] = None) -> list[EventRecord]:
        out = self._data
        if project_id:
            out = [e for e in out if e.project_id == project_id]
        if task_id:
            out = [e for e in out if e.task_id == task_id]
        return list(out)


class FakeLeaseRepository(LeaseRepository):
    def __init__(self) -> None:
        self._data: dict[str, LeaseRecord] = {}

    def acquire(self, task_id: str, project_id: str, worker_id: str, ttl_seconds: float) -> bool:
        current = self._data.get(task_id)
        n = now()
        if current is not None and current.worker_id != worker_id and current.expires_at > n:
            return False
        self._data[task_id] = LeaseRecord(
            task_id=task_id, project_id=project_id, worker_id=worker_id,
            acquired_at=n, expires_at=n + timedelta(seconds=ttl_seconds),
        )
        return True

    def release(self, task_id: str, worker_id: str) -> None:
        current = self._data.get(task_id)
        if current is not None and current.worker_id == worker_id:
            del self._data[task_id]

    def list(self) -> list[LeaseRecord]:
        return list(self._data.values())


class FakeFindingRepository(FindingRepository):
    def __init__(self) -> None:
        self._data: dict[str, FindingRecord] = {}

    def save(self, finding: FindingRecord) -> None:
        finding.updated_at = now()
        if not finding.discovered_at:
            finding.discovered_at = finding.updated_at
        self._data[finding.id] = finding

    def list(self, project_id: Optional[str] = None, severity: Optional[str] = None) -> list[FindingRecord]:
        out = list(self._data.values())
        if project_id:
            out = [f for f in out if f.project_id == project_id]
        if severity:
            out = [f for f in out if f.severity == severity]
        return out


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


class FakeMemoryRepository(MemoryRepository):
    def __init__(self) -> None:
        self._data: dict[str, MemoryRecord] = {}

    def save(self, memory: MemoryRecord) -> None:
        memory.updated_at = now()
        if not memory.created_at:
            memory.created_at = memory.updated_at
        self._data[memory.id] = memory

    def retrieve(
        self,
        memory_class: Optional[str] = None,
        project_scope: Optional[str] = None,
        embedding: Optional[list[float]] = None,
        top_k: int = 5,
    ) -> list[tuple[MemoryRecord, bool]]:
        candidates = [m for m in self._data.values() if m.lifecycle_state == "ACTIVE"]
        if memory_class:
            candidates = [m for m in candidates if m.memory_class == memory_class]
        if project_scope:
            candidates = [m for m in candidates if m.project_scope == project_scope]
        if embedding is not None:
            candidates = sorted(
                (m for m in candidates if m.embedding),
                key=lambda m: -_cosine(m.embedding, embedding),
            )
        candidates = candidates[:top_k]
        return [(m, True) for m in candidates]  # always advisory

    def supersede(self, old_id: str, new_record: MemoryRecord) -> None:
        self.save(new_record)
        old = self._data.get(old_id)
        if old is not None:
            old.lifecycle_state = "SUPERSEDED"
            old.superseded_by = new_record.id
            old.updated_at = now()


class FakeProjectLockRepository(ProjectLockRepository):
    def __init__(self) -> None:
        self._data: dict[str, ProjectLockRecord] = {}

    def acquire(self, project_id: str, worker_id: str, task_id: str, ttl_seconds: float) -> bool:
        current = self._data.get(project_id)
        n = now()
        if current is not None and current.worker_id != worker_id and current.expires_at > n:
            return False
        self._data[project_id] = ProjectLockRecord(
            project_id=project_id, worker_id=worker_id, task_id=task_id,
            acquired_at=n, expires_at=n + timedelta(seconds=ttl_seconds),
        )
        return True

    def release(self, project_id: str, worker_id: str) -> None:
        current = self._data.get(project_id)
        if current is not None and current.worker_id == worker_id:
            del self._data[project_id]

    def list(self) -> list[ProjectLockRecord]:
        return list(self._data.values())


class FakeWorkerRepository(WorkerRepository):
    def __init__(self) -> None:
        self._data: dict[str, WorkerRecord] = {}

    def register(self, worker_id: str, supervisor_id: str) -> None:
        n = now()
        existing = self._data.get(worker_id)
        if existing is not None:
            existing.status = "IDLE"
            existing.last_heartbeat = n
            existing.restart_count += 1
        else:
            self._data[worker_id] = WorkerRecord(
                worker_id=worker_id, supervisor_id=supervisor_id, status="IDLE",
                last_heartbeat=n, started_at=n, restart_count=0,
            )

    def heartbeat(self, worker_id: str, status: str) -> None:
        rec = self._data.get(worker_id)
        if rec is not None:
            rec.status = status
            rec.last_heartbeat = now()

    def list(self, supervisor_id: Optional[str] = None) -> list[WorkerRecord]:
        out = list(self._data.values())
        if supervisor_id:
            out = [w for w in out if w.supervisor_id == supervisor_id]
        return out

    def remove(self, worker_id: str) -> None:
        self._data.pop(worker_id, None)


class FakeScheduleRepository(ScheduleRepository):
    def __init__(self) -> None:
        self._data: dict[str, ScheduleRecord] = {}

    def upsert(self, job_id: str, project_id: str, job_type: str,
               interval_seconds: float, next_run_at: Optional[object] = None) -> None:
        if job_id in self._data:
            return
        self._data[job_id] = ScheduleRecord(
            job_id=job_id, project_id=project_id, job_type=job_type,
            interval_seconds=interval_seconds, next_run_at=next_run_at or now(),
        )

    def due(self, now_: Optional[object] = None) -> list[ScheduleRecord]:
        n = now_ or now()
        return [s for s in self._data.values() if s.next_run_at <= n]

    def list(self) -> list[ScheduleRecord]:
        return list(self._data.values())

    def record_run(self, job_id: str, success: bool, interval_seconds: float,
                   jitter_seconds: float = 0.0) -> None:
        rec = self._data.get(job_id)
        if rec is None:
            return
        n = now()
        rec.last_run_at = n
        rec.next_run_at = n + timedelta(seconds=interval_seconds + jitter_seconds)
        if success:
            rec.last_status = "OK"
            rec.consecutive_failures = 0
        else:
            rec.last_status = "FAILED"
            rec.consecutive_failures += 1


class FakeFailureCounterRepository(FailureCounterRepository):
    def __init__(self) -> None:
        self._data: dict[tuple[str, str], list] = {}  # (project_id, task_type) -> [count, quarantined]

    def record_failure(self, project_id: str, task_type: str, threshold: int) -> bool:
        key = (project_id, task_type)
        entry = self._data.setdefault(key, [0, False])
        entry[0] += 1
        if entry[0] >= threshold:
            entry[1] = True
        return entry[1]

    def reset(self, project_id: str, task_type: str) -> None:
        self._data.pop((project_id, task_type), None)

    def is_quarantined(self, project_id: str, task_type: str) -> bool:
        entry = self._data.get((project_id, task_type))
        return bool(entry and entry[1])


class FakeSkillRepository(SkillRepository):
    def __init__(self) -> None:
        self._data: dict[str, SkillRecord] = {}

    def save(self, skill: SkillRecord) -> None:
        n = now()
        skill.updated_at = n
        if not skill.created_at:
            skill.created_at = n
        self._data[skill.skill_id] = skill

    def get(self, skill_id: str) -> Optional[SkillRecord]:
        return self._data.get(skill_id)

    def list(self) -> list[SkillRecord]:
        return list(self._data.values())


class FakeSkillVersionRepository(SkillVersionRepository):
    def __init__(self) -> None:
        self._data: dict[tuple[str, str], SkillVersionRecord] = {}

    def save(self, version: SkillVersionRecord) -> None:
        key = (version.skill_id, version.version)
        existing = self._data.get(key)
        if existing is not None and existing.lifecycle_state == "published":
            raise ValueError(
                f"skill version {version.skill_id}@{version.version} is published and immutable"
            )
        n = now()
        if not version.created_at:
            version.created_at = n
        version.id = version.id or f"{version.skill_id}:{version.version}"
        self._data[key] = version

    def get(self, skill_id: str, version: str) -> Optional[SkillVersionRecord]:
        return self._data.get((skill_id, version))

    def list_for_skill(self, skill_id: str) -> list[SkillVersionRecord]:
        return [v for (sid, _), v in self._data.items() if sid == skill_id]

    def mark_deprecated(self, skill_id: str, version: str) -> None:
        rec = self._data.get((skill_id, version))
        if rec is not None:
            rec.lifecycle_state = "deprecated"
            rec.deprecated_at = now()
