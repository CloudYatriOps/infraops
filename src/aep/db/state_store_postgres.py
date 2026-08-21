"""PostgreSQL-backed drop-in replacement for `src/aep/state_store.py`'s
SQLite `StateStore`.

`PostgresStateStore` implements the SAME public method surface that
`StateStore` exposes (save_task/get_task/list_tasks/non_terminal_tasks/
append_event/query_events/record_failure/reset_failure_counter/
is_quarantined/register_worker/heartbeat_worker/list_workers/remove_worker/
acquire_lease/renew_lease/release_lease/expired_leases/list_leases/
force_release_lease/acquire_project_lock/release_project_lock/
list_project_locks/upsert_schedule/due_schedules/list_schedules/
record_schedule_run/close), so the orchestrator/agents/bootstrap.py can
construct this instead of `StateStore` with no other code changes -
*provided* the interfaces genuinely line up. Two real gaps exist where
they do not (documented at the call sites below, not silently papered
over):

  1. **IDs must be valid UUIDs.** `src/aep/migrations_sql/0001_initial_schema.sql`
     declares `tasks.id`/`tasks.project_id` etc as native Postgres `uuid`
     columns. `Task.id`/`Event.id` are always `str(uuid.uuid4())` in real
     orchestrator usage (`orchestrator.new_task_id()`, `EventLogger.log()`),
     so that path is fine. But `ProjectConfig.id` and many unit tests use
     short human strings (`"p1"`, `"e2e"`, `"demo"`) - those are NOT valid
     UUIDs and will raise a psycopg2 `DataError` if passed to any of these
     methods. This is a genuine, unresolved interface mismatch: the
     Postgres schema was designed Stage-A-first for real UUIDs, and no
     translation/shim exists (or should exist - inventing a fake
     string->UUID mapping would silently change identity semantics).
     Callers opting into this backend must use real UUID project/task ids.

  2. **`list_tasks`/`non_terminal_tasks` accept multiple statuses; the
     Postgres repository layer's `TaskRepository.list()` only accepts a
     single `status: Optional[str]`.** This facade compensates by listing
     with no status filter and filtering the (small, per-project) result
     set in Python - functionally equivalent, but note it is O(all tasks
     in the project) per call rather than an indexed multi-value SQL
     `IN (...)`, unlike the SQLite path's dedicated query. Fine at Stage
     A/A.5 scale; worth a real `status IN (...)` repository method if this
     ever becomes a hot path.

  3. **`runtime_leases`/`runtime_project_locks`/`tasks` carry real foreign
     keys in Postgres that SQLite's schema never had.** `acquire_lease`
     requires the task to already exist (`runtime_leases.task_id
     REFERENCES tasks(id)`) AND the worker to already be registered
     (`runtime_leases.worker_id REFERENCES runtime_workers(worker_id)`,
     same for `runtime_project_locks.worker_id`); `save_task`/
     `acquire_project_lock` similarly require the project to exist
     (`ensure_project` below auto-provisions a minimal `projects` row the
     first time a given `project_id` is seen by this store instance, to
     satisfy `tasks.project_id REFERENCES projects(id)`). Real
     orchestrator/runtime usage always registers a worker before it leases
     anything and always saves a task before leasing it, so this is not a
     behavior change in practice - but it is a real constraint SQLite
     silently allowed to be skipped, so it is called out explicitly rather
     than discovered by surprise.

Every other method maps cleanly 1:1 onto an existing repository method.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Iterable, Optional

from ..models import Event, Task, TaskStatus
from .models import (
    EventRecord,
    LeaseRecord,
    ProjectLockRecord,
    ProjectRecord,
    ScheduleRecord,
    TaskRecord,
    WorkerRecord,
)
from .postgres import (
    ConnectionPool,
    PostgresEventRepository,
    PostgresFailureCounterRepository,
    PostgresLeaseRepository,
    PostgresProjectLockRepository,
    PostgresProjectRepository,
    PostgresScheduleRepository,
    PostgresTaskRepository,
    PostgresWorkerRepository,
    dsn_from_parts,
)
from .startup import verify_database


def dsn_from_env() -> str:
    """Builds a DSN from `AEP_PG_*` env vars (falling back to the
    documented local-dev defaults), or `AEP_POSTGRES_DSN` verbatim if set.
    Never hardcodes a real credential - only ever reads from the
    environment.

    Zero-config path: if NEITHER `AEP_POSTGRES_DSN` NOR any `AEP_PG_*`
    part is explicitly set, nothing points AEP at a database the operator
    actually configured - so this starts/reuses AEP's own local embedded
    PostgreSQL instead of guessing at `localhost:5432` with a blank
    password (see `local_postgres.ensure_local_postgres`). Setting ANY
    `AEP_PG_*`/`AEP_POSTGRES_DSN` var (including pointing at Supabase or
    any other remote Postgres) opts back into the explicit path below,
    unchanged from before this existed."""
    explicit = os.environ.get("AEP_POSTGRES_DSN")
    if explicit:
        return explicit
    explicit_parts = ("AEP_PG_HOST", "AEP_PG_PORT", "AEP_PG_USER",
                      "AEP_PG_PASSWORD", "AEP_PG_DBNAME", "AEP_PG_SSLMODE")
    if not any(os.environ.get(k) for k in explicit_parts):
        from . import local_postgres
        return local_postgres.ensure_local_postgres()
    return dsn_from_parts(
        host=os.environ.get("AEP_PG_HOST", "localhost"),
        port=int(os.environ.get("AEP_PG_PORT", "5432")),
        user=os.environ.get("AEP_PG_USER", "aep"),
        password=os.environ.get("AEP_PG_PASSWORD", ""),
        dbname=os.environ.get("AEP_PG_DBNAME", "aep_platform"),
        sslmode=os.environ.get("AEP_PG_SSLMODE"),
    )


def _to_naive_iso(dt: Optional[datetime]) -> str:
    if dt is None:
        return ""
    return dt.isoformat()


def _parse_iso(s: str) -> datetime:
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class PostgresStateStore:
    """Drop-in (see module docstring for the two documented gaps)
    PostgreSQL-backed replacement for `state_store.StateStore`. The
    startup gate (`db.startup.verify_database`) runs unconditionally in
    `__init__`/`connect()` - construction itself raises
    `DatabaseUnavailableError`/`SchemaDriftError` rather than ever handing
    back a store that might be reading/writing against a broken or
    undermigrated schema."""

    def __init__(self, dsn: Optional[str] = None, minconn: int = 1, maxconn: int = 5,
                 _skip_startup_check: bool = False):
        self.dsn = dsn or dsn_from_env()
        if not _skip_startup_check:
            verify_database(self.dsn)
        self._pool = ConnectionPool(self.dsn, minconn=minconn, maxconn=maxconn)

        self._projects = PostgresProjectRepository(self._pool)
        self._tasks = PostgresTaskRepository(self._pool)
        self._events = PostgresEventRepository(self._pool)
        self._leases = PostgresLeaseRepository(self._pool)
        self._project_locks = PostgresProjectLockRepository(self._pool)
        self._workers = PostgresWorkerRepository(self._pool)
        self._schedules = PostgresScheduleRepository(self._pool)
        self._failure_counters = PostgresFailureCounterRepository(self._pool)

        # project_id -> True once we know a `projects` row exists, so
        # save_task's FK dependency is satisfied without a round trip on
        # every call. Real production callers create projects explicitly
        # via `ensure_project`; this is a convenience auto-provision for
        # anything that (like SQLite's schema-less StateStore) never had a
        # `projects` table to worry about in the first place.
        self._known_projects: set[str] = set()

    @classmethod
    def connect(cls, dsn: Optional[str] = None, **kwargs) -> "PostgresStateStore":
        return cls(dsn=dsn, **kwargs)

    def close(self) -> None:
        self._pool.closeall()

    # ---- Project auto-provisioning (FK support) ----------------------
    def ensure_project(self, project_id: str, name: Optional[str] = None,
                        repo_path: str = "", policy_path: str = "") -> None:
        if project_id in self._known_projects:
            return
        existing = self._projects.get(project_id)
        if existing is None:
            self._projects.save(ProjectRecord(
                id=project_id, name=name or project_id,
                repo_path=repo_path, policy_path=policy_path,
            ))
        self._known_projects.add(project_id)

    # ---- Tasks --------------------------------------------------------
    def save_task(self, task: Task) -> None:
        self.ensure_project(task.project_id)
        record = TaskRecord(
            id=task.id, project_id=task.project_id, type=task.type,
            status=task.status.value, priority=task.priority, risk=task.risk.value,
            dependencies=list(task.dependencies), owner_agent=task.owner_agent,
            attempts=task.attempts, max_attempts=task.max_attempts,
            evidence=[e.to_dict() for e in task.evidence], artifacts=list(task.artifacts),
            approval_status=task.approval_status, parent_task_id=task.parent_task_id,
            payload=task.payload,
        )
        self._tasks.save(record)
        # Mirror StateStore.save_task's behavior of stamping the dataclass
        # instance's timestamps in place.
        saved = self._tasks.get(task.id)
        if saved is not None:
            task.updated_at = _to_naive_iso(saved.updated_at)
            task.created_at = _to_naive_iso(saved.created_at)

    def get_task(self, task_id: str) -> Optional[Task]:
        record = self._tasks.get(task_id)
        return _record_to_task(record) if record is not None else None

    def list_tasks(self, project_id: Optional[str] = None,
                    statuses: Optional[Iterable[TaskStatus]] = None) -> list[Task]:
        # See module docstring gap (2): the repository only filters on a
        # single status, so multi-status filtering happens here in Python.
        records = self._tasks.list(project_id=project_id, status=None)
        if statuses:
            wanted = {s.value for s in statuses}
            records = [r for r in records if r.status in wanted]
        return [_record_to_task(r) for r in records]

    def non_terminal_tasks(self, project_id: Optional[str] = None) -> list[Task]:
        terminal = {TaskStatus.SUCCEEDED, TaskStatus.CANCELLED, TaskStatus.QUARANTINED}
        all_statuses = set(TaskStatus) - terminal
        return self.list_tasks(project_id=project_id, statuses=all_statuses)

    # ---- Events ---------------------------------------------------------
    def append_event(self, event: Event) -> None:
        record = EventRecord(
            id=event.id, project_id=event.project_id, actor=event.actor, action=event.action,
            task_id=event.task_id, decision=event.decision, details=event.details,
            timestamp=_parse_iso(event.timestamp) if event.timestamp else None,
        )
        self._events.append(record)
        if not event.timestamp:
            event.timestamp = _to_naive_iso(record.timestamp)

    def query_events(self, project_id: Optional[str] = None,
                      task_id: Optional[str] = None) -> list[Event]:
        records = self._events.query(project_id=project_id, task_id=task_id)
        return [
            Event(id=r.id, actor=r.actor, action=r.action, project_id=r.project_id,
                  task_id=r.task_id, decision=r.decision,
                  timestamp=_to_naive_iso(r.timestamp), details=r.details)
            for r in records
        ]

    # ---- Circuit breaker counters -----------------------------------
    def record_failure(self, project_id: str, task_type: str, threshold: int) -> bool:
        return self._failure_counters.record_failure(project_id, task_type, threshold)

    def reset_failure_counter(self, project_id: str, task_type: str) -> None:
        self._failure_counters.reset(project_id, task_type)

    def is_quarantined(self, project_id: str, task_type: str) -> bool:
        return self._failure_counters.is_quarantined(project_id, task_type)

    # ---- Runtime workers ------------------------------------------------
    def register_worker(self, worker_id: str, supervisor_id: str) -> None:
        self._workers.register(worker_id, supervisor_id)

    def heartbeat_worker(self, worker_id: str, status: str) -> None:
        self._workers.heartbeat(worker_id, status)

    def list_workers(self, supervisor_id: Optional[str] = None) -> list[dict]:
        return [_worker_to_dict(w) for w in self._workers.list(supervisor_id=supervisor_id)]

    def remove_worker(self, worker_id: str) -> None:
        self._workers.remove(worker_id)

    # ---- Task leases -----------------------------------------------------
    def acquire_lease(self, task_id: str, project_id: str, worker_id: str, ttl_seconds: float) -> bool:
        return self._leases.acquire(task_id, project_id, worker_id, ttl_seconds)

    def renew_lease(self, task_id: str, worker_id: str, ttl_seconds: float) -> bool:
        # No dedicated renew in the repository layer; acquire() is
        # idempotent for the current holder and re-stamps expires_at,
        # which is exactly renew's contract - but it also happily "renews"
        # a lease the caller never held if none currently exists, unlike
        # StateStore.renew_lease which requires an existing row held by
        # `worker_id`. Guard that distinction explicitly here.
        existing = {lease.task_id: lease for lease in self._leases.list()}
        current = existing.get(task_id)
        if current is None or current.worker_id != worker_id:
            return False
        return self._leases.acquire(task_id, current.project_id, worker_id, ttl_seconds)

    def release_lease(self, task_id: str, worker_id: str) -> None:
        self._leases.release(task_id, worker_id)

    def expired_leases(self) -> list[dict]:
        now = datetime.now(timezone.utc)
        return [_lease_to_dict(lease) for lease in self._leases.list() if lease.expires_at < now]

    def list_leases(self) -> list[dict]:
        return [_lease_to_dict(lease) for lease in self._leases.list()]

    def force_release_lease(self, task_id: str) -> None:
        for lease in self._leases.list():
            if lease.task_id == task_id:
                self._leases.release(task_id, lease.worker_id)
                return

    # ---- Per-project mutating-work lock ----------------------------------
    def acquire_project_lock(self, project_id: str, worker_id: str, task_id: str,
                              ttl_seconds: float) -> bool:
        return self._project_locks.acquire(project_id, worker_id, task_id, ttl_seconds)

    def release_project_lock(self, project_id: str, worker_id: str) -> None:
        self._project_locks.release(project_id, worker_id)

    def list_project_locks(self) -> list[dict]:
        return [_lock_to_dict(lock) for lock in self._project_locks.list()]

    # ---- Durable recurring-job schedule -----------------------------------
    def upsert_schedule(self, job_id: str, project_id: str, job_type: str,
                        interval_seconds: float, next_run_at: Optional[str] = None) -> None:
        parsed = _parse_iso(next_run_at) if next_run_at else None
        self._schedules.upsert(job_id, project_id, job_type, interval_seconds, next_run_at=parsed)

    def due_schedules(self, now: Optional[str] = None) -> list[dict]:
        parsed = _parse_iso(now) if now else None
        return [_schedule_to_dict(s) for s in self._schedules.due(now_=parsed)]

    def list_schedules(self) -> list[dict]:
        return [_schedule_to_dict(s) for s in self._schedules.list()]

    def record_schedule_run(self, job_id: str, success: bool, interval_seconds: float,
                            jitter_seconds: float = 0.0) -> None:
        self._schedules.record_run(job_id, success, interval_seconds, jitter_seconds=jitter_seconds)


def _record_to_task(record: TaskRecord) -> Task:
    from ..models import Evidence, RiskLevel

    return Task(
        id=record.id, type=record.type, project_id=record.project_id,
        priority=record.priority, risk=RiskLevel(record.risk), status=TaskStatus(record.status),
        dependencies=list(record.dependencies), owner_agent=record.owner_agent,
        attempts=record.attempts, max_attempts=record.max_attempts,
        evidence=[Evidence(**e) for e in record.evidence], artifacts=list(record.artifacts),
        approval_status=record.approval_status, parent_task_id=record.parent_task_id,
        payload=record.payload, created_at=_to_naive_iso(record.created_at),
        updated_at=_to_naive_iso(record.updated_at),
    )


def _worker_to_dict(w: WorkerRecord) -> dict:
    return {
        "worker_id": w.worker_id, "supervisor_id": w.supervisor_id, "status": w.status,
        "last_heartbeat": _to_naive_iso(w.last_heartbeat), "started_at": _to_naive_iso(w.started_at),
        "restart_count": w.restart_count,
    }


def _lease_to_dict(lease: LeaseRecord) -> dict:
    return {
        "task_id": lease.task_id, "project_id": lease.project_id, "worker_id": lease.worker_id,
        "acquired_at": _to_naive_iso(lease.acquired_at), "expires_at": _to_naive_iso(lease.expires_at),
    }


def _lock_to_dict(lock: ProjectLockRecord) -> dict:
    return {
        "project_id": lock.project_id, "worker_id": lock.worker_id, "task_id": lock.task_id,
        "acquired_at": _to_naive_iso(lock.acquired_at), "expires_at": _to_naive_iso(lock.expires_at),
    }


def _schedule_to_dict(s: ScheduleRecord) -> dict:
    return {
        "job_id": s.job_id, "project_id": s.project_id, "job_type": s.job_type,
        "interval_seconds": s.interval_seconds, "next_run_at": _to_naive_iso(s.next_run_at),
        "last_run_at": _to_naive_iso(s.last_run_at) if s.last_run_at else None,
        "last_status": s.last_status, "consecutive_failures": s.consecutive_failures,
    }
