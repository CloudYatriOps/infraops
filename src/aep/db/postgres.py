"""PostgreSQL-backed repository implementations (psycopg2).

This is the ONLY module in the platform allowed to hold raw SQL for these
aggregates (migrations.py holds the DDL-only exception for schema
mutation itself - see its module docstring). Everything here is DML
(SELECT/INSERT/UPDATE) against the schema `supabase/migrations/` defines;
no schema-mutating DDL literal appears in this file,
enforced by the same lint test that scans the rest of src/aep/.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Optional

import psycopg2
import psycopg2.extras
from psycopg2.pool import SimpleConnectionPool

try:
    from pgvector.psycopg2 import register_vector
except ImportError:  # pragma: no cover - pgvector package always installed here
    register_vector = None

import uuid

from .models import (
    EventRecord,
    FindingRecord,
    LeaseRecord,
    MemoryRecord,
    ProjectLockRecord,
    ProjectRecord,
    ScheduleRecord,
    SkillDependencyRecord,
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

psycopg2.extras.register_uuid()


class ConnectionPool:
    """Thin wrapper over psycopg2's SimpleConnectionPool - not a
    heavyweight framework, just enough to avoid opening a new TCP
    connection per repository call in tests/CLI use."""

    def __init__(self, dsn: str, minconn: int = 1, maxconn: int = 5):
        self._pool = SimpleConnectionPool(minconn, maxconn, dsn=dsn)
        if register_vector is not None:
            conn = self._pool.getconn()
            try:
                register_vector(conn)
            except Exception:
                pass  # vector extension/type not present yet (e.g. before migration 0001 runs)
            finally:
                self._pool.putconn(conn)

    def getconn(self):
        conn = self._pool.getconn()
        if register_vector is not None:
            try:
                register_vector(conn)
            except Exception:
                pass
        return conn

    def putconn(self, conn) -> None:
        self._pool.putconn(conn)

    def closeall(self) -> None:
        self._pool.closeall()


def dsn_from_parts(host: str, port: int, user: str, password: str, dbname: str, sslmode: Optional[str] = None) -> str:
    parts = f"host={host} port={port} user={user} password={password} dbname={dbname}"
    if sslmode:
        parts += f" sslmode={sslmode}"
    return parts


class PostgresProjectRepository(ProjectRepository):
    def __init__(self, pool: ConnectionPool):
        self._pool = pool

    def save(self, project: ProjectRecord) -> None:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO projects (id, name, repo_path, policy_path, default_posture,
                           protected_branches, token_budget)
                       VALUES (%s, %s, %s, %s, %s, %s, %s)
                       ON CONFLICT (id) DO UPDATE SET
                           name = EXCLUDED.name, repo_path = EXCLUDED.repo_path,
                           policy_path = EXCLUDED.policy_path, default_posture = EXCLUDED.default_posture,
                           protected_branches = EXCLUDED.protected_branches,
                           token_budget = EXCLUDED.token_budget, updated_at = now()""",
                    (project.id, project.name, project.repo_path, project.policy_path,
                     project.default_posture, json.dumps(project.protected_branches),
                     project.token_budget),
                )
            conn.commit()
        finally:
            self._pool.putconn(conn)

    def get(self, project_id: str) -> Optional[ProjectRecord]:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, name, repo_path, policy_path, default_posture, protected_branches, "
                    "token_budget, created_at, updated_at FROM projects WHERE id = %s",
                    (project_id,),
                )
                row = cur.fetchone()
                return _row_to_project(row) if row else None
        finally:
            self._pool.putconn(conn)

    def list(self) -> list[ProjectRecord]:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, name, repo_path, policy_path, default_posture, protected_branches, "
                    "token_budget, created_at, updated_at FROM projects"
                )
                return [_row_to_project(r) for r in cur.fetchall()]
        finally:
            self._pool.putconn(conn)


def _row_to_project(row) -> ProjectRecord:
    return ProjectRecord(
        id=str(row[0]), name=row[1], repo_path=row[2], policy_path=row[3],
        default_posture=row[4], protected_branches=row[5], token_budget=row[6],
        created_at=row[7], updated_at=row[8],
    )


class PostgresTaskRepository(TaskRepository):
    def __init__(self, pool: ConnectionPool):
        self._pool = pool

    def save(self, task: TaskRecord) -> None:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO tasks (id, project_id, type, status, priority, risk, dependencies,
                           owner_agent, attempts, max_attempts, evidence, artifacts, approval_status,
                           parent_task_id, payload)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                       ON CONFLICT (id) DO UPDATE SET
                           status = EXCLUDED.status, priority = EXCLUDED.priority, risk = EXCLUDED.risk,
                           dependencies = EXCLUDED.dependencies, owner_agent = EXCLUDED.owner_agent,
                           attempts = EXCLUDED.attempts, max_attempts = EXCLUDED.max_attempts,
                           evidence = EXCLUDED.evidence, artifacts = EXCLUDED.artifacts,
                           approval_status = EXCLUDED.approval_status, payload = EXCLUDED.payload,
                           updated_at = now()""",
                    (task.id, task.project_id, task.type, task.status, task.priority, task.risk,
                     json.dumps(task.dependencies), task.owner_agent, task.attempts, task.max_attempts,
                     json.dumps(task.evidence), json.dumps(task.artifacts), task.approval_status,
                     task.parent_task_id, json.dumps(task.payload)),
                )
            conn.commit()
        finally:
            self._pool.putconn(conn)

    def get(self, task_id: str) -> Optional[TaskRecord]:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(_TASK_SELECT + " WHERE id = %s", (task_id,))
                row = cur.fetchone()
                return _row_to_task(row) if row else None
        finally:
            self._pool.putconn(conn)

    def list(self, project_id: Optional[str] = None, status: Optional[str] = None) -> list[TaskRecord]:
        conn = self._pool.getconn()
        try:
            query = _TASK_SELECT + " WHERE 1=1"
            params: list = []
            if project_id:
                query += " AND project_id = %s"
                params.append(project_id)
            if status:
                query += " AND status = %s"
                params.append(status)
            with conn.cursor() as cur:
                cur.execute(query, params)
                return [_row_to_task(r) for r in cur.fetchall()]
        finally:
            self._pool.putconn(conn)


_TASK_SELECT = (
    "SELECT id, project_id, type, status, priority, risk, dependencies, owner_agent, "
    "attempts, max_attempts, evidence, artifacts, approval_status, parent_task_id, "
    "payload, created_at, updated_at FROM tasks"
)


def _row_to_task(row) -> TaskRecord:
    return TaskRecord(
        id=str(row[0]), project_id=str(row[1]), type=row[2], status=row[3], priority=row[4],
        risk=row[5], dependencies=row[6], owner_agent=row[7], attempts=row[8], max_attempts=row[9],
        evidence=row[10], artifacts=row[11], approval_status=row[12],
        parent_task_id=str(row[13]) if row[13] else None, payload=row[14],
        created_at=row[15], updated_at=row[16],
    )


class PostgresEventRepository(EventRepository):
    def __init__(self, pool: ConnectionPool):
        self._pool = pool

    def append(self, event: EventRecord) -> None:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO events (id, project_id, task_id, actor, action, decision, details)
                       VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                    (event.id, event.project_id, event.task_id, event.actor, event.action,
                     event.decision, json.dumps(event.details)),
                )
            conn.commit()
        finally:
            self._pool.putconn(conn)

    def query(self, project_id: Optional[str] = None, task_id: Optional[str] = None) -> list[EventRecord]:
        conn = self._pool.getconn()
        try:
            query = ("SELECT id, project_id, task_id, actor, action, decision, details, \"timestamp\" "
                      "FROM events WHERE 1=1")
            params: list = []
            if project_id:
                query += " AND project_id = %s"
                params.append(project_id)
            if task_id:
                query += " AND task_id = %s"
                params.append(task_id)
            query += " ORDER BY \"timestamp\" ASC"
            with conn.cursor() as cur:
                cur.execute(query, params)
                out = []
                for r in cur.fetchall():
                    out.append(EventRecord(
                        id=str(r[0]), project_id=str(r[1]), task_id=str(r[2]) if r[2] else None,
                        actor=r[3], action=r[4], decision=r[5], details=r[6], timestamp=r[7],
                    ))
                return out
        finally:
            self._pool.putconn(conn)


class PostgresLeaseRepository(LeaseRepository):
    def __init__(self, pool: ConnectionPool):
        self._pool = pool

    def acquire(self, task_id: str, project_id: str, worker_id: str, ttl_seconds: float) -> bool:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT worker_id, expires_at FROM runtime_leases WHERE task_id = %s FOR UPDATE",
                    (task_id,),
                )
                row = cur.fetchone()
                n = now()
                if row is not None:
                    held_by, expires_at = row
                    if held_by != worker_id and expires_at > n:
                        conn.rollback()
                        return False
                    cur.execute(
                        "UPDATE runtime_leases SET worker_id=%s, acquired_at=%s, expires_at=%s WHERE task_id=%s",
                        (worker_id, n, _plus(n, ttl_seconds), task_id),
                    )
                    conn.commit()
                    return True
                # No existing row was visible under FOR UPDATE. Two
                # genuinely concurrent first-time claims can both reach
                # here (SELECT ... FOR UPDATE only locks EXISTING rows -
                # it does not block a concurrent INSERT of a brand-new
                # row). Use INSERT ... ON CONFLICT DO NOTHING and check
                # rowcount so the loser cleanly returns False instead of
                # letting an IntegrityError propagate as an unhandled
                # crash (see BUGFIX.md).
                cur.execute(
                    "INSERT INTO runtime_leases (task_id, project_id, worker_id, acquired_at, expires_at) "
                    "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (task_id) DO NOTHING",
                    (task_id, project_id, worker_id, n, _plus(n, ttl_seconds)),
                )
                won = cur.rowcount == 1
            conn.commit()
            return won
        finally:
            self._pool.putconn(conn)

    def release(self, task_id: str, worker_id: str) -> None:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM runtime_leases WHERE task_id=%s AND worker_id=%s",
                    (task_id, worker_id),
                )
            conn.commit()
        finally:
            self._pool.putconn(conn)

    def list(self) -> list[LeaseRecord]:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT task_id, project_id, worker_id, acquired_at, expires_at FROM runtime_leases")
                return [
                    LeaseRecord(task_id=str(r[0]), project_id=str(r[1]), worker_id=r[2],
                                acquired_at=r[3], expires_at=r[4])
                    for r in cur.fetchall()
                ]
        finally:
            self._pool.putconn(conn)


def _plus(dt: datetime, seconds: float) -> datetime:
    from datetime import timedelta
    return dt + timedelta(seconds=seconds)


class PostgresFindingRepository(FindingRepository):
    def __init__(self, pool: ConnectionPool):
        self._pool = pool

    def save(self, finding: FindingRecord) -> None:
        # BUG-0006 fix: `discovered_at` is now part of the INSERT column
        # list. A caller-supplied value (e.g. a backfill/migration import,
        # or a test constructing a finding that has "been open for N
        # days") is preserved on first insert; when the caller left it
        # unset (the common "brand new finding" case for every real
        # scanner today) the column falls back to its schema default
        # (`now()`, unchanged behavior for all pre-existing callers). On
        # conflict (re-save of an existing finding), `discovered_at` is
        # deliberately NOT in the UPDATE SET list, so a re-save can never
        # move discovered_at forward - it is set exactly once, at first
        # insert.
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                if finding.discovered_at is not None:
                    cur.execute(
                        """INSERT INTO findings (id, project_id, category, severity, status, resource,
                               description, confidence, false_positive, task_id, evidence, discovered_at)
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                           ON CONFLICT (id) DO UPDATE SET
                               status = EXCLUDED.status, description = EXCLUDED.description,
                               false_positive = EXCLUDED.false_positive, evidence = EXCLUDED.evidence,
                               updated_at = now()""",
                        (finding.id, finding.project_id, finding.category, finding.severity, finding.status,
                         finding.resource, finding.description, finding.confidence, finding.false_positive,
                         finding.task_id, json.dumps(finding.evidence), finding.discovered_at),
                    )
                else:
                    cur.execute(
                        """INSERT INTO findings (id, project_id, category, severity, status, resource,
                               description, confidence, false_positive, task_id, evidence)
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                           ON CONFLICT (id) DO UPDATE SET
                               status = EXCLUDED.status, description = EXCLUDED.description,
                               false_positive = EXCLUDED.false_positive, evidence = EXCLUDED.evidence,
                               updated_at = now()""",
                        (finding.id, finding.project_id, finding.category, finding.severity, finding.status,
                         finding.resource, finding.description, finding.confidence, finding.false_positive,
                         finding.task_id, json.dumps(finding.evidence)),
                    )
            conn.commit()
        finally:
            self._pool.putconn(conn)

    def list(self, project_id: Optional[str] = None, severity: Optional[str] = None) -> list[FindingRecord]:
        conn = self._pool.getconn()
        try:
            query = ("SELECT id, project_id, category, severity, status, resource, description, "
                      "confidence, false_positive, task_id, evidence, discovered_at, updated_at "
                      "FROM findings WHERE 1=1")
            params: list = []
            if project_id:
                query += " AND project_id = %s"
                params.append(project_id)
            if severity:
                query += " AND severity = %s"
                params.append(severity)
            with conn.cursor() as cur:
                cur.execute(query, params)
                out = []
                for r in cur.fetchall():
                    out.append(FindingRecord(
                        id=str(r[0]), project_id=str(r[1]), category=r[2], severity=r[3], status=r[4],
                        resource=r[5], description=r[6], confidence=r[7], false_positive=r[8],
                        task_id=str(r[9]) if r[9] else None, evidence=r[10],
                        discovered_at=r[11], updated_at=r[12],
                    ))
                return out
        finally:
            self._pool.putconn(conn)


def _vector_literal(embedding: Optional[list[float]]) -> Optional[str]:
    if embedding is None:
        return None
    return "[" + ",".join(repr(float(x)) for x in embedding) + "]"


class PostgresMemoryRepository(MemoryRepository):
    def __init__(self, pool: ConnectionPool):
        self._pool = pool

    def save(self, memory: MemoryRecord) -> None:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO memory_records (id, memory_class, project_scope, org_scope, content,
                           embedding, fingerprint, evidence_ref, confidence, source, lifecycle_state,
                           superseded_by)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                       ON CONFLICT (id) DO UPDATE SET
                           content = EXCLUDED.content, lifecycle_state = EXCLUDED.lifecycle_state,
                           superseded_by = EXCLUDED.superseded_by, updated_at = now()""",
                    (memory.id, memory.memory_class, memory.project_scope, memory.org_scope,
                     json.dumps(memory.content), _vector_literal(memory.embedding), memory.fingerprint,
                     memory.evidence_ref, memory.confidence, memory.source, memory.lifecycle_state,
                     memory.superseded_by),
                )
            conn.commit()
        finally:
            self._pool.putconn(conn)

    def retrieve(
        self,
        memory_class: Optional[str] = None,
        project_scope: Optional[str] = None,
        embedding: Optional[list[float]] = None,
        top_k: int = 5,
    ) -> list[tuple[MemoryRecord, bool]]:
        conn = self._pool.getconn()
        try:
            query = (
                "SELECT id, memory_class, project_scope, org_scope, content, embedding, fingerprint, "
                "evidence_ref, confidence, source, lifecycle_state, superseded_by, created_at, updated_at "
                "FROM memory_records WHERE lifecycle_state = 'ACTIVE'"
            )
            params: list = []
            if memory_class:
                query += " AND memory_class = %s"
                params.append(memory_class)
            if project_scope:
                query += " AND project_scope = %s"
                params.append(project_scope)
            if embedding is not None:
                query += " ORDER BY embedding <=> %s::vector LIMIT %s"
                params.append(_vector_literal(embedding))
                params.append(top_k)
            else:
                query += " LIMIT %s"
                params.append(top_k)
            with conn.cursor() as cur:
                cur.execute(query, params)
                out = []
                for r in cur.fetchall():
                    rec = MemoryRecord(
                        id=str(r[0]), memory_class=r[1], project_scope=str(r[2]) if r[2] else None,
                        org_scope=str(r[3]) if r[3] else None, content=r[4],
                        embedding=(r[5].to_list() if hasattr(r[5], "to_list") else list(r[5])) if r[5] is not None else None,
                        fingerprint=r[6],
                        evidence_ref=r[7], confidence=r[8], source=r[9], lifecycle_state=r[10],
                        superseded_by=str(r[11]) if r[11] else None, created_at=r[12], updated_at=r[13],
                    )
                    out.append((rec, True))  # always advisory - never mutates a decision
                return out
        finally:
            self._pool.putconn(conn)

    def supersede(self, old_id: str, new_record: MemoryRecord) -> None:
        self.save(new_record)
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE memory_records SET lifecycle_state='SUPERSEDED', superseded_by=%s, "
                    "updated_at=now() WHERE id=%s",
                    (new_record.id, old_id),
                )
            conn.commit()
        finally:
            self._pool.putconn(conn)


class PostgresProjectLockRepository(ProjectLockRepository):
    """Per-project mutating-work lock, mirroring
    `StateStore.acquire_project_lock`/`release_project_lock`/
    `list_project_locks`. Same real transactional-exclusivity pattern as
    `PostgresLeaseRepository`: SELECT ... FOR UPDATE on the existing row,
    INSERT ... ON CONFLICT DO NOTHING for the first-ever claim so two
    concurrent first-time acquires never raise - exactly one wins."""

    def __init__(self, pool: ConnectionPool):
        self._pool = pool

    def acquire(self, project_id: str, worker_id: str, task_id: str, ttl_seconds: float) -> bool:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT worker_id, expires_at FROM runtime_project_locks WHERE project_id = %s FOR UPDATE",
                    (project_id,),
                )
                row = cur.fetchone()
                n = now()
                if row is not None:
                    held_by, expires_at = row
                    if held_by != worker_id and expires_at > n:
                        conn.rollback()
                        return False
                    cur.execute(
                        "UPDATE runtime_project_locks SET worker_id=%s, task_id=%s, acquired_at=%s, "
                        "expires_at=%s WHERE project_id=%s",
                        (worker_id, task_id, n, _plus(n, ttl_seconds), project_id),
                    )
                    conn.commit()
                    return True
                cur.execute(
                    "INSERT INTO runtime_project_locks (project_id, worker_id, task_id, acquired_at, expires_at) "
                    "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (project_id) DO NOTHING",
                    (project_id, worker_id, task_id, n, _plus(n, ttl_seconds)),
                )
                won = cur.rowcount == 1
            conn.commit()
            return won
        finally:
            self._pool.putconn(conn)

    def release(self, project_id: str, worker_id: str) -> None:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM runtime_project_locks WHERE project_id=%s AND worker_id=%s",
                    (project_id, worker_id),
                )
            conn.commit()
        finally:
            self._pool.putconn(conn)

    def list(self) -> list[ProjectLockRecord]:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT project_id, worker_id, task_id, acquired_at, expires_at FROM runtime_project_locks"
                )
                return [
                    ProjectLockRecord(project_id=str(r[0]), worker_id=r[1], task_id=str(r[2]),
                                       acquired_at=r[3], expires_at=r[4])
                    for r in cur.fetchall()
                ]
        finally:
            self._pool.putconn(conn)


class PostgresWorkerRepository(WorkerRepository):
    """Runtime worker registration/heartbeat, mirroring
    `StateStore.register_worker`/`heartbeat_worker`/`list_workers`/
    `remove_worker`."""

    def __init__(self, pool: ConnectionPool):
        self._pool = pool

    def register(self, worker_id: str, supervisor_id: str) -> None:
        conn = self._pool.getconn()
        try:
            n = now()
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO runtime_workers (worker_id, supervisor_id, status, last_heartbeat,
                           started_at, restart_count)
                       VALUES (%s, %s, 'IDLE', %s, %s, 0)
                       ON CONFLICT (worker_id) DO UPDATE SET
                           status='IDLE', last_heartbeat=EXCLUDED.last_heartbeat,
                           restart_count=runtime_workers.restart_count+1""",
                    (worker_id, supervisor_id, n, n),
                )
            conn.commit()
        finally:
            self._pool.putconn(conn)

    def heartbeat(self, worker_id: str, status: str) -> None:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE runtime_workers SET status=%s, last_heartbeat=%s WHERE worker_id=%s",
                    (status, now(), worker_id),
                )
            conn.commit()
        finally:
            self._pool.putconn(conn)

    def list(self, supervisor_id: Optional[str] = None) -> list[WorkerRecord]:
        conn = self._pool.getconn()
        try:
            query = ("SELECT worker_id, supervisor_id, status, last_heartbeat, started_at, "
                      "restart_count FROM runtime_workers")
            params: list = []
            if supervisor_id:
                query += " WHERE supervisor_id = %s"
                params.append(supervisor_id)
            with conn.cursor() as cur:
                cur.execute(query, params)
                return [
                    WorkerRecord(worker_id=r[0], supervisor_id=r[1], status=r[2],
                                 last_heartbeat=r[3], started_at=r[4], restart_count=r[5])
                    for r in cur.fetchall()
                ]
        finally:
            self._pool.putconn(conn)

    def remove(self, worker_id: str) -> None:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM runtime_workers WHERE worker_id=%s", (worker_id,))
            conn.commit()
        finally:
            self._pool.putconn(conn)


class PostgresScheduleRepository(ScheduleRepository):
    """Durable recurring-job schedule, mirroring `StateStore.upsert_schedule`/
    `due_schedules`/`list_schedules`/`record_schedule_run`."""

    def __init__(self, pool: ConnectionPool):
        self._pool = pool

    def upsert(self, job_id: str, project_id: str, job_type: str,
               interval_seconds: float, next_run_at: Optional[object] = None) -> None:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                # Insert-if-unseen only: ON CONFLICT DO NOTHING guarantees
                # an existing schedule's next_run_at is NEVER reset by a
                # later upsert call (a restart must not re-fire early or
                # duplicate a job) - and is race-safe for two concurrent
                # first-time upserts, same pattern as the lease/lock fix.
                cur.execute(
                    """INSERT INTO runtime_schedules (job_id, project_id, job_type, interval_seconds,
                           next_run_at, last_run_at, last_status, consecutive_failures)
                       VALUES (%s, %s, %s, %s, %s, NULL, NULL, 0)
                       ON CONFLICT (job_id) DO NOTHING""",
                    (job_id, project_id, job_type, interval_seconds, next_run_at or now()),
                )
            conn.commit()
        finally:
            self._pool.putconn(conn)

    def due(self, now_: Optional[object] = None) -> list[ScheduleRecord]:
        conn = self._pool.getconn()
        try:
            n = now_ or now()
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT job_id, project_id, job_type, interval_seconds, next_run_at, "
                    "last_run_at, last_status, consecutive_failures FROM runtime_schedules "
                    "WHERE next_run_at <= %s",
                    (n,),
                )
                return [_row_to_schedule(r) for r in cur.fetchall()]
        finally:
            self._pool.putconn(conn)

    def list(self) -> list[ScheduleRecord]:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT job_id, project_id, job_type, interval_seconds, next_run_at, "
                    "last_run_at, last_status, consecutive_failures FROM runtime_schedules"
                )
                return [_row_to_schedule(r) for r in cur.fetchall()]
        finally:
            self._pool.putconn(conn)

    def record_run(self, job_id: str, success: bool, interval_seconds: float,
                   jitter_seconds: float = 0.0) -> None:
        conn = self._pool.getconn()
        try:
            n = now()
            next_run = _plus(n, interval_seconds + jitter_seconds)
            with conn.cursor() as cur:
                if success:
                    cur.execute(
                        "UPDATE runtime_schedules SET last_run_at=%s, last_status='OK', "
                        "consecutive_failures=0, next_run_at=%s WHERE job_id=%s",
                        (n, next_run, job_id),
                    )
                else:
                    cur.execute(
                        "UPDATE runtime_schedules SET last_run_at=%s, last_status='FAILED', "
                        "consecutive_failures=consecutive_failures+1, next_run_at=%s WHERE job_id=%s",
                        (n, next_run, job_id),
                    )
            conn.commit()
        finally:
            self._pool.putconn(conn)


def _row_to_schedule(r) -> ScheduleRecord:
    return ScheduleRecord(
        job_id=r[0], project_id=str(r[1]), job_type=r[2], interval_seconds=r[3],
        next_run_at=r[4], last_run_at=r[5], last_status=r[6], consecutive_failures=r[7],
    )


class PostgresFailureCounterRepository(FailureCounterRepository):
    """Circuit-breaker consecutive-failure/quarantine bookkeeping backed
    by the `failure_counters` table added in migration 0003, mirroring
    `StateStore.record_failure`/`reset_failure_counter`/`is_quarantined`."""

    def __init__(self, pool: ConnectionPool):
        self._pool = pool

    def record_failure(self, project_id: str, task_type: str, threshold: int) -> bool:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO failure_counters (project_id, task_type, consecutive_failures, quarantined)
                       VALUES (%s, %s, 1, false)
                       ON CONFLICT (project_id, task_type) DO UPDATE SET
                           consecutive_failures = failure_counters.consecutive_failures + 1""",
                    (project_id, task_type),
                )
                cur.execute(
                    "SELECT consecutive_failures FROM failure_counters WHERE project_id=%s AND task_type=%s",
                    (project_id, task_type),
                )
                count = cur.fetchone()[0]
                quarantined = count >= threshold
                if quarantined:
                    cur.execute(
                        "UPDATE failure_counters SET quarantined=true WHERE project_id=%s AND task_type=%s",
                        (project_id, task_type),
                    )
            conn.commit()
            return quarantined
        finally:
            self._pool.putconn(conn)

    def reset(self, project_id: str, task_type: str) -> None:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM failure_counters WHERE project_id=%s AND task_type=%s",
                    (project_id, task_type),
                )
            conn.commit()
        finally:
            self._pool.putconn(conn)

    def is_quarantined(self, project_id: str, task_type: str) -> bool:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT quarantined FROM failure_counters WHERE project_id=%s AND task_type=%s",
                    (project_id, task_type),
                )
                row = cur.fetchone()
                return bool(row and row[0])
        finally:
            self._pool.putconn(conn)


class PostgresSkillRepository(SkillRepository):
    """Stable skill-identity rows (Stage B Part 3), migration 0006."""

    def __init__(self, pool: ConnectionPool):
        self._pool = pool

    def save(self, skill: SkillRecord) -> None:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                # Concurrency-safe get-or-create, same ON CONFLICT + no
                # silent overwrite discipline as BUG-0001 established -
                # a skill's identity row is not expected to change once
                # created, so a second `save` for the same skill_id is a
                # no-op rather than an overwrite.
                cur.execute(
                    """INSERT INTO skills (skill_id, name, description, purpose, scope)
                       VALUES (%s, %s, %s, %s, %s)
                       ON CONFLICT (skill_id) DO NOTHING""",
                    (skill.skill_id, skill.name, skill.description, skill.purpose, skill.scope),
                )
            conn.commit()
        finally:
            self._pool.putconn(conn)

    def get(self, skill_id: str) -> Optional[SkillRecord]:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT skill_id, name, description, purpose, scope, created_at, updated_at "
                    "FROM skills WHERE skill_id=%s",
                    (skill_id,),
                )
                row = cur.fetchone()
                return _row_to_skill(row) if row else None
        finally:
            self._pool.putconn(conn)

    def list(self) -> list[SkillRecord]:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT skill_id, name, description, purpose, scope, created_at, updated_at FROM skills"
                )
                return [_row_to_skill(r) for r in cur.fetchall()]
        finally:
            self._pool.putconn(conn)


def _row_to_skill(row) -> SkillRecord:
    return SkillRecord(
        skill_id=row[0], name=row[1], description=row[2], purpose=row[3], scope=row[4],
        created_at=row[5], updated_at=row[6],
    )


class PostgresSkillVersionRepository(SkillVersionRepository):
    """Immutable published skill version rows (Stage B Part 3/4), migration
    0006. Immutability of a PUBLISHED version is enforced at TWO layers:
    application (this class refuses to re-insert an existing (skill_id,
    version) pair - `ON CONFLICT DO NOTHING` + rowcount check, raising
    rather than silently doing nothing, since a caller asking to save an
    existing version is a bug, not a benign race) and database (migration
    0006's `trg_skill_versions_immutable` trigger, which rejects any raw
    UPDATE that would change a published row's content even if some other
    caller bypassed this repository entirely)."""

    def __init__(self, pool: ConnectionPool):
        self._pool = pool

    def save(self, version: SkillVersionRecord) -> None:
        conn = self._pool.getconn()
        try:
            row_id = version.id or str(uuid.uuid4())
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO skill_versions (
                           id, skill_id, version, risk_level, description, purpose, scope,
                           capabilities, allowed_tools, prohibited_actions, required_checks,
                           verification_rules, escalation_rules, approval_requirements,
                           input_contract, output_contract, examples, lifecycle_state,
                           compatibility_metadata, published_at, deprecated_at
                       ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                                 %s, %s, %s, %s, %s)
                       ON CONFLICT (skill_id, version) DO NOTHING""",
                    (
                        row_id, version.skill_id, version.version, version.risk_level,
                        version.description, version.purpose, version.scope,
                        json.dumps(version.capabilities), json.dumps(version.allowed_tools),
                        json.dumps(version.prohibited_actions), json.dumps(version.required_checks),
                        json.dumps(version.verification_rules), json.dumps(version.escalation_rules),
                        json.dumps(version.approval_requirements), json.dumps(version.input_contract),
                        json.dumps(version.output_contract), json.dumps(version.examples),
                        version.lifecycle_state, json.dumps(version.compatibility_metadata),
                        version.published_at, version.deprecated_at,
                    ),
                )
                if cur.rowcount == 0:
                    conn.rollback()
                    raise ValueError(
                        f"skill version {version.skill_id}@{version.version} already exists; "
                        "publishing must use a new version, never re-insert an existing one"
                    )
                version.id = row_id
                for dep in version.dependencies:
                    cur.execute(
                        """INSERT INTO skill_dependencies (id, skill_version_id, depends_on_skill_id,
                               version_constraint)
                           VALUES (%s, %s, %s, %s)
                           ON CONFLICT (skill_version_id, depends_on_skill_id) DO NOTHING""",
                        (str(uuid.uuid4()), row_id, dep.depends_on_skill_id, dep.version_constraint),
                    )
            conn.commit()
        finally:
            self._pool.putconn(conn)

    def get(self, skill_id: str, version: str) -> Optional[SkillVersionRecord]:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, skill_id, version, risk_level, description, purpose, scope, "
                    "capabilities, allowed_tools, prohibited_actions, required_checks, "
                    "verification_rules, escalation_rules, approval_requirements, input_contract, "
                    "output_contract, examples, lifecycle_state, compatibility_metadata, "
                    "created_at, published_at, deprecated_at FROM skill_versions "
                    "WHERE skill_id=%s AND version=%s",
                    (skill_id, version),
                )
                row = cur.fetchone()
                if row is None:
                    return None
                record = _row_to_skill_version(row)
                record.dependencies = self._deps(cur, record.id)
                return record
        finally:
            self._pool.putconn(conn)

    def list_for_skill(self, skill_id: str) -> list[SkillVersionRecord]:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, skill_id, version, risk_level, description, purpose, scope, "
                    "capabilities, allowed_tools, prohibited_actions, required_checks, "
                    "verification_rules, escalation_rules, approval_requirements, input_contract, "
                    "output_contract, examples, lifecycle_state, compatibility_metadata, "
                    "created_at, published_at, deprecated_at FROM skill_versions WHERE skill_id=%s",
                    (skill_id,),
                )
                rows = cur.fetchall()
                out = []
                for row in rows:
                    record = _row_to_skill_version(row)
                    record.dependencies = self._deps(cur, record.id)
                    out.append(record)
                return out
        finally:
            self._pool.putconn(conn)

    def _deps(self, cur, skill_version_id: str) -> list[SkillDependencyRecord]:
        cur.execute(
            "SELECT depends_on_skill_id, version_constraint FROM skill_dependencies "
            "WHERE skill_version_id=%s",
            (skill_version_id,),
        )
        return [SkillDependencyRecord(depends_on_skill_id=r[0], version_constraint=r[1])
                for r in cur.fetchall()]

    def mark_deprecated(self, skill_id: str, version: str) -> None:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE skill_versions SET lifecycle_state='deprecated', deprecated_at=now() "
                    "WHERE skill_id=%s AND version=%s",
                    (skill_id, version),
                )
            conn.commit()
        finally:
            self._pool.putconn(conn)


def _row_to_skill_version(row) -> SkillVersionRecord:
    return SkillVersionRecord(
        id=str(row[0]), skill_id=row[1], version=row[2], risk_level=row[3],
        description=row[4], purpose=row[5], scope=row[6],
        capabilities=row[7], allowed_tools=row[8], prohibited_actions=row[9],
        required_checks=row[10], verification_rules=row[11], escalation_rules=row[12],
        approval_requirements=row[13], input_contract=row[14], output_contract=row[15],
        examples=row[16], lifecycle_state=row[17], compatibility_metadata=row[18],
        created_at=row[19], published_at=row[20], deprecated_at=row[21],
    )
