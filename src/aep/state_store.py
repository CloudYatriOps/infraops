"""Durable state store (SQLite/WAL) for tasks and the audit event log.

This is the component that makes the platform survive crashes/restarts:
nothing about scheduling lives only in memory. `Orchestrator.resume()`
reloads every non-terminal task straight from here.
"""
from __future__ import annotations

import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterable, Optional

from .models import Event, Task, TaskStatus

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    status TEXT NOT NULL,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_project_status ON tasks(project_id, status);

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    task_id TEXT,
    timestamp TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_project ON events(project_id);
CREATE INDEX IF NOT EXISTS idx_events_task ON events(task_id);

CREATE TABLE IF NOT EXISTS failure_counters (
    project_id TEXT NOT NULL,
    task_type TEXT NOT NULL,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    quarantined INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, task_type)
);

-- Phase 8 (24/7 Autonomous Runtime): additive tables only. No second
-- database/queue engine - runtime state lives in the SAME SQLite file as
-- tasks/events above, so a crash mid-lease leaves a resumable, consistent
-- record exactly like a crash mid-task does. See src/aep/runtime/.
CREATE TABLE IF NOT EXISTS runtime_workers (
    worker_id TEXT PRIMARY KEY,
    supervisor_id TEXT NOT NULL,
    status TEXT NOT NULL,
    last_heartbeat TEXT NOT NULL,
    started_at TEXT NOT NULL,
    restart_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS runtime_leases (
    task_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    acquired_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runtime_project_locks (
    project_id TEXT PRIMARY KEY,
    worker_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    acquired_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runtime_schedules (
    job_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    job_type TEXT NOT NULL,
    interval_seconds REAL NOT NULL,
    next_run_at TEXT NOT NULL,
    last_run_at TEXT,
    last_status TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0
);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class StateStore:
    """Thread-safe SQLite-backed durable store.

    Uses WAL journal mode so readers don't block the single writer, and
    commits every mutation immediately (no batching) so a process kill at
    any point leaves the DB in a consistent, resumable state.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=FULL;")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def _cursor(self):
        with self._lock:
            cur = self._conn.cursor()
            try:
                yield cur
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            finally:
                cur.close()

    # ---- Tasks -----------------------------------------------------
    def save_task(self, task: Task) -> None:
        task.updated_at = now_iso()
        if not task.created_at:
            task.created_at = task.updated_at
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO tasks (id, project_id, status, data, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET
                       status=excluded.status,
                       data=excluded.data,
                       updated_at=excluded.updated_at""",
                (task.id, task.project_id, task.status.value, task.to_json(),
                 task.created_at, task.updated_at),
            )

    def get_task(self, task_id: str) -> Optional[Task]:
        with self._cursor() as cur:
            cur.execute("SELECT data FROM tasks WHERE id=?", (task_id,))
            row = cur.fetchone()
            return Task.from_json(row[0]) if row else None

    def list_tasks(self, project_id: Optional[str] = None,
                    statuses: Optional[Iterable[TaskStatus]] = None) -> list[Task]:
        query = "SELECT data FROM tasks WHERE 1=1"
        params: list = []
        if project_id:
            query += " AND project_id=?"
            params.append(project_id)
        if statuses:
            placeholders = ",".join("?" for _ in statuses)
            query += f" AND status IN ({placeholders})"
            params.extend(s.value for s in statuses)
        with self._cursor() as cur:
            cur.execute(query, params)
            return [Task.from_json(r[0]) for r in cur.fetchall()]

    def non_terminal_tasks(self, project_id: Optional[str] = None) -> list[Task]:
        terminal = {TaskStatus.SUCCEEDED, TaskStatus.CANCELLED, TaskStatus.QUARANTINED}
        all_statuses = set(TaskStatus) - terminal
        return self.list_tasks(project_id=project_id, statuses=all_statuses)

    # ---- Events (append-only audit trail) --------------------------
    def append_event(self, event: Event) -> None:
        if not event.id:
            event.id = str(uuid.uuid4())
        if not event.timestamp:
            event.timestamp = now_iso()
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO events (id, project_id, task_id, timestamp, data) VALUES (?, ?, ?, ?, ?)",
                (event.id, event.project_id, event.task_id, event.timestamp, event.to_json()),
            )

    def query_events(self, project_id: Optional[str] = None,
                      task_id: Optional[str] = None) -> list[Event]:
        query = "SELECT data FROM events WHERE 1=1"
        params: list = []
        if project_id:
            query += " AND project_id=?"
            params.append(project_id)
        if task_id:
            query += " AND task_id=?"
            params.append(task_id)
        query += " ORDER BY timestamp ASC"
        with self._cursor() as cur:
            cur.execute(query, params)
            return [Event.from_json(r[0]) for r in cur.fetchall()]

    # ---- Circuit breaker counters -----------------------------------
    def record_failure(self, project_id: str, task_type: str, threshold: int) -> bool:
        """Increment consecutive-failure counter; returns True if now quarantined."""
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO failure_counters (project_id, task_type, consecutive_failures, quarantined)
                   VALUES (?, ?, 1, 0)
                   ON CONFLICT(project_id, task_type) DO UPDATE SET
                       consecutive_failures = consecutive_failures + 1""",
                (project_id, task_type),
            )
            cur.execute(
                "SELECT consecutive_failures FROM failure_counters WHERE project_id=? AND task_type=?",
                (project_id, task_type),
            )
            count = cur.fetchone()[0]
            quarantined = count >= threshold
            if quarantined:
                cur.execute(
                    "UPDATE failure_counters SET quarantined=1 WHERE project_id=? AND task_type=?",
                    (project_id, task_type),
                )
            return quarantined

    def reset_failure_counter(self, project_id: str, task_type: str) -> None:
        with self._cursor() as cur:
            cur.execute(
                "DELETE FROM failure_counters WHERE project_id=? AND task_type=?",
                (project_id, task_type),
            )

    def is_quarantined(self, project_id: str, task_type: str) -> bool:
        with self._cursor() as cur:
            cur.execute(
                "SELECT quarantined FROM failure_counters WHERE project_id=? AND task_type=?",
                (project_id, task_type),
            )
            row = cur.fetchone()
            return bool(row and row[0])

    # ---- Phase 8: runtime workers ------------------------------------
    def register_worker(self, worker_id: str, supervisor_id: str) -> None:
        ts = now_iso()
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO runtime_workers (worker_id, supervisor_id, status, last_heartbeat, started_at, restart_count)
                   VALUES (?, ?, 'IDLE', ?, ?, 0)
                   ON CONFLICT(worker_id) DO UPDATE SET
                       status='IDLE', last_heartbeat=excluded.last_heartbeat,
                       restart_count=restart_count+1""",
                (worker_id, supervisor_id, ts, ts),
            )

    def heartbeat_worker(self, worker_id: str, status: str) -> None:
        with self._cursor() as cur:
            cur.execute(
                "UPDATE runtime_workers SET status=?, last_heartbeat=? WHERE worker_id=?",
                (status, now_iso(), worker_id),
            )

    def list_workers(self, supervisor_id: Optional[str] = None) -> list[dict]:
        with self._cursor() as cur:
            if supervisor_id:
                cur.execute("SELECT worker_id, supervisor_id, status, last_heartbeat, started_at, "
                            "restart_count FROM runtime_workers WHERE supervisor_id=?", (supervisor_id,))
            else:
                cur.execute("SELECT worker_id, supervisor_id, status, last_heartbeat, started_at, "
                            "restart_count FROM runtime_workers")
            cols = ["worker_id", "supervisor_id", "status", "last_heartbeat", "started_at", "restart_count"]
            return [dict(zip(cols, r)) for r in cur.fetchall()]

    def remove_worker(self, worker_id: str) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM runtime_workers WHERE worker_id=?", (worker_id,))

    # ---- Phase 8: task leases -----------------------------------------
    def acquire_lease(self, task_id: str, project_id: str, worker_id: str, ttl_seconds: float) -> bool:
        """Try to acquire (or re-acquire after expiry) an exclusive lease on a
        task. Returns False if another worker currently holds a non-expired
        lease. Durable: survives process crash/restart via SQLite."""
        now = datetime.now(timezone.utc)
        expires_at = _iso_plus(now, ttl_seconds)
        with self._cursor() as cur:
            cur.execute("SELECT worker_id, expires_at FROM runtime_leases WHERE task_id=?", (task_id,))
            row = cur.fetchone()
            if row is not None:
                held_by, expires = row
                if held_by != worker_id and _parse_iso(expires) > now:
                    return False
                cur.execute(
                    "UPDATE runtime_leases SET worker_id=?, acquired_at=?, expires_at=? WHERE task_id=?",
                    (worker_id, now.isoformat(), expires_at, task_id),
                )
                return True
            cur.execute(
                "INSERT INTO runtime_leases (task_id, project_id, worker_id, acquired_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (task_id, project_id, worker_id, now.isoformat(), expires_at),
            )
            return True

    def renew_lease(self, task_id: str, worker_id: str, ttl_seconds: float) -> bool:
        now = datetime.now(timezone.utc)
        with self._cursor() as cur:
            cur.execute("SELECT worker_id FROM runtime_leases WHERE task_id=?", (task_id,))
            row = cur.fetchone()
            if row is None or row[0] != worker_id:
                return False
            cur.execute("UPDATE runtime_leases SET expires_at=? WHERE task_id=?",
                        (_iso_plus(now, ttl_seconds), task_id))
            return True

    def release_lease(self, task_id: str, worker_id: str) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM runtime_leases WHERE task_id=? AND worker_id=?", (task_id, worker_id))

    def expired_leases(self) -> list[dict]:
        now = now_iso()
        with self._cursor() as cur:
            cur.execute("SELECT task_id, project_id, worker_id, expires_at FROM runtime_leases "
                        "WHERE expires_at < ?", (now,))
            cols = ["task_id", "project_id", "worker_id", "expires_at"]
            return [dict(zip(cols, r)) for r in cur.fetchall()]

    def list_leases(self) -> list[dict]:
        with self._cursor() as cur:
            cur.execute("SELECT task_id, project_id, worker_id, acquired_at, expires_at FROM runtime_leases")
            cols = ["task_id", "project_id", "worker_id", "acquired_at", "expires_at"]
            return [dict(zip(cols, r)) for r in cur.fetchall()]

    def force_release_lease(self, task_id: str) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM runtime_leases WHERE task_id=?", (task_id,))

    # ---- Phase 8: per-project mutating-work lock ----------------------
    def acquire_project_lock(self, project_id: str, worker_id: str, task_id: str,
                              ttl_seconds: float) -> bool:
        """One mutating workflow at a time per project - durable so a
        restart doesn't let two workers both believe they hold it."""
        now = datetime.now(timezone.utc)
        with self._cursor() as cur:
            cur.execute("SELECT worker_id, expires_at FROM runtime_project_locks WHERE project_id=?",
                        (project_id,))
            row = cur.fetchone()
            if row is not None:
                held_by, expires = row
                if held_by != worker_id and _parse_iso(expires) > now:
                    return False
                cur.execute(
                    "UPDATE runtime_project_locks SET worker_id=?, task_id=?, acquired_at=?, expires_at=? "
                    "WHERE project_id=?",
                    (worker_id, task_id, now.isoformat(), _iso_plus(now, ttl_seconds), project_id),
                )
                return True
            cur.execute(
                "INSERT INTO runtime_project_locks (project_id, worker_id, task_id, acquired_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (project_id, worker_id, task_id, now.isoformat(), _iso_plus(now, ttl_seconds)),
            )
            return True

    def release_project_lock(self, project_id: str, worker_id: str) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM runtime_project_locks WHERE project_id=? AND worker_id=?",
                        (project_id, worker_id))

    def list_project_locks(self) -> list[dict]:
        with self._cursor() as cur:
            cur.execute("SELECT project_id, worker_id, task_id, acquired_at, expires_at "
                        "FROM runtime_project_locks")
            cols = ["project_id", "worker_id", "task_id", "acquired_at", "expires_at"]
            return [dict(zip(cols, r)) for r in cur.fetchall()]

    # ---- Phase 8: durable recurring-job schedule ----------------------
    def upsert_schedule(self, job_id: str, project_id: str, job_type: str,
                        interval_seconds: float, next_run_at: Optional[str] = None) -> None:
        """Insert a job if unseen (so a restart never re-fires it early/
        duplicates it); NEVER resets next_run_at of an existing job."""
        with self._cursor() as cur:
            cur.execute("SELECT job_id FROM runtime_schedules WHERE job_id=?", (job_id,))
            if cur.fetchone() is not None:
                return
            cur.execute(
                "INSERT INTO runtime_schedules (job_id, project_id, job_type, interval_seconds, "
                "next_run_at, last_run_at, last_status, consecutive_failures) "
                "VALUES (?, ?, ?, ?, ?, NULL, NULL, 0)",
                (job_id, project_id, job_type, interval_seconds, next_run_at or now_iso()),
            )

    def due_schedules(self, now: Optional[str] = None) -> list[dict]:
        now = now or now_iso()
        with self._cursor() as cur:
            cur.execute("SELECT job_id, project_id, job_type, interval_seconds, next_run_at, "
                        "last_run_at, last_status, consecutive_failures FROM runtime_schedules "
                        "WHERE next_run_at <= ?", (now,))
            cols = ["job_id", "project_id", "job_type", "interval_seconds", "next_run_at",
                    "last_run_at", "last_status", "consecutive_failures"]
            return [dict(zip(cols, r)) for r in cur.fetchall()]

    def list_schedules(self) -> list[dict]:
        with self._cursor() as cur:
            cur.execute("SELECT job_id, project_id, job_type, interval_seconds, next_run_at, "
                        "last_run_at, last_status, consecutive_failures FROM runtime_schedules")
            cols = ["job_id", "project_id", "job_type", "interval_seconds", "next_run_at",
                    "last_run_at", "last_status", "consecutive_failures"]
            return [dict(zip(cols, r)) for r in cur.fetchall()]

    def record_schedule_run(self, job_id: str, success: bool, interval_seconds: float,
                            jitter_seconds: float = 0.0) -> None:
        now = datetime.now(timezone.utc)
        next_run = _iso_plus(now, interval_seconds + jitter_seconds)
        with self._cursor() as cur:
            if success:
                cur.execute(
                    "UPDATE runtime_schedules SET last_run_at=?, last_status='OK', "
                    "consecutive_failures=0, next_run_at=? WHERE job_id=?",
                    (now.isoformat(), next_run, job_id),
                )
            else:
                cur.execute(
                    "UPDATE runtime_schedules SET last_run_at=?, last_status='FAILED', "
                    "consecutive_failures=consecutive_failures+1, next_run_at=? WHERE job_id=?",
                    (now.isoformat(), next_run, job_id),
                )


def _parse_iso(s: str):
    return datetime.fromisoformat(s)


def _iso_plus(dt, seconds: float) -> str:
    from datetime import timedelta
    return (dt + timedelta(seconds=seconds)).isoformat()
