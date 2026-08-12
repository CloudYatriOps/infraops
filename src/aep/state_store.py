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
