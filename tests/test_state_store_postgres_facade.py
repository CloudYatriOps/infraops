"""Smoke test for the PostgresStateStore facade (drop-in adapter over the
Stage A repository layer) against a real, migrated, throwaway-schema
Postgres database. Skips if local PostgreSQL is unreachable."""
from __future__ import annotations

import uuid

import pytest

from aep.db import migrations
from aep.db.state_store_postgres import PostgresStateStore
from aep.models import Event, Task, TaskStatus

from db_pg_helper import LOCAL_DSN, drop_test_schema, fresh_test_schema_connection, local_postgres_available

pytestmark = pytest.mark.skipif(
    not local_postgres_available(),
    reason="local PostgreSQL (aep_platform db) is not reachable in this environment",
)


@pytest.fixture
def store():
    schema = f"aep_test_{uuid.uuid4().hex[:12]}"
    conn = fresh_test_schema_connection(schema)
    migrations.apply_pending(conn)
    conn.close()
    dsn = f"{LOCAL_DSN} options='-c search_path={schema},public'"
    s = PostgresStateStore(dsn=dsn)
    try:
        yield s
    finally:
        s.close()
        drop_test_schema(schema)


def test_task_roundtrip(store):
    project_id = str(uuid.uuid4())
    task = Task(id=str(uuid.uuid4()), type="recon", project_id=project_id)
    store.save_task(task)
    assert task.created_at and task.updated_at

    fetched = store.get_task(task.id)
    assert fetched is not None
    assert fetched.status == TaskStatus.PENDING

    fetched.status = TaskStatus.SUCCEEDED
    store.save_task(fetched)
    listed = store.list_tasks(project_id, statuses=[TaskStatus.SUCCEEDED])
    assert [t.id for t in listed] == [task.id]

    non_terminal = store.non_terminal_tasks(project_id)
    assert non_terminal == []


def test_event_roundtrip(store):
    project_id = str(uuid.uuid4())
    store.ensure_project(project_id)
    event = Event(id=str(uuid.uuid4()), actor="orchestrator", action="task_started",
                  project_id=project_id, task_id=None, decision=None, timestamp="",
                  details={"k": "v"})
    store.append_event(event)
    events = store.query_events(project_id=project_id)
    assert len(events) == 1
    assert events[0].action == "task_started"
    assert events[0].details == {"k": "v"}


def test_lease_and_project_lock(store):
    project_id = str(uuid.uuid4())
    task_id = str(uuid.uuid4())
    store.ensure_project(project_id)
    # runtime_leases.task_id has a real FK to tasks(id) (unlike SQLite's
    # schema, which has none) - a lease can only be acquired for a task
    # that has already been saved. Real orchestrator usage always saves a
    # task before leasing it, so this is not a behavior change in
    # practice, but it is a genuine, documented interface gap (see
    # state_store_postgres.py module docstring).
    store.save_task(Task(id=task_id, type="recon", project_id=project_id))
    # runtime_leases.worker_id / runtime_project_locks.worker_id also FK
    # to runtime_workers(worker_id) - register both workers first.
    store.register_worker("worker-a", "sup")
    store.register_worker("worker-b", "sup")
    assert store.acquire_lease(task_id, project_id, "worker-a", ttl_seconds=30) is True
    assert store.acquire_lease(task_id, project_id, "worker-b", ttl_seconds=30) is False
    assert store.renew_lease(task_id, "worker-a", ttl_seconds=60) is True
    store.release_lease(task_id, "worker-a")
    assert store.list_leases() == []

    assert store.acquire_project_lock(project_id, "worker-a", task_id, ttl_seconds=30) is True
    assert store.acquire_project_lock(project_id, "worker-b", task_id, ttl_seconds=30) is False
    store.release_project_lock(project_id, "worker-a")
    assert store.list_project_locks() == []


def test_worker_and_schedule_and_failure_counter(store):
    store.register_worker("w1", "sup1")
    store.heartbeat_worker("w1", "BUSY")
    workers = store.list_workers("sup1")
    assert workers[0]["status"] == "BUSY"
    store.remove_worker("w1")
    assert store.list_workers() == []

    project_id = str(uuid.uuid4())
    store.ensure_project(project_id)
    store.upsert_schedule("job1", project_id, "poll", interval_seconds=60)
    store.upsert_schedule("job1", project_id, "poll", interval_seconds=999)  # must not reset
    due = store.due_schedules()
    assert due and due[0]["interval_seconds"] == 60
    store.record_schedule_run("job1", success=True, interval_seconds=60)

    assert store.is_quarantined(project_id, "recon") is False
    quarantined = False
    for _ in range(10):
        quarantined = store.record_failure(project_id, "recon", threshold=3)
        if quarantined:
            break
    assert quarantined is True
    assert store.is_quarantined(project_id, "recon") is True
    store.reset_failure_counter(project_id, "recon")
    assert store.is_quarantined(project_id, "recon") is False
