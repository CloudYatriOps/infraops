"""Stage A.5 crash/recovery proof: state saved through `PostgresStateStore`
must survive the complete destruction of the in-process Python objects that
wrote it (connection pool, store instance, everything) and be readable back,
unchanged, by a brand-new `PostgresStateStore` instance opened against the
same DSN - exactly as a real process restart would look from the outside.

Also includes the facade-level concurrent-lease-acquisition proof requested
for Stage A.5: two real threads, each with their OWN `PostgresStateStore`
facade instance (own connection pool), race `acquire_lease` for the same
task_id. Exactly one must win; the loser must get `False` back through the
facade (not just the raw repository) so it can correctly decide not to also
do the work.
"""
from __future__ import annotations

import gc
import threading
import uuid

import pytest

from aep.db import migrations
from aep.db.state_store_postgres import PostgresStateStore
from aep.models import Event, Task, TaskStatus

from db_pg_helper import drop_test_schema, dsn_with_schema, fresh_test_schema_connection, local_postgres_available

pytestmark = pytest.mark.skipif(
    not local_postgres_available(),
    reason="local PostgreSQL (aep_platform db) is not reachable in this environment",
)


@pytest.fixture
def schema_dsn():
    schema = f"aep_test_{uuid.uuid4().hex[:12]}"
    conn = fresh_test_schema_connection(schema)
    migrations.apply_pending(conn)
    conn.close()
    dsn = dsn_with_schema(schema)
    try:
        yield dsn
    finally:
        drop_test_schema(schema)


def test_fresh_process_restart_recovers_task_lease_and_event_state(schema_dsn):
    project_id = str(uuid.uuid4())
    task_id = str(uuid.uuid4())
    worker_id = "worker-restart-proof"

    # ---- "process 1": write real state, then simulate a crash ----------
    store = PostgresStateStore(dsn=schema_dsn)
    store.ensure_project(project_id)
    store.register_worker(worker_id, "sup-1")

    task = Task(id=task_id, type="recon", project_id=project_id, priority=5)
    store.save_task(task)

    assert store.acquire_lease(task_id, project_id, worker_id, ttl_seconds=120) is True

    event = Event(
        id=str(uuid.uuid4()), actor=worker_id, action="evidence_recorded",
        project_id=project_id, task_id=task_id, decision=None, timestamp="",
        details={"finding": "port 22 open", "severity": "info"},
    )
    store.append_event(event)

    # Simulate a genuine process crash: discard every in-process Python
    # object that could be holding state or a live connection, including
    # the connection pool itself, then force garbage collection so no
    # stale connection/reference lingers.
    store.close()
    del store
    del task
    del event
    gc.collect()

    # ---- "process 2": brand-new instance, as if a fresh process started -
    fresh_store = PostgresStateStore(dsn=schema_dsn)
    try:
        recovered_task = fresh_store.get_task(task_id)
        assert recovered_task is not None
        assert recovered_task.id == task_id
        assert recovered_task.project_id == project_id
        assert recovered_task.type == "recon"
        assert recovered_task.priority == 5
        assert recovered_task.status == TaskStatus.PENDING

        leases = fresh_store.list_leases()
        assert len(leases) == 1, f"expected exactly one lease, found {len(leases)} (no loss/duplication)"
        assert leases[0]["task_id"] == task_id
        assert leases[0]["worker_id"] == worker_id

        events = fresh_store.query_events(project_id=project_id, task_id=task_id)
        assert len(events) == 1, f"expected exactly one event, found {len(events)} (no loss/duplication)"
        assert events[0].action == "evidence_recorded"
        assert events[0].details == {"finding": "port 22 open", "severity": "info"}

        # Re-listing tasks for the project must show exactly one task too -
        # no ghost duplicate row from a re-applied write.
        all_tasks = fresh_store.list_tasks(project_id)
        assert len(all_tasks) == 1
    finally:
        fresh_store.close()


def test_concurrent_facade_instances_race_acquire_lease_exactly_one_winner(schema_dsn):
    """Two 'workers', each its own `PostgresStateStore` facade instance
    (own connection pool - not sharing anything in-process), race
    `acquire_lease` for the SAME task_id at the same time. Exactly one
    thread's facade call must return True; the other must return False
    (never raise), proving the loser can correctly decide, via the
    facade's own return value, not to proceed with duplicate work."""
    project_id = str(uuid.uuid4())
    task_id = str(uuid.uuid4())

    setup_store = PostgresStateStore(dsn=schema_dsn)
    try:
        setup_store.ensure_project(project_id)
        setup_store.save_task(Task(id=task_id, type="recon", project_id=project_id))
        setup_store.register_worker("worker-a", "sup")
        setup_store.register_worker("worker-b", "sup")
    finally:
        setup_store.close()

    results: dict[str, object] = {}
    errors: list = []
    barrier = threading.Barrier(2)

    def race(worker_id: str):
        store = PostgresStateStore(dsn=schema_dsn)
        try:
            barrier.wait(timeout=5)
            results[worker_id] = store.acquire_lease(task_id, project_id, worker_id, ttl_seconds=60)
        except Exception as exc:  # noqa: BLE001 - a raise here would itself be a bug
            errors.append(exc)
        finally:
            store.close()

    threads = [
        threading.Thread(target=race, args=("worker-a",)),
        threading.Thread(target=race, args=("worker-b",)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    assert errors == [], f"acquire_lease raised through the facade instead of cleanly losing: {errors}"
    assert list(results.values()).count(True) == 1, f"expected exactly one winner, got {results}"
    assert list(results.values()).count(False) == 1, f"expected exactly one loser, got {results}"

    # Confirm final state: exactly one lease row exists, held by the winner.
    verify_store = PostgresStateStore(dsn=schema_dsn)
    try:
        leases = verify_store.list_leases()
        assert len(leases) == 1
        winner = [w for w, won in results.items() if won][0]
        assert leases[0]["worker_id"] == winner
    finally:
        verify_store.close()
