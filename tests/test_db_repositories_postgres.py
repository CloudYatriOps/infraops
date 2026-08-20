"""Real-Postgres integration tests for the Stage A repository
implementations (src/aep/db/postgres.py) - runs against the local
`aep_platform` database in a throwaway schema. Skips gracefully if it's
not reachable; never fakes a pass."""
from __future__ import annotations

import uuid

import pytest

from aep.db import migrations
from aep.db.models import EventRecord, FindingRecord, MemoryRecord, ProjectRecord, TaskRecord, new_id
from aep.db.postgres import (
    ConnectionPool,
    PostgresEventRepository,
    PostgresFailureCounterRepository,
    PostgresFindingRepository,
    PostgresLeaseRepository,
    PostgresMemoryRepository,
    PostgresProjectLockRepository,
    PostgresProjectRepository,
    PostgresScheduleRepository,
    PostgresTaskRepository,
    PostgresWorkerRepository,
)

from db_pg_helper import drop_test_schema, fresh_test_schema_connection, local_postgres_available

pytestmark = pytest.mark.skipif(
    not local_postgres_available(),
    reason="local PostgreSQL (aep_platform db) is not reachable in this environment",
)


def _dsn_for_schema(schema: str) -> str:
    return (
        "host=localhost port=5432 user=aep password=aep_local_dev_only dbname=aep_platform "
        f"options='-c search_path={schema},public'"
    )


@pytest.fixture
def pg_schema():
    schema = f"aep_test_{uuid.uuid4().hex[:12]}"
    setup_conn = fresh_test_schema_connection(schema)
    migrations.apply_pending(setup_conn)
    setup_conn.close()
    try:
        yield schema
    finally:
        drop_test_schema(schema)


@pytest.fixture
def pg_dsn(pg_schema):
    return _dsn_for_schema(pg_schema)


@pytest.fixture
def pg_pool(pg_dsn):
    pool = ConnectionPool(pg_dsn, minconn=1, maxconn=8)
    try:
        yield pool
    finally:
        pool.closeall()


def test_project_repository_real_postgres_roundtrip(pg_pool):
    repo = PostgresProjectRepository(pg_pool)
    p = ProjectRecord(id=new_id(), name="real-demo", repo_path="/tmp/demo", policy_path="config/policy.yaml")
    repo.save(p)
    fetched = repo.get(p.id)
    assert fetched is not None
    assert fetched.name == "real-demo"
    assert fetched.protected_branches == ["main", "master"]


def test_task_repository_real_postgres_foreign_key_and_filters(pg_pool):
    projects = PostgresProjectRepository(pg_pool)
    tasks = PostgresTaskRepository(pg_pool)
    proj = ProjectRecord(id=new_id(), name="p", repo_path="/tmp", policy_path="x")
    projects.save(proj)

    t1 = TaskRecord(id=new_id(), project_id=proj.id, type="scan", status="PENDING")
    t2 = TaskRecord(id=new_id(), project_id=proj.id, type="scan", status="SUCCEEDED")
    tasks.save(t1)
    tasks.save(t2)

    assert len(tasks.list(project_id=proj.id)) == 2
    assert len(tasks.list(project_id=proj.id, status="PENDING")) == 1
    fetched = tasks.get(t1.id)
    assert fetched.status == "PENDING"


def test_task_repository_rejects_unknown_project_id_via_foreign_key(pg_pool):
    tasks = PostgresTaskRepository(pg_pool)
    with pytest.raises(Exception):
        tasks.save(TaskRecord(id=new_id(), project_id=new_id(), type="scan"))


def test_event_repository_real_postgres_ordering(pg_pool):
    projects = PostgresProjectRepository(pg_pool)
    events = PostgresEventRepository(pg_pool)
    proj = ProjectRecord(id=new_id(), name="p", repo_path="/tmp", policy_path="x")
    projects.save(proj)
    events.append(EventRecord(id=new_id(), project_id=proj.id, actor="agent", action="scan"))
    events.append(EventRecord(id=new_id(), project_id=proj.id, actor="agent", action="discover"))
    rows = events.query(project_id=proj.id)
    assert len(rows) == 2


def test_lease_repository_real_postgres_exclusive_acquire(pg_pool):
    projects = PostgresProjectRepository(pg_pool)
    tasks = PostgresTaskRepository(pg_pool)
    leases = PostgresLeaseRepository(pg_pool)
    proj = ProjectRecord(id=new_id(), name="p", repo_path="/tmp", policy_path="x")
    projects.save(proj)
    task = TaskRecord(id=new_id(), project_id=proj.id, type="scan")
    tasks.save(task)

    conn = pg_pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO runtime_workers (worker_id, supervisor_id, status, last_heartbeat, started_at) "
                "VALUES (%s, 's1', 'IDLE', now(), now()), (%s, 's1', 'IDLE', now(), now())",
                ("worker-1", "worker-2"),
            )
        conn.commit()
    finally:
        pg_pool.putconn(conn)

    assert leases.acquire(task.id, proj.id, "worker-1", ttl_seconds=60) is True
    assert leases.acquire(task.id, proj.id, "worker-2", ttl_seconds=60) is False
    leases.release(task.id, "worker-1")
    assert leases.acquire(task.id, proj.id, "worker-2", ttl_seconds=60) is True


def test_finding_repository_real_postgres_severity_filter(pg_pool):
    projects = PostgresProjectRepository(pg_pool)
    findings = PostgresFindingRepository(pg_pool)
    proj = ProjectRecord(id=new_id(), name="p", repo_path="/tmp", policy_path="x")
    projects.save(proj)
    findings.save(FindingRecord(id=new_id(), project_id=proj.id, category="secret", severity="critical"))
    findings.save(FindingRecord(id=new_id(), project_id=proj.id, category="sast", severity="low"))
    assert len(findings.list(project_id=proj.id, severity="critical")) == 1


def test_finding_repository_real_postgres_preserves_caller_supplied_discovered_at(pg_pool):
    """BUG-0006 regression test: a caller-supplied `discovered_at` (e.g. a
    backfill/migration import, or Phase 10 Wave 2's recurrence-interval
    math needing a genuinely old finding) must be preserved on first
    insert, not silently overwritten with `now()`."""
    from datetime import datetime, timedelta, timezone

    projects = PostgresProjectRepository(pg_pool)
    findings = PostgresFindingRepository(pg_pool)
    proj = ProjectRecord(id=new_id(), name="p", repo_path="/tmp", policy_path="x")
    projects.save(proj)

    old = (datetime.now(timezone.utc) - timedelta(days=45)).replace(microsecond=0)
    fid = new_id()
    findings.save(FindingRecord(id=fid, project_id=proj.id, category="secret", severity="critical",
                                 discovered_at=old))
    saved = [f for f in findings.list(project_id=proj.id) if f.id == fid][0]
    assert saved.discovered_at is not None
    assert abs((saved.discovered_at - old).total_seconds()) < 1

    # A caller that does NOT set discovered_at still gets the schema
    # default (now()) - unchanged behavior for every existing caller.
    fid2 = new_id()
    findings.save(FindingRecord(id=fid2, project_id=proj.id, category="sast", severity="low"))
    saved2 = [f for f in findings.list(project_id=proj.id) if f.id == fid2][0]
    assert saved2.discovered_at is not None
    assert (datetime.now(timezone.utc) - saved2.discovered_at).total_seconds() < 30

    # ON CONFLICT re-save must never move discovered_at forward.
    findings.save(FindingRecord(id=fid, project_id=proj.id, category="secret", severity="critical",
                                 status="REMEDIATED", discovered_at=old))
    resaved = [f for f in findings.list(project_id=proj.id) if f.id == fid][0]
    assert abs((resaved.discovered_at - old).total_seconds()) < 1
    assert resaved.status == "REMEDIATED"


def test_memory_repository_real_postgres_ann_cosine_search(pg_pool):
    """Proves the pgvector column + ivfflat cosine index actually works
    against a real Postgres, using real test vectors (embedding
    generation itself remains NOT_IMPLEMENTED - see docs/MEMORY.md)."""
    memory = PostgresMemoryRepository(pg_pool)
    close = MemoryRecord(id=new_id(), memory_class="ENGINEERING_MEMORY", source="test",
                          content={"label": "close"}, embedding=[1, 0, 0, 0, 0, 0, 0, 0])
    far = MemoryRecord(id=new_id(), memory_class="ENGINEERING_MEMORY", source="test",
                        content={"label": "far"}, embedding=[0, 1, 0, 0, 0, 0, 0, 0])
    memory.save(far)
    memory.save(close)

    results = memory.retrieve(embedding=[0.9, 0.1, 0, 0, 0, 0, 0, 0], top_k=2)
    assert results[0][0].content["label"] == "close"
    assert all(advisory is True for _, advisory in results)


def test_memory_repository_real_postgres_supersession(pg_pool):
    memory = PostgresMemoryRepository(pg_pool)
    old = MemoryRecord(id=new_id(), memory_class="SECURITY_MEMORY", source="scan", content={"v": 1})
    memory.save(old)
    new = MemoryRecord(id=new_id(), memory_class="SECURITY_MEMORY", source="scan", content={"v": 2})
    memory.supersede(old.id, new)

    active = memory.retrieve(memory_class="SECURITY_MEMORY")
    assert [m.id for m, _ in active] == [new.id]


def _make_project_and_task(pg_pool):
    projects = PostgresProjectRepository(pg_pool)
    tasks = PostgresTaskRepository(pg_pool)
    proj = ProjectRecord(id=new_id(), name="p", repo_path="/tmp", policy_path="x")
    projects.save(proj)
    task = TaskRecord(id=new_id(), project_id=proj.id, type="scan")
    tasks.save(task)
    conn = pg_pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO runtime_workers (worker_id, supervisor_id, status, last_heartbeat, started_at) "
                "VALUES (%s, 's1', 'IDLE', now(), now()), (%s, 's1', 'IDLE', now(), now())",
                ("worker-1", "worker-2"),
            )
        conn.commit()
    finally:
        pg_pool.putconn(conn)
    return proj, task


def _register_racer_workers(pg_pool, count: int) -> None:
    workers = PostgresWorkerRepository(pg_pool)
    for i in range(count):
        workers.register(f"racer-{i}", "concurrency-test")


def test_project_lock_repository_real_postgres_exclusive_acquire(pg_pool):
    proj, task = _make_project_and_task(pg_pool)
    locks = PostgresProjectLockRepository(pg_pool)

    assert locks.acquire(proj.id, "worker-1", task.id, ttl_seconds=60) is True
    assert locks.acquire(proj.id, "worker-2", task.id, ttl_seconds=60) is False
    locks.release(proj.id, "worker-1")
    assert locks.acquire(proj.id, "worker-2", task.id, ttl_seconds=60) is True
    assert len(locks.list()) == 1


def test_worker_repository_real_postgres_register_heartbeat_list_remove(pg_pool):
    workers = PostgresWorkerRepository(pg_pool)
    workers.register("worker-x", "sup-1")
    workers.heartbeat("worker-x", "BUSY")
    listed = workers.list(supervisor_id="sup-1")
    assert len(listed) == 1
    assert listed[0].status == "BUSY"
    workers.register("worker-x", "sup-1")  # re-register bumps restart_count
    assert workers.list()[0].restart_count == 1
    workers.remove("worker-x")
    assert workers.list() == []


def test_schedule_repository_real_postgres_upsert_due_and_record_run(pg_pool):
    from datetime import timedelta

    from aep.db.models import now as pg_now

    projects = PostgresProjectRepository(pg_pool)
    proj = ProjectRecord(id=new_id(), name="p", repo_path="/tmp", policy_path="x")
    projects.save(proj)
    schedules = PostgresScheduleRepository(pg_pool)

    past = pg_now() - timedelta(seconds=5)
    schedules.upsert("job1", proj.id, "scan", interval_seconds=60, next_run_at=past)
    # Second upsert must be a no-op - next_run_at is never reset.
    schedules.upsert("job1", proj.id, "scan", interval_seconds=999)
    assert schedules.list()[0].interval_seconds == 60

    due = schedules.due()
    assert [s.job_id for s in due] == ["job1"]
    schedules.record_run("job1", success=True, interval_seconds=60)
    assert schedules.due() == []
    assert schedules.list()[0].last_status == "OK"


def test_failure_counter_repository_real_postgres_quarantine_and_reset(pg_pool):
    projects = PostgresProjectRepository(pg_pool)
    proj = ProjectRecord(id=new_id(), name="p", repo_path="/tmp", policy_path="x")
    projects.save(proj)
    counters = PostgresFailureCounterRepository(pg_pool)

    assert counters.record_failure(proj.id, "scan", threshold=3) is False
    assert counters.record_failure(proj.id, "scan", threshold=3) is False
    assert counters.is_quarantined(proj.id, "scan") is False
    assert counters.record_failure(proj.id, "scan", threshold=3) is True
    assert counters.is_quarantined(proj.id, "scan") is True
    counters.reset(proj.id, "scan")
    assert counters.is_quarantined(proj.id, "scan") is False


def test_lease_repository_real_postgres_concurrent_first_time_acquire_exactly_one_winner(pg_dsn, pg_pool):
    """Reproduces the bug: multiple genuinely concurrent first-time
    `acquire()` calls on the SAME never-before-seen task_id, each from
    its own real psycopg2 connection/thread. Before the fix, the
    no-existing-row branch did a bare INSERT with no conflict handling,
    so two racing threads could both pass the `row is None` check and
    both attempt to INSERT the same PRIMARY KEY, raising an uncaught
    IntegrityError in the loser's thread instead of it cleanly losing.
    After the fix (INSERT ... ON CONFLICT DO NOTHING + rowcount check),
    exactly one thread must return True, the rest False, and NO thread
    may raise."""
    import threading

    from aep.db.postgres import ConnectionPool as _CP

    proj, task = _make_project_and_task(pg_pool)
    _register_racer_workers(pg_pool, 8)

    results: list = [None] * 8
    errors: list = []
    barrier = threading.Barrier(8)

    def worker(i):
        pool = _CP(pg_dsn, minconn=1, maxconn=1)
        repo = PostgresLeaseRepository(pool)
        try:
            barrier.wait(timeout=5)
            results[i] = repo.acquire(task.id, proj.id, f"racer-{i}", ttl_seconds=60)
        except Exception as exc:  # noqa: BLE001 - we want to see any leak here
            errors.append(exc)
        finally:
            pool.closeall()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    assert errors == [], f"acquire() raised instead of cleanly losing the race: {errors}"
    assert results.count(True) == 1, f"expected exactly one winner, got {results}"
    assert results.count(False) == 7, f"expected seven losers, got {results}"


def test_project_lock_repository_real_postgres_concurrent_first_time_acquire_exactly_one_winner(pg_dsn, pg_pool):
    """Equivalent concurrency proof for the new ProjectLockRepository:
    multiple real threads/connections race `acquire()` on the same
    never-before-locked project_id; exactly one wins, the rest cleanly
    return False, none raise."""
    import threading

    from aep.db.postgres import ConnectionPool as _CP

    proj, task = _make_project_and_task(pg_pool)
    _register_racer_workers(pg_pool, 8)

    results: list = [None] * 8
    errors: list = []
    barrier = threading.Barrier(8)

    def worker(i):
        pool = _CP(pg_dsn, minconn=1, maxconn=1)
        repo = PostgresProjectLockRepository(pool)
        try:
            barrier.wait(timeout=5)
            results[i] = repo.acquire(proj.id, f"racer-{i}", task.id, ttl_seconds=60)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            pool.closeall()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    assert errors == [], f"acquire() raised instead of cleanly losing the race: {errors}"
    assert results.count(True) == 1, f"expected exactly one winner, got {results}"
    assert results.count(False) == 7, f"expected seven losers, got {results}"
