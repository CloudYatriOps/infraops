"""Fast unit tests against the in-memory fake repository double - zero
network/Postgres dependency, always run."""
from __future__ import annotations

from aep.db.fake import (
    FakeEventRepository,
    FakeFailureCounterRepository,
    FakeFindingRepository,
    FakeLeaseRepository,
    FakeMemoryRepository,
    FakeProjectLockRepository,
    FakeProjectRepository,
    FakeScheduleRepository,
    FakeTaskRepository,
    FakeWorkerRepository,
)
from aep.db.models import EventRecord, FindingRecord, MemoryRecord, ProjectRecord, TaskRecord, new_id, now


def test_project_repository_save_and_get_roundtrip():
    repo = FakeProjectRepository()
    p = ProjectRecord(id=new_id(), name="demo", repo_path="/tmp/demo", policy_path="config/policy.yaml")
    repo.save(p)
    fetched = repo.get(p.id)
    assert fetched is not None
    assert fetched.name == "demo"
    assert fetched.created_at is not None and fetched.updated_at is not None


def test_project_repository_list():
    repo = FakeProjectRepository()
    for i in range(3):
        repo.save(ProjectRecord(id=new_id(), name=f"p{i}", repo_path="/tmp", policy_path="x"))
    assert len(repo.list()) == 3


def test_task_repository_filters_by_project_and_status():
    repo = FakeTaskRepository()
    proj_a, proj_b = new_id(), new_id()
    repo.save(TaskRecord(id=new_id(), project_id=proj_a, type="scan", status="PENDING"))
    repo.save(TaskRecord(id=new_id(), project_id=proj_a, type="scan", status="SUCCEEDED"))
    repo.save(TaskRecord(id=new_id(), project_id=proj_b, type="scan", status="PENDING"))

    assert len(repo.list(project_id=proj_a)) == 2
    assert len(repo.list(project_id=proj_a, status="PENDING")) == 1
    assert len(repo.list(status="SUCCEEDED")) == 1


def test_event_repository_append_only_and_query_filters():
    repo = FakeEventRepository()
    proj = new_id()
    task = new_id()
    repo.append(EventRecord(id=new_id(), project_id=proj, task_id=task, actor="agent", action="scan"))
    repo.append(EventRecord(id=new_id(), project_id=proj, task_id=None, actor="agent", action="discover"))
    assert len(repo.query(project_id=proj)) == 2
    assert len(repo.query(project_id=proj, task_id=task)) == 1


def test_lease_repository_exclusive_acquire_and_release():
    repo = FakeLeaseRepository()
    proj, task = new_id(), new_id()
    assert repo.acquire(task, proj, "worker-1", ttl_seconds=60) is True
    # A different worker cannot acquire while the lease is live.
    assert repo.acquire(task, proj, "worker-2", ttl_seconds=60) is False
    # The same worker can re-acquire (renew).
    assert repo.acquire(task, proj, "worker-1", ttl_seconds=60) is True
    repo.release(task, "worker-1")
    assert repo.acquire(task, proj, "worker-2", ttl_seconds=60) is True


def test_finding_repository_filters_by_severity():
    repo = FakeFindingRepository()
    proj = new_id()
    repo.save(FindingRecord(id=new_id(), project_id=proj, category="secret", severity="critical"))
    repo.save(FindingRecord(id=new_id(), project_id=proj, category="sast", severity="low"))
    assert len(repo.list(project_id=proj, severity="critical")) == 1
    assert len(repo.list(project_id=proj)) == 2


def test_memory_retrieval_is_always_advisory_and_never_mutates_caller_state():
    repo = FakeMemoryRepository()
    proj = new_id()
    m = MemoryRecord(id=new_id(), memory_class="OPERATIONAL_MEMORY", source="rca",
                      project_scope=proj, content={"note": "past incident X was a DNS failure"})
    repo.save(m)

    results = repo.retrieve(memory_class="OPERATIONAL_MEMORY", project_scope=proj)
    assert len(results) == 1
    record, advisory = results[0]
    assert advisory is True  # caller must decide what to do with this - never authoritative
    assert record.content["note"] == "past incident X was a DNS failure"


def test_memory_ann_search_orders_by_cosine_similarity():
    repo = FakeMemoryRepository()
    proj = new_id()
    close = MemoryRecord(id=new_id(), memory_class="ENGINEERING_MEMORY", source="test",
                          project_scope=proj, content={}, embedding=[1.0, 0.0, 0.0])
    far = MemoryRecord(id=new_id(), memory_class="ENGINEERING_MEMORY", source="test",
                        project_scope=proj, content={}, embedding=[0.0, 1.0, 0.0])
    repo.save(far)
    repo.save(close)
    results = repo.retrieve(embedding=[0.9, 0.1, 0.0], top_k=2)
    assert results[0][0].id == close.id


def test_memory_supersession_preserves_old_record_and_points_forward():
    repo = FakeMemoryRepository()
    proj = new_id()
    old = MemoryRecord(id=new_id(), memory_class="SECURITY_MEMORY", source="scan",
                        project_scope=proj, content={"finding": "v1"})
    repo.save(old)
    new = MemoryRecord(id=new_id(), memory_class="SECURITY_MEMORY", source="scan",
                        project_scope=proj, content={"finding": "v2"})
    repo.supersede(old.id, new)

    active = [m for m, _ in repo.retrieve(memory_class="SECURITY_MEMORY", project_scope=proj)]
    assert [m.id for m in active] == [new.id]
    assert repo._data[old.id].lifecycle_state == "SUPERSEDED"
    assert repo._data[old.id].superseded_by == new.id


def test_project_lock_repository_exclusive_acquire_and_release():
    repo = FakeProjectLockRepository()
    proj, task = new_id(), new_id()
    assert repo.acquire(proj, "worker-1", task, ttl_seconds=60) is True
    assert repo.acquire(proj, "worker-2", task, ttl_seconds=60) is False
    # Same worker can re-acquire/renew.
    assert repo.acquire(proj, "worker-1", task, ttl_seconds=60) is True
    repo.release(proj, "worker-1")
    assert repo.acquire(proj, "worker-2", task, ttl_seconds=60) is True
    assert len(repo.list()) == 1


def test_worker_repository_register_heartbeat_list_remove():
    repo = FakeWorkerRepository()
    repo.register("w1", "sup1")
    repo.heartbeat("w1", "BUSY")
    workers = repo.list(supervisor_id="sup1")
    assert len(workers) == 1
    assert workers[0].status == "BUSY"
    # Re-registering bumps restart_count (mirrors StateStore.register_worker).
    repo.register("w1", "sup1")
    assert repo.list()[0].restart_count == 1
    repo.remove("w1")
    assert repo.list() == []


def test_schedule_repository_upsert_never_resets_next_run_at():
    repo = FakeScheduleRepository()
    proj = new_id()
    repo.upsert("job1", proj, "scan", interval_seconds=60)
    first = repo.list()[0]
    # Second upsert with a different interval must be a no-op.
    repo.upsert("job1", proj, "scan", interval_seconds=999)
    assert repo.list()[0].next_run_at == first.next_run_at
    assert repo.list()[0].interval_seconds == 60


def test_schedule_repository_due_and_record_run():
    from datetime import timedelta
    repo = FakeScheduleRepository()
    proj = new_id()
    past = now() - timedelta(seconds=5)
    repo.upsert("job1", proj, "scan", interval_seconds=60, next_run_at=past)
    assert [s.job_id for s in repo.due()] == ["job1"]
    repo.record_run("job1", success=True, interval_seconds=60)
    assert repo.due() == []
    assert repo.list()[0].last_status == "OK"
    repo.upsert("job2", proj, "scan", interval_seconds=60, next_run_at=past)
    repo.record_run("job2", success=False, interval_seconds=60)
    job2 = [s for s in repo.list() if s.job_id == "job2"][0]
    assert job2.last_status == "FAILED"
    assert job2.consecutive_failures == 1


def test_failure_counter_repository_quarantines_at_threshold_and_resets():
    repo = FakeFailureCounterRepository()
    proj = new_id()
    assert repo.record_failure(proj, "scan", threshold=3) is False
    assert repo.record_failure(proj, "scan", threshold=3) is False
    assert repo.is_quarantined(proj, "scan") is False
    assert repo.record_failure(proj, "scan", threshold=3) is True
    assert repo.is_quarantined(proj, "scan") is True
    repo.reset(proj, "scan")
    assert repo.is_quarantined(proj, "scan") is False
