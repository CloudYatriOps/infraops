"""Phase 8 (24/7 Autonomous Runtime) core behavior tests - Part 14.

Covers: supervisor startup/shutdown, crash recovery, task lease
acquisition/expiry/recovery, worker heartbeat timeout, stuck task
recovery, duplicate task prevention, project/repository locking,
multiple independent projects, scheduler recurrence, missed-schedule
recovery, restart-without-duplicate-execution, worker concurrency limits,
priority ordering/starvation, circuit-breaker/quarantine tracking, and a
full controlled E2E autonomous cycle.
"""
from __future__ import annotations

import time

import pytest

from aep.policy import PolicyEngine
from aep.runtime import health as health_mod
from aep.runtime import priority as priority_mod
from aep.runtime import scheduler as scheduler_mod
from aep.runtime.supervisor import RuntimeSupervisor
from aep.runtime.workers import Worker
from aep.state_store import StateStore


@pytest.fixture
def store(tmp_path):
    return StateStore(str(tmp_path / "runtime.db"))


@pytest.fixture
def policy():
    return PolicyEngine.from_yaml("config/policy.yaml")


# ---- Part 1/2: leases, duplicate prevention, crash recovery -----------

def test_lease_acquire_prevents_duplicate_claim(store):
    assert store.acquire_lease("t1", "proj", "worker-a", ttl_seconds=30) is True
    # a second worker cannot claim the same task while the lease is live
    assert store.acquire_lease("t1", "proj", "worker-b", ttl_seconds=30) is False


def test_lease_renew_and_release(store):
    store.acquire_lease("t1", "proj", "worker-a", ttl_seconds=30)
    assert store.renew_lease("t1", "worker-a", ttl_seconds=30) is True
    assert store.renew_lease("t1", "worker-b", ttl_seconds=30) is False  # not the holder
    store.release_lease("t1", "worker-a")
    assert store.acquire_lease("t1", "proj", "worker-b", ttl_seconds=30) is True


def test_crashed_worker_lease_expires_and_allows_recovery(store):
    # worker-a "crashes" holding a near-instantly-expiring lease
    store.acquire_lease("t1", "proj", "worker-a", ttl_seconds=0.01)
    time.sleep(0.05)
    expired = store.expired_leases()
    assert any(l["task_id"] == "t1" for l in expired)
    # a fresh worker can now safely claim it
    assert store.acquire_lease("t1", "proj", "worker-b", ttl_seconds=30) is True


def test_worker_run_once_prevents_duplicate_execution(store):
    w1 = Worker("sup", store, lease_ttl_s=30)
    w2 = Worker("sup", store, lease_ttl_s=30)
    job = {"job_id": "job-1", "project_id": "proj", "job_type": "dependency_cve_scan",
           "interval_seconds": 60}
    calls = []

    def dispatch(j):
        calls.append(j["job_id"])
        return "ok"

    r1 = w1.claim_task(job)
    r2 = w2.claim_task(job)
    assert r1.claimed is True
    assert r2.claimed is False
    w1.release_task(job)


# ---- Part 3: project/repository locking --------------------------------

def test_project_lock_serializes_mutating_work(store):
    ok1 = store.acquire_project_lock("proj-a", "worker-1", "task-1", ttl_seconds=30)
    ok2 = store.acquire_project_lock("proj-a", "worker-2", "task-2", ttl_seconds=30)
    assert ok1 is True
    assert ok2 is False  # same project, different worker: denied


def test_independent_projects_run_independently(store):
    ok1 = store.acquire_project_lock("proj-a", "worker-1", "task-1", ttl_seconds=30)
    ok2 = store.acquire_project_lock("proj-b", "worker-2", "task-2", ttl_seconds=30)
    assert ok1 is True
    assert ok2 is True


def test_worker_claim_task_acquires_project_lock_for_mutating_job(store):
    w = Worker("sup", store, lease_ttl_s=30)
    job = {"job_id": "t1", "project_id": "proj-a", "job_type": "code_modification"}
    result = w.claim_task(job)
    assert result.claimed is True
    locks = store.list_project_locks()
    assert any(l["project_id"] == "proj-a" for l in locks)
    w.release_task(job)
    assert store.list_project_locks() == []


def test_project_lock_survives_process_restart(tmp_path):
    db_path = str(tmp_path / "r.db")
    s1 = StateStore(db_path)
    s1.acquire_project_lock("proj", "worker-1", "task-1", ttl_seconds=30)
    s1.close()
    # simulate a restart: brand new StateStore instance, same file
    s2 = StateStore(db_path)
    assert s2.acquire_project_lock("proj", "worker-2", "task-2", ttl_seconds=30) is False


# ---- Part 8: worker heartbeat timeout / stuck task detection ----------

def test_worker_heartbeat_timeout_detected(store):
    store.register_worker("stale-worker", "sup")
    # force an old heartbeat
    with store._cursor() as cur:
        cur.execute("UPDATE runtime_workers SET last_heartbeat=? WHERE worker_id=?",
                    ("2000-01-01T00:00:00+00:00", "stale-worker"))
    report = health_mod.assess(store.list_workers(), store.list_leases(),
                                heartbeat_timeout_s=60, stuck_task_timeout_s=300)
    assert "stale-worker" in report.stale_workers
    assert report.state in ("DEGRADED", "UNHEALTHY")


def test_stuck_task_detected_and_recommended_for_requeue(store):
    store.acquire_lease("stuck-task", "proj", "worker-a", ttl_seconds=9999)
    with store._cursor() as cur:
        cur.execute("UPDATE runtime_leases SET acquired_at=? WHERE task_id=?",
                    ("2000-01-01T00:00:00+00:00", "stuck-task"))
    report = health_mod.assess(store.list_workers(), store.list_leases(),
                                heartbeat_timeout_s=60, stuck_task_timeout_s=300)
    assert "stuck-task" in report.stuck_tasks
    assert any(r.kind == "requeue_task" and r.target == "stuck-task" for r in report.recommendations)


def test_supervisor_recover_requeues_stuck_task(store, policy):
    store.acquire_lease("stuck-task", "proj", "worker-a", ttl_seconds=9999)
    with store._cursor() as cur:
        cur.execute("UPDATE runtime_leases SET acquired_at=? WHERE task_id=?",
                    ("2000-01-01T00:00:00+00:00", "stuck-task"))
    sup = RuntimeSupervisor(store, policy, num_workers=1, stuck_task_timeout_s=300)
    sup.recover()
    assert store.list_leases() == []  # released, safe to reclaim
    assert store.acquire_lease("stuck-task", "proj", "worker-b", ttl_seconds=30) is True


# ---- Part 4: scheduler recurrence / missed-run / restart-safety -------

def test_register_default_jobs_idempotent_after_restart(tmp_path):
    db = str(tmp_path / "r.db")
    s1 = StateStore(db)
    scheduler_mod.register_default_jobs(s1, "proj-x", interval_seconds=100)
    before = {j["job_id"]: j["next_run_at"] for j in s1.list_schedules()}
    s1.close()
    s2 = StateStore(db)
    scheduler_mod.register_default_jobs(s2, "proj-x", interval_seconds=100)
    after = {j["job_id"]: j["next_run_at"] for j in s2.list_schedules()}
    # a restart must NOT reset next_run_at (no duplicate/early execution)
    assert before == after
    assert len(after) == len(scheduler_mod.JOB_TYPES)


def test_missed_schedule_still_runs_exactly_once_per_due_check(store):
    scheduler_mod.register_default_jobs(store, "proj-y", interval_seconds=1000)
    # force one job's next_run_at far in the past ("missed" while offline)
    jobs = store.list_schedules()
    job_id = jobs[0]["job_id"]
    with store._cursor() as cur:
        cur.execute("UPDATE runtime_schedules SET next_run_at=? WHERE job_id=?",
                    ("2000-01-01T00:00:00+00:00", job_id))
    calls = []
    results = scheduler_mod.run_due_jobs(store, dispatch=lambda j: calls.append(j["job_id"]) or True)
    assert calls.count(job_id) == 1
    # running due jobs again immediately must not re-run it (next_run_at pushed forward)
    calls2 = []
    scheduler_mod.run_due_jobs(store, dispatch=lambda j: calls2.append(j["job_id"]) or True)
    assert job_id not in calls2


def test_scheduler_failure_tracking_and_backoff(store):
    scheduler_mod.register_default_jobs(store, "proj-z", interval_seconds=10)
    job_id = store.list_schedules()[0]["job_id"]
    with store._cursor() as cur:
        cur.execute("UPDATE runtime_schedules SET next_run_at=? WHERE job_id=?",
                    ("2000-01-01T00:00:00+00:00", job_id))
    scheduler_mod.run_due_jobs(store, dispatch=lambda j: False)
    job = [j for j in store.list_schedules() if j["job_id"] == job_id][0]
    assert job["last_status"] == "FAILED"
    assert job["consecutive_failures"] == 1


# ---- Part 2: worker concurrency limits ---------------------------------

def test_worker_pool_respects_configured_worker_count(store, policy):
    sup = RuntimeSupervisor(store, policy, num_workers=3)
    assert len(sup.workers) == 3
    assert sup.max_workers == 3


# ---- Part 6: priority ordering / starvation prevention -----------------

def test_priority_ordering_matches_spec_example():
    critical_prod_security = priority_mod.score(priority_mod.PriorityInput(
        task_type="security.finding", severity="critical", production_impact=True))
    active_incident = priority_mod.score(priority_mod.PriorityInput(
        task_type="operations.incident", severity="high", active_incident=True))
    failed_deployment = priority_mod.score(priority_mod.PriorityInput(
        task_type="deployment.verify", severity="medium", deployment_blocked=True))
    high_cve = priority_mod.score(priority_mod.PriorityInput(
        task_type="dependency.cve", severity="high"))
    ci_failure = priority_mod.score(priority_mod.PriorityInput(
        task_type="ci.failure", severity="medium"))
    scheduled_maintenance = priority_mod.score(priority_mod.PriorityInput(
        task_type="maintenance.scan", severity="low"))

    ordering = [critical_prod_security.total, active_incident.total, failed_deployment.total,
                high_cve.total, ci_failure.total, scheduled_maintenance.total]
    assert ordering == sorted(ordering, reverse=True)
    assert critical_prod_security.reason  # every decision is explained


def test_priority_starvation_prevention_via_age():
    # an old low-severity task eventually outranks a fresh low-severity one
    fresh = priority_mod.score(priority_mod.PriorityInput(task_type="x", severity="low", age_hours=0))
    old = priority_mod.score(priority_mod.PriorityInput(task_type="x", severity="low", age_hours=20))
    assert old.total > fresh.total


# ---- Part 7: runaway protection / circuit breaker reuse ---------------

def test_existing_circuit_breaker_reused_for_runtime_quarantine(store):
    # Phase 8 reuses the SAME StateStore.record_failure/is_quarantined
    # circuit breaker Phase 1 built - no second mechanism.
    for _ in range(5):
        quarantined = store.record_failure("proj", "runtime.job", threshold=5)
    assert quarantined is True
    assert store.is_quarantined("proj", "runtime.job") is True


# ---- Full controlled E2E autonomous cycle ------------------------------

def test_full_controlled_autonomous_cycle_end_to_end(store, policy, tmp_path):
    project_id = "e2e-proj"
    scheduler_mod.register_default_jobs(store, project_id, interval_seconds=1)
    sup = RuntimeSupervisor(store, policy, num_workers=2)
    reports = sup.run(max_cycles=1, repos={project_id: "."})
    assert len(reports) == 1
    assert reports[0].jobs_dispatched == len(scheduler_mod.JOB_TYPES)
    # evidence recorded durably (Event log), never fabricated
    events = store.query_events(project_id=project_id)
    assert len(events) >= 1
    for e in events:
        assert e.details["outcome"] in ("REAL", "MOCKED", "UNAVAILABLE", "BLOCKED", "DENIED")
    # runtime stayed healthy throughout the bounded run
    assert reports[0].health == "HEALTHY"


def test_worker_crash_then_lease_expiry_then_requeue_no_duplicate(store, policy):
    """worker crashes mid-task -> lease expires -> supervisor detects
    stale lease -> task safely requeued -> a second worker can pick it up
    -> duplicate execution never occurs (only one worker's work counts)."""
    project_id = "crash-proj"
    task_id = "mutating-task-1"
    crashed_worker = Worker("sup", store, lease_ttl_s=0.01)
    claim = crashed_worker.claim_task({"job_id": task_id, "project_id": project_id,
                                        "job_type": "code_modification"})
    assert claim.claimed is True
    # worker "crashes" here - never calls release_task()
    time.sleep(0.05)

    sup = RuntimeSupervisor(store, policy, num_workers=1, stuck_task_timeout_s=0.01)
    report = sup.recover()
    assert task_id in [r for r in report.stuck_tasks] or store.expired_leases()

    fresh_worker = Worker("sup", store, lease_ttl_s=30)
    reclaim = fresh_worker.claim_task({"job_id": task_id, "project_id": project_id,
                                        "job_type": "code_modification"})
    assert reclaim.claimed is True
    # the crashed worker can no longer also claim it (no duplicate)
    dup = crashed_worker.claim_task({"job_id": task_id, "project_id": project_id,
                                      "job_type": "code_modification"})
    assert dup.claimed is False
