from aep.models import Event, Task, TaskStatus
from aep.state_store import StateStore


def test_save_and_get_task(tmp_path):
    store = StateStore(str(tmp_path / "state.db"))
    task = Task(id="t1", type="recon", project_id="p1")
    store.save_task(task)

    loaded = store.get_task("t1")
    assert loaded is not None
    assert loaded.id == "t1"
    assert loaded.status == TaskStatus.PENDING
    assert loaded.created_at != ""
    store.close()


def test_list_tasks_filters_by_status(tmp_path):
    store = StateStore(str(tmp_path / "state.db"))
    t1 = Task(id="t1", type="recon", project_id="p1", status=TaskStatus.SUCCEEDED)
    t2 = Task(id="t2", type="recon", project_id="p1", status=TaskStatus.PENDING)
    store.save_task(t1)
    store.save_task(t2)

    pending = store.list_tasks("p1", statuses=[TaskStatus.PENDING])
    assert [t.id for t in pending] == ["t2"]
    store.close()


def test_append_only_event_log_is_queryable(tmp_path):
    store = StateStore(str(tmp_path / "state.db"))
    store.append_event(Event(id="e1", actor="orchestrator", action="task_started",
                              project_id="p1", task_id="t1", decision=None,
                              timestamp="", details={"note": "started"}))
    store.append_event(Event(id="e2", actor="orchestrator", action="task_succeeded",
                              project_id="p1", task_id="t1", decision=None,
                              timestamp="", details={}))

    events = store.query_events(project_id="p1", task_id="t1")
    assert [e.action for e in events] == ["task_started", "task_succeeded"]
    store.close()


def test_crash_recovery_resumes_from_durable_state(tmp_path):
    """Simulates a process crash: a StateStore instance writes some task
    state and is discarded WITHOUT clean shutdown of any in-memory
    scheduler; a brand-new StateStore pointed at the same file must see
    everything the first one committed."""
    db_path = str(tmp_path / "state.db")

    store_a = StateStore(db_path)
    t1 = Task(id="t1", type="recon", project_id="p1", status=TaskStatus.RUNNING)
    store_a.save_task(t1)
    store_a.append_event(Event(id="e1", actor="orchestrator", action="task_started",
                                project_id="p1", task_id="t1", decision=None,
                                timestamp="", details={}))
    # No explicit close() / clean shutdown - simulating a kill -9.
    del store_a

    store_b = StateStore(db_path)
    recovered = store_b.get_task("t1")
    assert recovered is not None
    assert recovered.status == TaskStatus.RUNNING  # exactly as left by the "crashed" process
    events = store_b.query_events(project_id="p1")
    assert len(events) == 1
    store_b.close()


def test_failure_counter_circuit_breaker(tmp_path):
    store = StateStore(str(tmp_path / "state.db"))
    quarantined = False
    for _ in range(5):
        quarantined = store.record_failure("p1", "code_fix", threshold=5)
    assert quarantined is True
    assert store.is_quarantined("p1", "code_fix") is True

    store.reset_failure_counter("p1", "code_fix")
    assert store.is_quarantined("p1", "code_fix") is False
    store.close()
