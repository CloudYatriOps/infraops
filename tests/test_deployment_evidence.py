"""Deployment evidence durability (Phase 6 Part 13) - reuses the EXISTING
StateStore/Event machinery, so "survives a process restart" is verified
here by literally closing one StateStore and opening a NEW one against
the same file, exactly like Phase 3/4's durability tests do for
suppressions/verification events."""
from __future__ import annotations

from pathlib import Path

from aep.deployment.evidence import latest_deployment_evidence, list_deployment_evidence, record_deployment
from aep.deployment.models import DeploymentRecord, DeploymentState, VerificationCheck
from aep.state_store import StateStore


def _sample_record(task_id: str = "task-1") -> DeploymentRecord:
    return DeploymentRecord(
        task_id=task_id, commit_sha="abc123", artifact_id="artifact-1", environment="staging",
        release_gates_passed=True, approval_status="not_required", provider="local_fixture",
        provider_status="LOCAL_FIXTURE", rollout_status="ROLLOUT_COMPLETE",
        verification_results=[VerificationCheck("readiness", True, "2/2 ready")],
        final_state=DeploymentState.VERIFIED,
    )


def test_record_and_list_round_trips(tmp_path: Path):
    db_path = str(tmp_path / "state.db")
    store = StateStore(db_path)
    record_deployment(store, "proj1", _sample_record())
    records = list_deployment_evidence(store, "proj1")
    assert len(records) == 1
    assert records[0].commit_sha == "abc123"
    assert records[0].final_state == DeploymentState.VERIFIED


def test_evidence_survives_a_fresh_process_reopening_the_same_db(tmp_path: Path):
    db_path = str(tmp_path / "state.db")
    store1 = StateStore(db_path)
    record_deployment(store1, "proj1", _sample_record(task_id="task-durable"))
    del store1  # simulate the process ending

    store2 = StateStore(db_path)  # a brand-new StateStore instance, same file
    record = latest_deployment_evidence(store2, "proj1", "task-durable")
    assert record is not None
    assert record.task_id == "task-durable"
    assert record.final_state == DeploymentState.VERIFIED


def test_multiple_attempts_for_the_same_task_are_all_kept():
    """Evidence is append-only - a retried deployment task's earlier
    (e.g. BLOCKED) attempt is never overwritten by its later attempt."""
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        store = StateStore(f"{d}/s.db")
        try:
            first = _sample_record(task_id="task-2")
            first.final_state = DeploymentState.BLOCKED
            record_deployment(store, "proj1", first)
            second = _sample_record(task_id="task-2")
            record_deployment(store, "proj1", second)
            all_records = [r for r in list_deployment_evidence(store, "proj1") if r.task_id == "task-2"]
            assert len(all_records) == 2
            assert latest_deployment_evidence(store, "proj1", "task-2").final_state == DeploymentState.VERIFIED
        finally:
            # Windows holds an exclusive lock on the sqlite file until the
            # connection is explicitly closed - unlike POSIX, where an open
            # file can still be unlinked - so TemporaryDirectory's own
            # cleanup fails here without this.
            store.close()
