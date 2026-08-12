"""Deployment evidence store (Phase 6 Part 13).

"Persist evidence for every deployment attempt... must survive process
restart." Reuses the EXISTING `StateStore`/`Event` durable machinery
(Phase 1's SQLite-backed event log, already crash-safe and already what
`progress/calculator.py::record_phase_verified` uses for its own durable
fact) rather than inventing a new storage primitive - exactly the same
choice Phase 3's `record_phase_verified` and Phase 4's suppression store
made.
"""
from __future__ import annotations

from ..models import Event
from ..state_store import StateStore, now_iso
from .models import DeploymentRecord

DEPLOYMENT_EVIDENCE_ACTION = "deployment_evidence"


def record_deployment(store: StateStore, project_id: str, record: DeploymentRecord) -> None:
    store.append_event(Event(
        id="", actor="deployment_agent", action=DEPLOYMENT_EVIDENCE_ACTION,
        project_id=project_id, task_id=record.task_id, decision=record.final_state.value,
        timestamp=now_iso(), details=record.to_dict(),
    ))


def list_deployment_evidence(store: StateStore, project_id: str) -> list[DeploymentRecord]:
    """Every deployment attempt ever recorded for this project, oldest
    first - reading back the SAME durable events `record_deployment`
    wrote, in a fresh `StateStore` instance if the caller constructs one,
    which is what makes this "survives a process restart" for real rather
    than by assertion (see `tests/test_deployment_evidence.py`)."""
    events = store.query_events(project_id=project_id)
    return [DeploymentRecord.from_dict(e.details) for e in events
            if e.action == DEPLOYMENT_EVIDENCE_ACTION]


def latest_deployment_evidence(store: StateStore, project_id: str,
                                task_id: str) -> DeploymentRecord | None:
    matches = [r for r in list_deployment_evidence(store, project_id) if r.task_id == task_id]
    return matches[-1] if matches else None
