"""Part 9: Incident Memory, backed by the EXISTING StateStore/Event
mechanism - the exact pattern `deployment/evidence.py` already established
for durable deployment records. No new storage primitive is invented.

Critically: `find_similar` returns *advisory* evidence only. Nothing in
this module or its callers ever lets a historical remediation
automatically override current evidence/policy (Part 9) - see
`remediation.py`/the agent, which only ever CONSULT this as one more piece
of context alongside the current diagnosis, never as an instruction.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from ..models import Event
from ..state_store import StateStore, now_iso

INCIDENT_MEMORY_ACTION = "operations_incident_memory"


@dataclass
class IncidentMemoryRecord:
    fingerprint: str
    incident_id: str
    root_cause: str
    confidence: str
    remediation_used: str
    remediation_succeeded: bool
    environment: str | None
    evidence_refs: list[str] = field(default_factory=list)
    recorded_at: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "IncidentMemoryRecord":
        return IncidentMemoryRecord(**d)


def record_incident(store: StateStore, project_id: str, record: IncidentMemoryRecord) -> None:
    record.recorded_at = record.recorded_at or now_iso()
    store.append_event(Event(
        id="", actor="operations_intelligence_agent", action=INCIDENT_MEMORY_ACTION,
        project_id=project_id, task_id=record.incident_id,
        decision="SUCCEEDED" if record.remediation_succeeded else "FAILED",
        timestamp=record.recorded_at, details=record.to_dict(),
    ))


def list_incidents(store: StateStore, project_id: str) -> list[IncidentMemoryRecord]:
    events = store.query_events(project_id=project_id)
    return [IncidentMemoryRecord.from_dict(e.details) for e in events
            if e.action == INCIDENT_MEMORY_ACTION]


def find_similar(store: StateStore, project_id: str, fingerprint: str) -> list[IncidentMemoryRecord]:
    """"Similar incident occurred previously" lookup (Part 9) - matched on
    the SAME deterministic fingerprint `correlation.py` computes, oldest
    first. Advisory only: callers must never apply `remediation_used`
    automatically without re-evaluating current evidence/policy."""
    return [r for r in list_incidents(store, project_id) if r.fingerprint == fingerprint]
