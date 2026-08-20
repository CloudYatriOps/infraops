"""Operations incident-memory capability (Phase 7 Part 9), exposed through
the existing capability-scoped tool registry - the exact same pattern
`deployment_tool.py` uses for deployment evidence. Never gives an agent
raw StateStore access (ARCHITECTURE.md §5: agents only touch what
AgentContext exposes); the operations agent goes through this tool for
every incident-memory read/write.
"""
from __future__ import annotations

from ..operations.memory import IncidentMemoryRecord, find_similar, list_incidents, record_incident
from ..state_store import StateStore
from ..tool_registry import Tool

CAPABILITIES = {"operations.record_incident", "operations.list_incidents",
                 "operations.find_similar_incidents"}


def _build_handler(store: StateStore):
    def _handler(capability: str, **kwargs) -> dict:
        if capability == "operations.record_incident":
            record_incident(store, kwargs["project_id"], IncidentMemoryRecord.from_dict(kwargs["record"]))
            return {"ok": True}
        if capability == "operations.list_incidents":
            records = list_incidents(store, kwargs["project_id"])
            return {"ok": True, "data": [r.to_dict() for r in records]}
        if capability == "operations.find_similar_incidents":
            records = find_similar(store, kwargs["project_id"], kwargs["fingerprint"])
            return {"ok": True, "data": [r.to_dict() for r in records]}
        raise ValueError(f"unsupported capability for operations tool: {capability}")
    return _handler


def build_operations_tool(store: StateStore) -> Tool:
    from ..models import RiskLevel
    return Tool(
        name="operations",
        capabilities=set(CAPABILITIES),
        risk=RiskLevel.LOW,
        description="Durable operational incident memory (Part 9), backed by the platform's "
                     "existing StateStore - advisory-only retrieval, never an override of "
                     "current evidence/policy.",
        handler=_build_handler(store),
    )
