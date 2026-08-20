"""Part 7: closed-loop task chain construction.

DETECT -> COLLECT EVIDENCE -> CORRELATE -> DIAGNOSE -> PLAN -> POLICY CHECK
-> APPROVAL IF REQUIRED -> REMEDIATE -> VERIFY -> MONITOR FOR RECURRENCE ->
CLOSE OR ESCALATE, built entirely from the EXISTING orchestrator/task-graph
follow_up_tasks mechanism (Phase 5/6 Part 11 pattern) - no independent
orchestration system.
"""
from __future__ import annotations

import uuid

from ..models import RiskLevel, Task


def build_remediation_task(project_id: str, incident: dict, diagnosis: dict, action: dict,
                            environment: str) -> Task:
    return Task(
        id=str(uuid.uuid4()), type="operations_remediate", project_id=project_id,
        owner_agent="operations_intelligence_agent", max_attempts=1,
        risk=RiskLevel.HIGH if environment == "production" else RiskLevel.MEDIUM,
        payload={"mode": "remediate", "incident": incident, "diagnosis": diagnosis,
                 "action": action, "environment": environment},
    )


def build_rescan_task(project_id: str, incident: dict, action: dict, environment: str) -> Task:
    return Task(
        id=str(uuid.uuid4()), type="operations_rescan", project_id=project_id,
        owner_agent="operations_intelligence_agent", max_attempts=1,
        payload={"mode": "rescan", "incident": incident, "action": action,
                 "environment": environment},
    )


def build_escalate_task(project_id: str, incident: dict, diagnosis: dict, reason: str,
                         attempted: list[str] | None = None) -> Task:
    return Task(
        id=str(uuid.uuid4()), type="operations_escalate", project_id=project_id,
        owner_agent="operations_intelligence_agent", max_attempts=1,
        payload={"mode": "escalate", "incident": incident, "diagnosis": diagnosis,
                 "reason": reason, "attempted": attempted or []},
    )
