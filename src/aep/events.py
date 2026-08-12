"""Thin helper for writing consistent, redacted audit events."""
from __future__ import annotations

import uuid
from typing import Optional

from .models import Event
from .redaction import redact_mapping
from .state_store import StateStore, now_iso


class EventLogger:
    def __init__(self, store: StateStore):
        self._store = store

    def log(self, actor: str, action: str, project_id: str,
             task_id: Optional[str] = None, decision: Optional[str] = None,
             details: Optional[dict] = None) -> Event:
        safe_details = redact_mapping(details or {})
        event = Event(
            id=str(uuid.uuid4()),
            actor=actor,
            action=action,
            project_id=project_id,
            task_id=task_id,
            decision=decision,
            timestamp=now_iso(),
            details=safe_details,
        )
        self._store.append_event(event)
        return event
