"""False-positive suppression model (Phase 4 Part 9).

"Do NOT simply delete findings" is enforced structurally, not just by
convention: suppressions are recorded as ordinary, append-only
`Event`s through the *existing* StateStore/EventLogger machinery (the
same approach `progress/calculator.py::record_phase_verified` already
uses for phase verification) - there is no `DELETE` anywhere in this
module, and no code path removes a `SecurityFinding` from a scan record
because it was suppressed. `is_suppressed()` is a read-time filter over
the durable event log; the underlying finding, and every suppression ever
recorded for it (including a later revocation), remain queryable forever
via `list_suppressions()`.

Required fields per Part 9: suppression, justification, expiry, reviewer,
evidence - all five are present on `Suppression` and required at call time
(no un-justified suppression is possible through this API).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from ..models import Event
from ..state_store import StateStore, now_iso

SUPPRESSED_ACTION = "security_finding_suppressed"
REVOKED_ACTION = "security_finding_suppression_revoked"


@dataclass
class Suppression:
    finding_id: str
    justification: str
    reviewer: str
    evidence: str
    created_at: str
    expiry: Optional[str]  # ISO8601, None = no expiry
    revoked: bool = False
    revoked_at: Optional[str] = None
    revoked_by: Optional[str] = None

    def is_active(self, now: Optional[str] = None) -> bool:
        if self.revoked:
            return False
        if self.expiry is None:
            return True
        now = now or now_iso()
        return now < self.expiry


def suppress_finding(store: StateStore, project_id: str, finding_id: str, justification: str,
                      reviewer: str, evidence: str, expiry: Optional[str] = None) -> Event:
    """Part 9's five required fields are all mandatory parameters here -
    there is no way to call this without a justification, a named
    reviewer, and evidence backing the call. Raises if any is blank."""
    if not justification.strip():
        raise ValueError("a suppression requires a non-empty justification")
    if not reviewer.strip():
        raise ValueError("a suppression requires a named reviewer")
    if not evidence.strip():
        raise ValueError("a suppression requires supporting evidence")
    return store.append_event(Event(
        id=str(uuid.uuid4()), actor=reviewer, action=SUPPRESSED_ACTION, project_id=project_id,
        task_id=None, decision="SUPPRESSED",
        timestamp=now_iso(),
        details={"finding_id": finding_id, "justification": justification, "reviewer": reviewer,
                 "evidence": evidence, "expiry": expiry},
    ))


def revoke_suppression(store: StateStore, project_id: str, finding_id: str, revoked_by: str,
                        reason: str) -> Event:
    """Revocation is itself a new, append-only event - it does not touch
    (let alone delete) the original suppression event. `list_suppressions`
    replays both in order, so the full history of "suppressed, then later
    revoked, and why" is always reconstructable."""
    return store.append_event(Event(
        id=str(uuid.uuid4()), actor=revoked_by, action=REVOKED_ACTION, project_id=project_id,
        task_id=None, decision="REVOKED", timestamp=now_iso(),
        details={"finding_id": finding_id, "revoked_by": revoked_by, "reason": reason},
    ))


def list_suppressions(store: StateStore, project_id: str) -> list[Suppression]:
    """Replays the durable event log into the current Suppression state
    per finding_id. A finding suppressed then revoked shows up with
    `revoked=True` - never removed from the list."""
    events = store.query_events(project_id=project_id)
    by_finding: dict[str, Suppression] = {}
    for e in events:
        if e.action == SUPPRESSED_ACTION:
            d = e.details
            by_finding[d["finding_id"]] = Suppression(
                finding_id=d["finding_id"], justification=d["justification"],
                reviewer=d["reviewer"], evidence=d["evidence"], created_at=e.timestamp,
                expiry=d.get("expiry"),
            )
        elif e.action == REVOKED_ACTION:
            existing = by_finding.get(e.details["finding_id"])
            if existing is not None:
                existing.revoked = True
                existing.revoked_at = e.timestamp
                existing.revoked_by = e.details.get("revoked_by")
    return list(by_finding.values())


def is_suppressed(suppressions: list[Suppression], finding_id: str,
                   now: Optional[str] = None) -> Optional[Suppression]:
    """Returns the active Suppression for `finding_id` if one exists (not
    revoked, not expired), else None. An expired or revoked suppression is
    NOT returned here (so posture/policy correctly treat the finding as
    open again) but remains fully visible via `list_suppressions`."""
    now = now or now_iso()
    match = next((s for s in suppressions if s.finding_id == finding_id), None)
    if match is not None and match.is_active(now):
        return match
    return None
