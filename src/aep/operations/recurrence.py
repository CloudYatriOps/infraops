"""Part 8: recurrence/flapping detection and circuit breaking.

Backed by the SAME durable `StateStore` the rest of the platform uses (no
new storage primitive) via `incident_memory.py`'s event log, so recurrence
counters survive a process restart exactly like Phase 1's
`failure_counters` table does for generic task retries. This module is
intentionally a distinct, incident-fingerprint-scoped circuit breaker from
`failure.FailureClassifier`'s task-type-scoped one - a flapping incident
and a flaky task retry are different concerns with different keys
(fingerprint vs task_type).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass
class RecurrenceDecision:
    attempt_number: int
    should_remediate: bool
    circuit_open: bool
    reason: str


class RecurrenceTracker:
    """In-memory-per-run counter keyed by incident fingerprint. Durable
    cross-run recurrence lives in `IncidentMemory` (Part 9); this tracker
    handles the same-run "don't remediate the same fingerprint forever"
    guard plus a cooldown window computed from timestamps supplied by the
    caller (never `time.sleep`-based, so it stays deterministic and
    testable)."""

    def __init__(self, max_attempts: int = 3, cooldown: timedelta = timedelta(minutes=15),
                 escalation_threshold: int = 3):
        self.max_attempts = max_attempts
        self.cooldown = cooldown
        self.escalation_threshold = escalation_threshold
        self._attempts: dict[str, int] = {}
        self._last_attempt_at: dict[str, datetime] = {}
        self._circuit_open: dict[str, bool] = {}

    def record_attempt(self, fingerprint: str, now: datetime | None = None) -> RecurrenceDecision:
        now = now or datetime.now(timezone.utc)
        if self._circuit_open.get(fingerprint):
            return RecurrenceDecision(attempt_number=self._attempts.get(fingerprint, 0),
                                       should_remediate=False, circuit_open=True,
                                       reason=f"circuit breaker OPEN for fingerprint "
                                              f"{fingerprint!r} - too many remediation attempts; "
                                              f"escalating instead of retrying again")

        last = self._last_attempt_at.get(fingerprint)
        if last is not None and (now - last) < self.cooldown:
            return RecurrenceDecision(attempt_number=self._attempts.get(fingerprint, 0),
                                       should_remediate=False, circuit_open=False,
                                       reason=f"within cooldown window ({self.cooldown}) since "
                                              f"last remediation attempt for {fingerprint!r} - "
                                              f"waiting before retrying")

        count = self._attempts.get(fingerprint, 0) + 1
        self._attempts[fingerprint] = count
        self._last_attempt_at[fingerprint] = now

        if count >= self.escalation_threshold:
            self._circuit_open[fingerprint] = True
            return RecurrenceDecision(attempt_number=count, should_remediate=False,
                                       circuit_open=True,
                                       reason=f"attempt {count} reached escalation threshold "
                                              f"({self.escalation_threshold}) for {fingerprint!r} - "
                                              f"opening circuit breaker and escalating rather than "
                                              f"remediating again")
        if count > self.max_attempts:
            return RecurrenceDecision(attempt_number=count, should_remediate=False,
                                       circuit_open=False,
                                       reason=f"attempt {count} exceeds max_attempts "
                                              f"({self.max_attempts}) for {fingerprint!r}")
        return RecurrenceDecision(attempt_number=count, should_remediate=True, circuit_open=False,
                                   reason=f"attempt {count}/{self.max_attempts} for {fingerprint!r} "
                                          f"- within limits, remediation authorized")

    def is_open(self, fingerprint: str) -> bool:
        return bool(self._circuit_open.get(fingerprint))

    def reset(self, fingerprint: str) -> None:
        """Called after a VERIFIED successful recovery (Part 7/8): a
        confirmed recovery clears the fingerprint's attempt history so a
        genuinely NEW future occurrence is not penalized by history it
        already recovered from."""
        self._attempts.pop(fingerprint, None)
        self._last_attempt_at.pop(fingerprint, None)
        self._circuit_open.pop(fingerprint, None)
