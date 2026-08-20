from datetime import datetime, timedelta, timezone

from aep.operations.recurrence import RecurrenceTracker


def test_allows_remediation_within_limits():
    tracker = RecurrenceTracker(max_attempts=3, escalation_threshold=5)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    decision = tracker.record_attempt("fp1", now=now)
    assert decision.should_remediate
    assert decision.attempt_number == 1


def test_cooldown_window_blocks_immediate_retry():
    tracker = RecurrenceTracker(cooldown=timedelta(minutes=10), escalation_threshold=10)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    tracker.record_attempt("fp1", now=now)
    decision = tracker.record_attempt("fp1", now=now + timedelta(minutes=1))
    assert not decision.should_remediate
    assert "cooldown" in decision.reason


def test_circuit_breaker_opens_at_escalation_threshold_and_stays_open():
    tracker = RecurrenceTracker(cooldown=timedelta(seconds=0), escalation_threshold=3, max_attempts=10)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for i in range(2):
        d = tracker.record_attempt("fp1", now=now + timedelta(minutes=i))
        assert d.should_remediate
    opened = tracker.record_attempt("fp1", now=now + timedelta(minutes=2))
    assert opened.circuit_open
    assert not opened.should_remediate
    assert tracker.is_open("fp1")
    # Once open, it never authorizes remediation again without a reset.
    still_open = tracker.record_attempt("fp1", now=now + timedelta(hours=5))
    assert still_open.circuit_open
    assert not still_open.should_remediate


def test_reset_clears_history_after_confirmed_recovery():
    tracker = RecurrenceTracker(cooldown=timedelta(seconds=0), escalation_threshold=2)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    tracker.record_attempt("fp1", now=now)
    tracker.reset("fp1")
    decision = tracker.record_attempt("fp1", now=now)
    assert decision.attempt_number == 1
    assert decision.should_remediate
