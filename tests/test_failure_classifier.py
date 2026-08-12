from aep.failure import FailureClassifier, classify
from aep.models import FailureClass
from aep.providers.router import BudgetExhaustedError
from aep.tool_registry import PermissionError as ToolPermissionError


def test_classify_tool_permission_error_as_security():
    assert classify(ToolPermissionError("nope")) == FailureClass.SECURITY


def test_classify_budget_exhaustion_as_human_required():
    assert classify(BudgetExhaustedError("out of budget")) == FailureClass.HUMAN_REQUIRED


def test_classify_timeout_as_transient():
    assert classify(TimeoutError("timed out")) == FailureClass.TRANSIENT


def test_security_failures_are_never_retried():
    clf = FailureClassifier()
    decision = clf.decide(FailureClass.SECURITY, attempts=1, max_attempts=5)
    assert decision.should_retry is False
    assert decision.quarantine is False  # -> becomes BLOCKED_ON_APPROVAL, not silently dropped


def test_transient_failures_retry_with_backoff():
    clf = FailureClassifier(base_backoff=1.0)
    decision = clf.decide(FailureClass.TRANSIENT, attempts=1, max_attempts=5)
    assert decision.should_retry is True
    assert decision.backoff_seconds > 0


def test_exhausting_max_attempts_quarantines():
    clf = FailureClassifier()
    decision = clf.decide(FailureClass.TOOL, attempts=5, max_attempts=5)
    assert decision.should_retry is False
    assert decision.quarantine is True


def test_backoff_grows_exponentially_and_is_capped():
    clf = FailureClassifier(base_backoff=1.0, max_backoff=10.0)
    d1 = clf.decide(FailureClass.TRANSIENT, attempts=1, max_attempts=10)
    d3 = clf.decide(FailureClass.TRANSIENT, attempts=3, max_attempts=10)
    d10 = clf.decide(FailureClass.TRANSIENT, attempts=10, max_attempts=10 + 1)
    assert d1.backoff_seconds < d3.backoff_seconds
    assert d10.backoff_seconds <= 10.0 * 1.25  # capped + max jitter
