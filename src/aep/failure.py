"""Failure classification, retry/backoff policy, and circuit breaking.

ARCHITECTURE.md §9. Classification is based on exception type / tool result
shape, not on asking a model "what went wrong" - that would reintroduce the
"trust the model" problem this whole layer exists to avoid.
"""
from __future__ import annotations

import random
from dataclasses import dataclass

from .github.client import (
    GitHubAuthError, GitHubNotFoundError, GitHubRateLimitError, GitHubValidationError,
    GitHubError,
)
from .models import FailureClass
from .providers.router import BudgetExhaustedError
from .tool_registry import PermissionError as ToolPermissionError

# Classes that are never auto-retried: they always require a human decision
# or are a hard security boundary. See ARCHITECTURE.md §9.
# Phase 6 addition: CI_CONFIGURATION (a malformed workflow/missing secret is
# not fixed by waiting and retrying the same run) joins this set. The other
# Phase 6 classes (DEPENDENCY/BUILD/DEPLOYMENT/HEALTH/NETWORK/
# EXTERNAL_SERVICE/FLAKY/UNKNOWN) are deliberately left retryable-by-default
# here - whether a *deployment* is safe to retry/rollback is a
# deployment-safety policy question (`deployment/rollback.py`), not a
# generic backoff question, and must not be conflated with this module's
# job of "is retrying the same task worth attempting again."
NO_AUTO_RETRY = {FailureClass.SECURITY, FailureClass.AUTH, FailureClass.HUMAN_REQUIRED,
                  FailureClass.CI_CONFIGURATION, FailureClass.UNKNOWN}


def classify(exc: BaseException) -> FailureClass:
    if isinstance(exc, ToolPermissionError):
        return FailureClass.SECURITY
    if isinstance(exc, BudgetExhaustedError):
        return FailureClass.HUMAN_REQUIRED
    # GitHub-specific classification must come before the generic
    # PermissionError/TimeoutError/substring checks below, since e.g. a
    # GitHubRateLimitError is transient (worth retrying) even though it's
    # raised from a 403 the way an auth failure also is.
    if isinstance(exc, GitHubRateLimitError):
        return FailureClass.TRANSIENT
    if isinstance(exc, GitHubAuthError):
        return FailureClass.AUTH
    if isinstance(exc, GitHubNotFoundError):
        return FailureClass.CODE  # wrong owner/repo/branch/PR number - a code/config mistake
    if isinstance(exc, GitHubValidationError):
        return FailureClass.CODE  # request rejected (e.g. PR already exists) - not retryable as-is
    if isinstance(exc, GitHubError):
        return FailureClass.TRANSIENT  # network error / 5xx / unexpected status
    if isinstance(exc, PermissionError):
        return FailureClass.AUTH
    if isinstance(exc, (TimeoutError,)):
        return FailureClass.TRANSIENT
    name = type(exc).__name__.lower()
    msg = str(exc).lower()
    if "connection" in msg or "timeout" in msg or "temporarily" in msg:
        return FailureClass.TRANSIENT
    if "assert" in name or "test" in msg:
        return FailureClass.TEST
    if "syntax" in msg or "attributeerror" == name or "typeerror" == name:
        return FailureClass.CODE
    if "provider" in msg or "model" in msg:
        return FailureClass.MODEL
    if "infrastructure" in msg or "cluster" in msg or "terraform" in msg:
        return FailureClass.INFRASTRUCTURE
    return FailureClass.TOOL


@dataclass
class RetryDecision:
    should_retry: bool
    backoff_seconds: float
    quarantine: bool


class FailureClassifier:
    def __init__(self, base_backoff: float = 1.0, max_backoff: float = 60.0,
                 circuit_breaker_threshold: int = 5):
        self.base_backoff = base_backoff
        self.max_backoff = max_backoff
        self.circuit_breaker_threshold = circuit_breaker_threshold

    def decide(self, failure_class: FailureClass, attempts: int, max_attempts: int) -> RetryDecision:
        if failure_class in NO_AUTO_RETRY:
            return RetryDecision(should_retry=False, backoff_seconds=0.0, quarantine=False)
        if attempts >= max_attempts:
            return RetryDecision(should_retry=False, backoff_seconds=0.0, quarantine=True)
        backoff = min(self.max_backoff, self.base_backoff * (2 ** (attempts - 1)))
        jitter = backoff * random.uniform(0, 0.25)
        return RetryDecision(should_retry=True, backoff_seconds=backoff + jitter, quarantine=False)
