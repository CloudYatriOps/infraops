"""Routes a task type to a provider, with fallback and a per-project token
budget. This is what lets `security_analysis` go to a stronger model while
`trivial_refactor` goes to a cheap/mock one, and what stops a runaway
continuous-mode loop from spending without bound."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .base import AIProvider, GenerationRequest, GenerationResult
from ..models import FailureClass


class BudgetExhaustedError(RuntimeError):
    pass


@dataclass
class RouteEntry:
    primary: str
    fallbacks: list[str] = field(default_factory=list)


class ModelRouter:
    def __init__(self, providers: dict[str, AIProvider],
                 routing_table: dict[str, RouteEntry],
                 default_route: Optional[RouteEntry] = None,
                 token_budget: Optional[int] = None):
        self._providers = providers
        self._routing_table = routing_table
        self._default_route = default_route or RouteEntry(primary=next(iter(providers)))
        self._token_budget = token_budget
        self._tokens_spent = 0

    def tokens_spent(self) -> int:
        return self._tokens_spent

    def remaining_budget(self) -> Optional[int]:
        if self._token_budget is None:
            return None
        return max(0, self._token_budget - self._tokens_spent)

    def generate(self, request: GenerationRequest) -> GenerationResult:
        if self._token_budget is not None and self._tokens_spent >= self._token_budget:
            raise BudgetExhaustedError(
                f"token budget of {self._token_budget} exhausted "
                f"({self._tokens_spent} spent) — pausing model calls for this project"
            )

        route = self._routing_table.get(request.task_type, self._default_route)
        candidates = [route.primary, *route.fallbacks]
        last_error: Optional[Exception] = None
        for name in candidates:
            provider = self._providers.get(name)
            if provider is None:
                continue
            if not provider.health().healthy:
                continue
            try:
                result = provider.generate(request)
                self._tokens_spent += result.input_tokens + result.output_tokens
                return result
            except Exception as e:  # noqa: BLE001 - deliberately broad, classified by FailureClassifier
                last_error = e
                continue
        # every candidate failed or was unhealthy
        raise RuntimeError(
            f"all providers failed for task_type='{request.task_type}' "
            f"(candidates={candidates}); last_error={last_error}"
        )
