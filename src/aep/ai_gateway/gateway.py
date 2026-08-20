"""`AIGateway`: deterministic (rule-table, non-ML) routing across
registered `AIProvider`s by task category, with primary/fallback and a
simple additive cost/token accounting ledger. Every routing decision
returns an explainable reason string naming which rule matched."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .provider import AIProvider, CompletionRequest, CompletionResponse, ModelInfo

# Deterministic category -> required-tag routing table (Part 2's "rule
# table, not ML"). A category with no matching model on ANY registered
# provider falls through to `default_tag` (see `_select_model`) rather
# than raising - callers that care can inspect `RoutingDecision.reason`.
CATEGORY_TAG_RULES: dict[str, str] = {
    "security_reasoning": "security-suitable",
    "large_context": "high-context",
    "classification": "low-cost",
    "verification": "high-capability",
}

# Categories where the gateway prefers routing to a DIFFERENT provider
# than the one that produced the artifact being verified - "a second set
# of eyes" is only meaningful if it isn't the same backend.
DISTINCT_PROVIDER_CATEGORIES = {"verification"}


@dataclass
class RoutingDecision:
    provider_id: str
    model_id: str
    reason: str
    is_fallback: bool = False


@dataclass
class UsageLedger:
    """A simple additive counter - intentionally NOT a billing system."""
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost_usd: float = 0.0
    calls: int = 0

    def record(self, response: CompletionResponse, model: Optional[ModelInfo]) -> None:
        self.calls += 1
        self.total_input_tokens += response.input_tokens
        self.total_output_tokens += response.output_tokens
        if model is not None:
            self.total_cost_usd += (
                response.input_tokens / 1000 * model.cost_per_1k_input_tokens_usd
                + response.output_tokens / 1000 * model.cost_per_1k_output_tokens_usd
            )


class AIGateway:
    def __init__(self, providers: dict[str, AIProvider],
                 default_provider_id: Optional[str] = None,
                 fallback_provider_id: Optional[str] = None):
        if not providers:
            raise ValueError("AIGateway requires at least one registered provider")
        self.providers = providers
        self.default_provider_id = default_provider_id or next(iter(providers))
        self.fallback_provider_id = fallback_provider_id
        self.ledger = UsageLedger()

    def _all_models(self) -> list[ModelInfo]:
        models = []
        for provider in self.providers.values():
            models.extend(provider.list_models())
        return models

    def route(self, category: str, exclude_provider_id: Optional[str] = None) -> RoutingDecision:
        """Pure routing decision (no network call) - `complete()` below
        uses this, but tests can call `route()` directly to assert on the
        explainable reason string without touching a provider at all."""
        required_tag = CATEGORY_TAG_RULES.get(category)
        candidates = self._all_models()
        if exclude_provider_id is None and category in DISTINCT_PROVIDER_CATEGORIES:
            # Left to the caller normally (they pass exclude_provider_id
            # explicitly for verification-of-X-by-provider-Y flows); with
            # nothing excluded there's no "distinct" constraint to apply.
            pass
        if exclude_provider_id is not None:
            candidates = [m for m in candidates if m.provider_id != exclude_provider_id]

        if required_tag is not None:
            tagged = [m for m in candidates if required_tag in m.tags]
            if tagged:
                chosen = tagged[0]
                return RoutingDecision(
                    provider_id=chosen.provider_id, model_id=chosen.model_id,
                    reason=f"category {category!r} matched rule -> tag {required_tag!r}; "
                           f"selected {chosen.provider_id}/{chosen.model_id}",
                )

        # No category rule, or no model carries the required tag: fall
        # back to the configured default provider's first model.
        default_provider = self.providers.get(self.default_provider_id)
        if default_provider is not None:
            models = [m for m in default_provider.list_models()
                      if exclude_provider_id is None or m.provider_id != exclude_provider_id]
            if models:
                chosen = models[0]
                reason = (f"category {category!r} had no rule" if required_tag is None else
                          f"category {category!r} rule (tag {required_tag!r}) matched no registered model")
                return RoutingDecision(
                    provider_id=chosen.provider_id, model_id=chosen.model_id,
                    reason=f"{reason}; defaulted to {chosen.provider_id}/{chosen.model_id}",
                )
        raise ValueError(f"no model available to route category {category!r} to")

    def complete(self, category: str, prompt: str, max_tokens: int = 1024,
                 exclude_provider_id: Optional[str] = None) -> tuple[CompletionResponse, RoutingDecision]:
        decision = self.route(category, exclude_provider_id=exclude_provider_id)
        provider = self.providers[decision.provider_id]
        model = next((m for m in provider.list_models() if m.model_id == decision.model_id), None)
        request = CompletionRequest(model_id=decision.model_id, prompt=prompt, max_tokens=max_tokens)
        try:
            response = provider.complete(request)
        except Exception as primary_exc:  # noqa: BLE001 - deliberately broad: any primary failure triggers fallback
            if self.fallback_provider_id and self.fallback_provider_id in self.providers \
                    and self.fallback_provider_id != decision.provider_id:
                fallback_provider = self.providers[self.fallback_provider_id]
                fallback_models = fallback_provider.list_models()
                fallback_model = fallback_models[0] if fallback_models else None
                if fallback_model is None:
                    raise
                fallback_request = CompletionRequest(
                    model_id=fallback_model.model_id, prompt=prompt, max_tokens=max_tokens)
                response = fallback_provider.complete(fallback_request)
                decision = RoutingDecision(
                    provider_id=fallback_provider.provider_id, model_id=fallback_model.model_id,
                    reason=f"primary {decision.provider_id}/{decision.model_id} failed "
                           f"({primary_exc.__class__.__name__}); fell back to "
                           f"{fallback_provider.provider_id}/{fallback_model.model_id}",
                    is_fallback=True,
                )
                model = fallback_model
            else:
                raise
        self.ledger.record(response, model)
        return response, decision
