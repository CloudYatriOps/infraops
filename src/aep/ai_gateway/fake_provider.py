"""`FakeAIProvider` - an explicit, honestly-named test double (same
pattern as `db/fake.py`'s in-memory repositories). It NEVER calls a real
model and NEVER pretends to: `complete()` returns a deterministic,
clearly-labeled canned string so tests and the offline demo path can
exercise `AIGateway` routing/fallback/accounting without any network
dependency or live-inference claim."""
from __future__ import annotations

from .provider import AIProvider, CompletionRequest, CompletionResponse, ModelInfo, ProviderHealth


class FakeAIProvider(AIProvider):
    def __init__(self, provider_id: str = "fake", models: list[ModelInfo] | None = None,
                 fail: bool = False, canned_text: str = "[FakeAIProvider: no real inference performed]"):
        self.provider_id = provider_id
        self._models = models or [
            ModelInfo(model_id="fake-general", provider_id=provider_id,
                      context_window_tokens=8_000, tags=frozenset({"low-cost"})),
            ModelInfo(model_id="fake-large-context", provider_id=provider_id,
                      context_window_tokens=200_000, tags=frozenset({"high-context"})),
            ModelInfo(model_id="fake-security", provider_id=provider_id,
                      context_window_tokens=32_000, tags=frozenset({"high-capability", "security-suitable"})),
        ]
        self.fail = fail
        self.canned_text = canned_text
        self.calls: list[CompletionRequest] = []

    def list_models(self) -> list[ModelInfo]:
        return list(self._models)

    def health_check(self) -> ProviderHealth:
        if self.fail:
            return ProviderHealth(healthy=False, detail="FakeAIProvider configured to report unhealthy")
        return ProviderHealth(healthy=True, detail="FakeAIProvider is a test double, not a real backend")

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        self.calls.append(request)
        if self.fail:
            raise RuntimeError(f"FakeAIProvider[{self.provider_id}] simulated failure")
        return CompletionResponse(
            text=self.canned_text, model_id=request.model_id, provider_id=self.provider_id,
            input_tokens=max(1, len(request.prompt) // 4), output_tokens=len(self.canned_text) // 4,
        )
