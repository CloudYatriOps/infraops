"""Deterministic, offline provider used by every test and by the demo.

It does not call any network API. It applies a small set of task-type ->
canned-but-realistic response rules so the orchestrator/agents can be
exercised end-to-end without a paid key or network access, while still
going through the exact same `render_safe_prompt` redaction path a real
provider would use.
"""
from __future__ import annotations

from .base import (
    AIProvider, GenerationRequest, GenerationResult, ProviderCapabilities,
    ProviderHealth, render_safe_prompt,
)


class MockProvider:
    name = "mock"
    model = "mock-deterministic-v1"

    def __init__(self, canned_responses: dict[str, object] | None = None):
        # task_type -> response. A value may be:
        #   - a plain string: always returned for that task_type
        #   - a list[str]: successive calls pop the next entry, repeating
        #     the last one once exhausted (used to simulate a CI-fix loop
        #     where the second commit's content must differ from the first)
        #   - a callable(request) -> str: fully custom, given the request
        # Falls back to a generic acknowledgment for unregistered task types.
        self._canned = canned_responses or {}
        self._call_counts: dict[str, int] = {}
        self._consecutive_failures = 0
        self._force_fail = False

    def force_fail(self, value: bool) -> None:
        """Test hook to exercise MODEL failure classification / fallback."""
        self._force_fail = value

    def _resolve_text(self, request: GenerationRequest) -> str:
        entry = self._canned.get(request.task_type)
        if entry is None:
            return f"[mock:{request.task_type}] acknowledged"
        if callable(entry):
            return entry(request)
        if isinstance(entry, list):
            idx = self._call_counts.get(request.task_type, 0)
            self._call_counts[request.task_type] = idx + 1
            return entry[min(idx, len(entry) - 1)]
        return entry

    def generate(self, request: GenerationRequest) -> GenerationResult:
        # Route the prompt through the same redaction path a real provider
        # would use, so tests can assert secrets never reach "the model".
        prompt = render_safe_prompt(request)

        if self._force_fail:
            self._consecutive_failures += 1
            raise RuntimeError("mock provider forced failure")

        self._consecutive_failures = 0
        text = self._resolve_text(request)
        input_tokens = len(prompt.split())
        output_tokens = len(text.split())
        return GenerationResult(
            text=text,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            estimated_cost_usd=0.0,
            provider_name=self.name,
            model=self.model,
        )

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            context_window_tokens=200_000,
            supports_tools=False,
            cost_per_1k_input_usd=0.0,
            cost_per_1k_output_usd=0.0,
        )

    def health(self) -> ProviderHealth:
        return ProviderHealth(healthy=self._consecutive_failures < 3,
                               consecutive_failures=self._consecutive_failures)
