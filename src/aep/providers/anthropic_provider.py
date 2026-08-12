"""Real Anthropic-backed provider. Only usable if ANTHROPIC_API_KEY is set
and the `anthropic` package is installed; otherwise raise at construction
time so the router falls back to another provider instead of silently
degrading."""
from __future__ import annotations

import os

from .base import (
    AIProvider, GenerationRequest, GenerationResult, ProviderCapabilities,
    ProviderHealth, render_safe_prompt,
)

_PRICE_PER_1K = {
    # Illustrative rates; real deployments should read current pricing from
    # provider docs/config rather than hard-coding it indefinitely.
    "claude-sonnet-4-5": (0.003, 0.015),
}


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str = "claude-sonnet-4-5"):
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set; cannot construct AnthropicProvider")
        try:
            import anthropic  # noqa: F401
        except ImportError as e:
            raise RuntimeError(
                "the 'anthropic' package is not installed; "
                "pip install anthropic to use AnthropicProvider"
            ) from e
        self._client = anthropic.Anthropic(api_key=api_key)
        self.model = model
        self._consecutive_failures = 0

    def generate(self, request: GenerationRequest) -> GenerationResult:
        prompt = render_safe_prompt(request)
        try:
            resp = self._client.messages.create(
                model=self.model,
                max_tokens=request.max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )
        except Exception:
            self._consecutive_failures += 1
            raise
        self._consecutive_failures = 0
        text = "".join(block.text for block in resp.content if hasattr(block, "text"))
        in_tok = resp.usage.input_tokens
        out_tok = resp.usage.output_tokens
        rate_in, rate_out = _PRICE_PER_1K.get(self.model, (0.0, 0.0))
        cost = (in_tok / 1000) * rate_in + (out_tok / 1000) * rate_out
        return GenerationResult(
            text=text, input_tokens=in_tok, output_tokens=out_tok,
            estimated_cost_usd=cost, provider_name=self.name, model=self.model,
        )

    def capabilities(self) -> ProviderCapabilities:
        rate_in, rate_out = _PRICE_PER_1K.get(self.model, (0.0, 0.0))
        return ProviderCapabilities(
            context_window_tokens=200_000, supports_tools=True,
            cost_per_1k_input_usd=rate_in, cost_per_1k_output_usd=rate_out,
        )

    def health(self) -> ProviderHealth:
        return ProviderHealth(healthy=self._consecutive_failures < 3,
                               consecutive_failures=self._consecutive_failures)
