"""Provider-neutral abstract contract every AI backend (real or test
double) must implement. No implementation of `AIProvider` lives in this
module - it is pure interface, mirroring `db/repositories.py`'s ABC
pattern."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ModelInfo:
    """Static capability metadata about one model a provider exposes.
    `tags` drives `AIGateway`'s deterministic routing rules (e.g.
    "high-context", "security-suitable", "low-cost")."""
    model_id: str
    provider_id: str
    context_window_tokens: int
    tags: frozenset[str] = field(default_factory=frozenset)
    cost_per_1k_input_tokens_usd: float = 0.0
    cost_per_1k_output_tokens_usd: float = 0.0


@dataclass
class ProviderHealth:
    healthy: bool
    detail: str = ""


@dataclass
class CompletionRequest:
    model_id: str
    prompt: str
    max_tokens: int = 1024
    metadata: dict = field(default_factory=dict)


@dataclass
class CompletionResponse:
    text: str
    model_id: str
    provider_id: str
    input_tokens: int = 0
    output_tokens: int = 0
    raw: Optional[dict] = None


class AIProvider(ABC):
    """One AI backend. `provider_id` must be stable and unique across
    providers registered into the same `AIGateway`."""

    provider_id: str

    @abstractmethod
    def list_models(self) -> list[ModelInfo]:
        """Static or dynamically-discovered model/capability metadata."""

    @abstractmethod
    def health_check(self) -> ProviderHealth:
        """Cheap, real reachability probe - never fabricated."""

    @abstractmethod
    def complete(self, request: CompletionRequest) -> CompletionResponse:
        """Perform (or, for a test double, simulate - and say so) one
        completion call. Real implementations MUST NEVER let a raw
        credential value flow into `request.prompt`, any exception
        message, or `CompletionResponse` - see credential-safety tests."""
