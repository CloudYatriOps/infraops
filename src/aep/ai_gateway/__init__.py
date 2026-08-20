"""Stage C Part 2: provider-neutral AI gateway.

Nothing in this package hardcodes a credential value. A concrete
provider (e.g. `omniroute_provider.OmniRouteProvider`) reads its
configuration from env var NAMES only (`AI_PROVIDER`, `AI_BASE_URL`,
`AI_CREDENTIAL`) - see ARCHITECTURE.md §33 and docs/AI-GATEWAY.md.

`FakeAIProvider` is an explicit, honestly-named test double (same pattern
as `db/fake.py`) - it never pretends to call a real model.
"""
from __future__ import annotations

from .gateway import AIGateway, RoutingDecision
from .provider import AIProvider, CompletionRequest, CompletionResponse, ModelInfo, ProviderHealth
from .fake_provider import FakeAIProvider

__all__ = [
    "AIGateway", "RoutingDecision",
    "AIProvider", "CompletionRequest", "CompletionResponse", "ModelInfo", "ProviderHealth",
    "FakeAIProvider",
]
