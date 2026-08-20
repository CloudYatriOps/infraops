"""Stage C Part 2: `AIGateway` deterministic routing, fallback, and
additive usage accounting - against `FakeAIProvider` (an honest test
double, never presented as real inference)."""
from __future__ import annotations

import pytest

from aep.ai_gateway.fake_provider import FakeAIProvider
from aep.ai_gateway.gateway import AIGateway
from aep.ai_gateway.provider import ModelInfo


def test_security_reasoning_routes_to_security_suitable_model():
    gw = AIGateway(providers={"fake": FakeAIProvider()})
    decision = gw.route("security_reasoning")
    assert decision.model_id == "fake-security"
    assert "security-suitable" in decision.reason


def test_large_context_routes_to_high_context_model():
    gw = AIGateway(providers={"fake": FakeAIProvider()})
    decision = gw.route("large_context")
    assert decision.model_id == "fake-large-context"


def test_classification_routes_to_low_cost_model():
    gw = AIGateway(providers={"fake": FakeAIProvider()})
    decision = gw.route("classification")
    assert decision.model_id == "fake-general"


def test_unknown_category_defaults_and_reason_says_so():
    gw = AIGateway(providers={"fake": FakeAIProvider()})
    decision = gw.route("some_never_seen_category")
    assert "had no rule" in decision.reason


def test_verification_prefers_distinct_provider_when_excluded():
    primary = FakeAIProvider(provider_id="primary")
    verifier = FakeAIProvider(provider_id="verifier")
    gw = AIGateway(providers={"primary": primary, "verifier": verifier})
    decision = gw.route("verification", exclude_provider_id="primary")
    assert decision.provider_id != "primary"


def test_complete_records_usage_ledger():
    gw = AIGateway(providers={"fake": FakeAIProvider()})
    response, decision = gw.complete("classification", "hello world")
    assert response.text
    assert gw.ledger.calls == 1
    assert gw.ledger.total_input_tokens > 0


def test_complete_falls_back_on_primary_failure():
    primary = FakeAIProvider(provider_id="primary", fail=True)
    fallback = FakeAIProvider(provider_id="fallback")
    gw = AIGateway(providers={"primary": primary, "fallback": fallback},
                   default_provider_id="primary", fallback_provider_id="fallback")
    response, decision = gw.complete("classification", "hello")
    assert decision.is_fallback is True
    assert decision.provider_id == "fallback"
    assert "failed" in decision.reason


def test_complete_raises_when_no_fallback_configured():
    primary = FakeAIProvider(provider_id="primary", fail=True)
    gw = AIGateway(providers={"primary": primary})
    with pytest.raises(RuntimeError):
        gw.complete("classification", "hello")


def test_gateway_requires_at_least_one_provider():
    with pytest.raises(ValueError):
        AIGateway(providers={})
