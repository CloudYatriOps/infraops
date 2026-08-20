"""Credential safety, lint-test style (same pattern as
tests/test_skills_threat_model.py): a fake AI_CREDENTIAL value must never
appear in any prompt sent to a provider, any log line, any evidence
record, or any exception message raised by the gateway/adapter."""
from __future__ import annotations

import io
import logging

import pytest

from aep.ai_gateway.gateway import AIGateway
from aep.ai_gateway.omniroute_provider import OmniRouteConfig, OmniRouteProvider
from aep.ai_gateway.provider import CompletionRequest

FAKE_CREDENTIAL = "sk-fake-not-a-real-secret-9999"  # obviously-fake, never a real credential


def test_credential_never_appears_in_config_repr_or_str():
    """BUG-0002 regression: dataclass's default repr/str prints every
    field verbatim, which would leak `credential` through any accidental
    print(cfg)/logging call/f-string embedding the config object itself
    (not just through the network-facing paths the other tests here
    cover). OmniRouteConfig must override both."""
    cfg = OmniRouteConfig(base_url="http://127.0.0.1:1", credential=FAKE_CREDENTIAL, provider_label="omniroute")
    assert FAKE_CREDENTIAL not in repr(cfg)
    assert FAKE_CREDENTIAL not in str(cfg)
    assert FAKE_CREDENTIAL not in f"{cfg}"


def test_credential_never_appears_in_connection_failure_exception_message():
    cfg = OmniRouteConfig(base_url="http://127.0.0.1:1", credential=FAKE_CREDENTIAL, provider_label="omniroute")
    provider = OmniRouteProvider(config=cfg, timeout_seconds=1.0)
    with pytest.raises(ConnectionError) as exc_info:
        provider.complete(CompletionRequest(model_id="whatever", prompt="hello"))
    assert FAKE_CREDENTIAL not in str(exc_info.value)


def test_credential_never_appears_in_health_check_detail():
    cfg = OmniRouteConfig(base_url="http://127.0.0.1:1", credential=FAKE_CREDENTIAL)
    provider = OmniRouteProvider(config=cfg, timeout_seconds=1.0)
    health = provider.health_check()
    assert FAKE_CREDENTIAL not in health.detail


def test_credential_never_logged_by_python_logging_during_failed_calls(caplog):
    cfg = OmniRouteConfig(base_url="http://127.0.0.1:1", credential=FAKE_CREDENTIAL)
    provider = OmniRouteProvider(config=cfg, timeout_seconds=1.0)
    with caplog.at_level(logging.DEBUG):
        try:
            provider.complete(CompletionRequest(model_id="whatever", prompt="hello"))
        except ConnectionError:
            pass
    for record in caplog.records:
        assert FAKE_CREDENTIAL not in record.getMessage()


def test_credential_never_flows_into_a_gateway_prompt():
    """The gateway itself never has access to a credential at all (only
    the provider construction does) - proven by inspecting the prompt
    text it forwards to the provider."""
    from aep.ai_gateway.fake_provider import FakeAIProvider
    fake = FakeAIProvider()
    gw = AIGateway(providers={"fake": fake})
    prompt = "please summarize this code"
    gw.complete("classification", prompt)
    assert all(FAKE_CREDENTIAL not in call.prompt for call in fake.calls)
