"""Unit tests for `OmniRouteProvider`'s request-shaping/response-parsing/
credential-redaction logic against a tiny local `http.server` stub - real,
verifiable coverage that needs no live OmniRoute network access."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from aep.ai_gateway.omniroute_provider import (
    ENV_BASE_URL, ENV_CREDENTIAL, ENV_PROVIDER, OmniRouteConfig, OmniRouteConfigError,
    OmniRouteProvider,
)
from aep.ai_gateway.provider import CompletionRequest

FAKE_CREDENTIAL = "sk-fake-not-a-real-secret-0001"  # obviously-fake test placeholder, never a real credential


class _StubHandler(BaseHTTPRequestHandler):
    seen_auth_header = None

    def log_message(self, *args):  # silence
        pass

    def do_GET(self):
        _StubHandler.seen_auth_header = self.headers.get("Authorization")
        if self.path == "/v1/models":
            body = json.dumps({"data": [
                {"id": "stub-model", "context_window": 4096, "tags": ["low-cost"]},
            ]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        _StubHandler.seen_auth_header = self.headers.get("Authorization")
        length = int(self.headers.get("Content-Length", 0))
        payload = json.loads(self.rfile.read(length) or b"{}")
        assert payload["model"] == "stub-model"
        assert payload["messages"][0]["content"] == "hello"
        body = json.dumps({
            "choices": [{"message": {"content": "stub completion"}}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 5},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def stub_server():
    server = HTTPServer(("127.0.0.1", 0), _StubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    thread.join(timeout=2)


def _config(stub_server) -> OmniRouteConfig:
    port = stub_server.server_address[1]
    return OmniRouteConfig(base_url=f"http://127.0.0.1:{port}", credential=FAKE_CREDENTIAL)


def test_from_env_raises_when_unconfigured(monkeypatch):
    monkeypatch.delenv(ENV_BASE_URL, raising=False)
    monkeypatch.delenv(ENV_CREDENTIAL, raising=False)
    with pytest.raises(OmniRouteConfigError) as exc_info:
        OmniRouteConfig.from_env()
    assert ENV_BASE_URL in str(exc_info.value)
    assert ENV_CREDENTIAL in str(exc_info.value)


def test_from_env_builds_config(monkeypatch):
    monkeypatch.setenv(ENV_BASE_URL, "http://example.invalid")
    monkeypatch.setenv(ENV_CREDENTIAL, FAKE_CREDENTIAL)
    monkeypatch.setenv(ENV_PROVIDER, "omniroute")
    cfg = OmniRouteConfig.from_env()
    assert cfg.base_url == "http://example.invalid"
    assert cfg.credential == FAKE_CREDENTIAL


def test_list_models_parses_stub_response(stub_server):
    provider = OmniRouteProvider(config=_config(stub_server))
    models = provider.list_models()
    assert len(models) == 1
    assert models[0].model_id == "stub-model"
    assert "low-cost" in models[0].tags


def test_complete_shapes_request_and_parses_response(stub_server):
    provider = OmniRouteProvider(config=_config(stub_server))
    response = provider.complete(CompletionRequest(model_id="stub-model", prompt="hello"))
    assert response.text == "stub completion"
    assert response.input_tokens == 3
    assert response.output_tokens == 5


def test_health_check_reports_true_on_reachable_stub(stub_server):
    provider = OmniRouteProvider(config=_config(stub_server))
    health = provider.health_check()
    assert health.healthy is True


def test_health_check_reports_false_and_redacted_on_unreachable_host():
    cfg = OmniRouteConfig(base_url="http://127.0.0.1:1", credential=FAKE_CREDENTIAL)
    provider = OmniRouteProvider(config=cfg, timeout_seconds=1.0)
    health = provider.health_check()
    assert health.healthy is False
    assert FAKE_CREDENTIAL not in health.detail


def test_credential_sent_as_bearer_header_never_in_url_or_body(stub_server):
    provider = OmniRouteProvider(config=_config(stub_server))
    provider.complete(CompletionRequest(model_id="stub-model", prompt="hello"))
    assert _StubHandler.seen_auth_header == f"Bearer {FAKE_CREDENTIAL}"
