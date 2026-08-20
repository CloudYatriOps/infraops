"""Real `AIProvider` implementation for OmniRoute. Configuration comes
EXCLUSIVELY from env var NAMES - `AI_PROVIDER`, `AI_BASE_URL`,
`AI_CREDENTIAL` - never a hardcoded value anywhere in this module. The
credential is read once at construction, held only in memory, and never
placed into a log line, exception message, prompt, or evidence record -
see tests/test_ai_gateway_credential_safety.py for the proof.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass

from .provider import AIProvider, CompletionRequest, CompletionResponse, ModelInfo, ProviderHealth

ENV_PROVIDER = "AI_PROVIDER"
ENV_BASE_URL = "AI_BASE_URL"
ENV_CREDENTIAL = "AI_CREDENTIAL"


class OmniRouteConfigError(Exception):
    """Raised when required env vars are missing. Message names the
    missing env var NAME only, never a value."""


@dataclass
class OmniRouteConfig:
    base_url: str
    credential: str
    provider_label: str = "omniroute"

    def __repr__(self) -> str:
        # dataclass's default repr prints every field verbatim, which
        # would leak `credential` through any accidental print(cfg),
        # logging call, or exception that embeds the config object -
        # override it so the credential can never surface this way
        # (see BUG-0002 in BUGFIX.md).
        return f"OmniRouteConfig(base_url={self.base_url!r}, credential='[REDACTED]', provider_label={self.provider_label!r})"

    __str__ = __repr__

    @staticmethod
    def from_env() -> "OmniRouteConfig":
        base_url = os.environ.get(ENV_BASE_URL)
        credential = os.environ.get(ENV_CREDENTIAL)
        provider_label = os.environ.get(ENV_PROVIDER, "omniroute")
        missing = [name for name, val in ((ENV_BASE_URL, base_url), (ENV_CREDENTIAL, credential)) if not val]
        if missing:
            raise OmniRouteConfigError(
                f"OmniRoute is not configured: missing env var(s) {missing} (names only - "
                "never set a credential value directly in code or logs)"
            )
        return OmniRouteConfig(base_url=base_url, credential=credential, provider_label=provider_label)


def _redact(text: str, credential: str) -> str:
    """Belt-and-suspenders redaction: even though the credential should
    never be interpolated into an outbound message in the first place,
    this scrubs it from anything derived from a response/error body
    before it can reach a log line or exception."""
    if not credential:
        return text
    return text.replace(credential, "[REDACTED]")


class OmniRouteProvider(AIProvider):
    provider_id = "omniroute"

    def __init__(self, config: OmniRouteConfig | None = None, timeout_seconds: float = 5.0):
        self.config = config or OmniRouteConfig.from_env()
        self.timeout_seconds = timeout_seconds

    def _headers(self) -> dict:
        # Authorization header carries the credential over the wire only
        # (never logged) - this is the one and only place it is read out
        # of `self.config.credential`.
        return {
            "Authorization": f"Bearer {self.config.credential}",
            "Content-Type": "application/json",
        }

    def list_models(self) -> list[ModelInfo]:
        body = self._request("GET", "/v1/models")
        models = []
        for entry in body.get("data", []):
            models.append(ModelInfo(
                model_id=entry.get("id", "unknown"), provider_id=self.provider_id,
                context_window_tokens=int(entry.get("context_window", 0) or 0),
                tags=frozenset(entry.get("tags", [])),
            ))
        return models

    def health_check(self) -> ProviderHealth:
        try:
            self._request("GET", "/v1/models")
            return ProviderHealth(healthy=True, detail=f"reached {self.config.base_url}")
        except Exception as exc:  # noqa: BLE001 - reported, not fabricated
            return ProviderHealth(healthy=False, detail=_redact(str(exc), self.config.credential))

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        payload = {
            "model": request.model_id,
            "messages": [{"role": "user", "content": request.prompt}],
            "max_tokens": request.max_tokens,
        }
        body = self._request("POST", "/v1/chat/completions", payload=payload)
        choice = (body.get("choices") or [{}])[0]
        text = choice.get("message", {}).get("content", "")
        usage = body.get("usage", {})
        return CompletionResponse(
            text=text, model_id=request.model_id, provider_id=self.provider_id,
            input_tokens=int(usage.get("prompt_tokens", 0) or 0),
            output_tokens=int(usage.get("completion_tokens", 0) or 0),
            raw=body,
        )

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict:
        url = self.config.base_url.rstrip("/") + path
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(url, data=data, headers=self._headers(), method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            # Redact defensively even though `str(exc)` should never
            # contain the credential (it isn't in the URL) - proven by
            # the credential-safety tests.
            raise ConnectionError(_redact(f"OmniRoute request to {path} failed: {exc}",
                                           self.config.credential)) from exc
