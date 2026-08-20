# AI Provider Gateway (Stage C)

## Interface

`src/aep/ai_gateway/provider.py` defines the provider-neutral contract
every AI backend must implement:

- `AIProvider.list_models() -> list[ModelInfo]`
- `AIProvider.health_check() -> ProviderHealth`
- `AIProvider.complete(request: CompletionRequest) -> CompletionResponse`

`ModelInfo.tags` is what `AIGateway` routes on (e.g. `"security-suitable"`,
`"high-context"`, `"low-cost"`, `"high-capability"`). No implementation
lives in `provider.py` itself - it is pure interface.

`AIGateway` (`src/aep/ai_gateway/gateway.py`) wraps one or more registered
providers:

```python
from aep.ai_gateway.gateway import AIGateway
from aep.ai_gateway.fake_provider import FakeAIProvider

gateway = AIGateway(providers={"fake": FakeAIProvider()},
                     default_provider_id="fake", fallback_provider_id=None)
response, decision = gateway.complete("classification", "summarize this")
```

`decision.reason` always explains which rule fired.

## Routing table

Deterministic, rule-table only - never ML/opaque scoring:

| category             | required tag         | notes                                    |
|-----------------------|----------------------|-------------------------------------------|
| `security_reasoning`  | `security-suitable`  |                                            |
| `large_context`       | `high-context`       |                                            |
| `classification`      | `low-cost`           |                                            |
| `verification`        | `high-capability`    | prefers a provider distinct from the one being verified (pass `exclude_provider_id`) |

Any other category, or a category whose tag matches no registered model,
falls through to the configured default provider's first model -
`decision.reason` names exactly which branch fired, so nothing routes
silently.

## Fallback behavior

`gateway.complete(...)` catches any exception from the primary provider's
`complete()` call and, if `fallback_provider_id` is configured and
different from the primary, retries against it once. The returned
`RoutingDecision.is_fallback` is `True` in that case and `reason` names
the primary's failure class. If no fallback is configured (or the
fallback is itself the same provider), the original exception propagates.

## Usage ledger

`gateway.ledger` accumulates `total_input_tokens`/`total_output_tokens`/
`total_cost_usd`/`calls` additively across every `complete()` call. This
is explicitly **not** a billing system - just a running counter for
demo/observability purposes.

## OmniRoute configuration

`OmniRouteProvider` (`src/aep/ai_gateway/omniroute_provider.py`) reads
configuration EXCLUSIVELY from these env var NAMES - never a hardcoded
value anywhere in this repo:

```
AI_PROVIDER=omniroute        # label, optional, defaults to "omniroute"
AI_BASE_URL=https://...      # required
AI_CREDENTIAL=...            # required - never logged, never a real value in this repo/docs/tests
```

If either required var is missing, `OmniRouteConfig.from_env()` raises
`OmniRouteConfigError` naming the missing var NAME (never a value).

## Credential handling rules

1. The credential is read from the environment exactly once, at
   `OmniRouteConfig` construction, and held only in
   `self.config.credential`.
2. It is sent over the wire exactly once per request, as an outbound
   `Authorization: Bearer <credential>` header - never in a URL, never in
   a request body.
3. It must never appear in a log line, an exception message, a
   `ProviderHealth.detail` string, an `Evidence` record, or a prompt
   forwarded to any provider. `_redact()` scrubs it defensively out of any
   derived exception/health-check text even though it should never reach
   there in the first place.
4. Test files use an obviously-fake placeholder value
   (`"sk-fake-not-a-real-secret-..."`) and assert the FAKE value never
   leaks - this is a lint-test-style proof, not a claim about the real
   credential's value (which never appears anywhere in this repo).
5. `FakeAIProvider` and `AIGateway` never have access to a credential at
   all - only real provider construction does.

See `tests/test_ai_gateway_credential_safety.py` and
`tests/test_omniroute_provider.py` for the concrete proofs, and
`ARCHITECTURE.md` Section 33 for the full Stage C addendum.

## CLI

`aep providers [--json]` lists every registered provider/model, which is
default/fallback, the routing table, and OmniRoute's real (not faked)
reachability status in the current environment.
