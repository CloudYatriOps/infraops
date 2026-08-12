"""Cloud adapter registry (Phase 5 Part 5).

Part 5 names OCI, AWS, Azure and GCP but is explicit: "Do not implement
all providers superficially. Implement the adapter architecture first and
fully implement ONE provider."

So exactly one adapter is registered: AWS. Azure/GCP/OCI are deliberately
NOT registered and NOT stubbed. Shipping an adapter that returns an empty
resource list would be worse than shipping nothing, because an empty
result from a stub is indistinguishable from a real adapter reporting a
clean account - the same false-assurance failure mode the Helm scanner
documents. `get_adapter()` reports NOT_IMPLEMENTED for them instead, which
is a fact a caller can act on.

Adding a provider later requires only a new module conforming to
`base.CloudProviderAdapter` plus one line here; nothing in `infra/`
outside this package branches on provider identity.
"""
from __future__ import annotations

from typing import Callable, Optional

from .aws_adapter import AWSAdapter
from .base import CloudAdapterStatus, CloudDiscoveryResult

# provider name -> factory. One entry, on purpose.
_ADAPTERS: dict[str, Callable[..., object]] = {
    "aws": AWSAdapter,
}

# Named by Part 5 but deliberately not implemented in Phase 5 - listed so
# the platform can say precisely *why* rather than just failing a lookup.
_KNOWN_UNIMPLEMENTED = {
    "azure": "no Azure adapter ships in Phase 5 (Part 5: implement one provider fully rather "
             "than four superficially); the azure-identity/azure-mgmt SDKs and any Azure "
             "endpoint are also unreachable from this sandbox",
    "gcp": "no GCP adapter ships in Phase 5 (see azure); google-cloud SDK and endpoints "
           "unreachable from this sandbox",
    "oci": "no OCI adapter ships in Phase 5 (see azure); the oci SDK and endpoints are "
           "unreachable from this sandbox",
}


def supported_providers() -> list[str]:
    return sorted(_ADAPTERS)


def known_providers() -> list[str]:
    return sorted(set(_ADAPTERS) | set(_KNOWN_UNIMPLEMENTED))


def get_adapter(provider: str, **kwargs):
    """Returns an adapter instance, or None if the provider has no
    implementation. Callers should use `describe_provider()` when they
    need the reason as well."""
    factory = _ADAPTERS.get(provider.lower())
    return factory(**kwargs) if factory else None


def describe_provider(provider: str, **kwargs) -> CloudDiscoveryResult:
    """Returns an *empty* discovery result carrying this provider's real
    status - never fabricated resources. This is what makes "we have no
    adapter" and "we have an adapter and the account is clean"
    distinguishable to every caller."""
    normalized = provider.lower()
    adapter = get_adapter(normalized, **kwargs)
    if adapter is None:
        reason = _KNOWN_UNIMPLEMENTED.get(
            normalized, f"'{provider}' is not a provider this platform knows about")
        return CloudDiscoveryResult(provider=normalized,
                                     status=CloudAdapterStatus.NOT_IMPLEMENTED, reason=reason)
    status, reason = adapter.status()
    return CloudDiscoveryResult(provider=normalized, status=status, reason=reason)


def discover(provider: str, capabilities: Optional[list] = None, **kwargs) -> CloudDiscoveryResult:
    adapter = get_adapter(provider, **kwargs)
    if adapter is None:
        return describe_provider(provider, **kwargs)
    return adapter.discover(capabilities=capabilities)
