"""Provider-agnostic cloud adapter contract (Phase 5 Part 5/6/12).

Part 5 asks for a generic `CloudProviderAdapter` with capabilities for
account discovery, IAM, networking, compute, storage, databases,
encryption, secrets, logging, backups, and public exposure - and is
explicit that the platform must NOT implement every provider
superficially. So exactly one provider (AWS) is implemented for real, in
`aws_adapter.py`, and no stub adapters for Azure/GCP/OCI ship at all:
a stub that returns empty results is indistinguishable from a real
adapter reporting a clean account, which is the same class of false
assurance the Helm scanner exists to avoid. `registry.py` reports
unregistered providers as NOT_IMPLEMENTED rather than pretending.

## Read-only by construction (Part 6)

Part 6 requires discovery to default to read-only. That is enforced here
structurally rather than by convention or documentation:

  - `CloudCapability` enumerates ONLY read operations.
  - `ReadOnlyViolation` is raised by `assert_read_only()` for any API
    operation name that is not on the explicit read-only allowlist, and
    the AWS adapter routes every single call through it.
  - There is no write method anywhere in this contract. An adapter cannot
    delete, modify, or create anything through this interface even if a
    caller asked it to, because the verbs do not exist.

Credentials are never accepted as literals (Part 5: "Never hard-code
credentials"). An adapter is constructed with a `client_factory` and,
optionally, the platform's existing `SecretManager` (`src/aep/secrets.py`)
- the same injection pattern `GitHubClient.transport` uses, which is also
what makes the contract tests in Part 12 possible without credentials.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional, Protocol


class CloudCapability(str, Enum):
    """The eleven read-only capability areas Part 5 names. Every one is an
    inspection; none mutates."""
    ACCOUNT_DISCOVERY = "account_discovery"
    IAM = "iam"
    NETWORKING = "networking"
    COMPUTE = "compute"
    STORAGE = "storage"
    DATABASES = "databases"
    ENCRYPTION = "encryption"
    SECRETS = "secrets"
    LOGGING = "logging"
    BACKUPS = "backups"
    PUBLIC_EXPOSURE = "public_exposure"


class CloudAdapterStatus(str, Enum):
    """Deliberately mirrors Phase 4's `ScannerAvailability` vocabulary so
    "can this run here?" means the same thing everywhere in the platform.
    Part 12's REAL / MOCKED / UNAVAILABLE labels map onto this directly."""
    AVAILABLE = "AVAILABLE"              # real credentials, real API reachable
    MOCKED = "MOCKED"                    # an injected fake transport (contract tests)
    UNAVAILABLE = "UNAVAILABLE"          # SDK or credentials missing
    BLOCKED = "BLOCKED"                  # network/egress prevents reaching the API
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"  # no adapter ships for this provider


class ReadOnlyViolation(PermissionError):
    """Raised when a caller attempts a non-read-only cloud operation.

    This is a hard failure, never a warning: Part 6 lists deleting cloud
    resources, applying Terraform, and modifying production IAM/networking
    as things the agent must not do automatically, and a warning that
    execution continues past is not an enforcement mechanism."""


# Operation-name prefixes considered read-only across cloud SDKs. An
# operation must match one of these AND not match the deny list below.
_READ_ONLY_PREFIXES = (
    "describe", "get", "list", "head", "search", "lookup", "query", "batch_get",
    "select", "scan", "check", "test", "estimate", "preview", "simulate",
)

# Explicit deny list for operation names that *start* like a read but are
# not. `get_session_token`/`get_federation_token` mint credentials;
# `test_role`-style calls vary by provider. Listing them beats relying on
# the prefix heuristic alone.
_NEVER_READ_ONLY = {
    "get_session_token", "get_federation_token", "get_credentials",
    "getauthorizationtoken", "get_authorization_token", "get_cluster_credentials",
    "get_password_data", "get_secret_value",
}


def is_read_only_operation(operation: str) -> bool:
    normalized = operation.lower().replace("-", "_")
    if normalized in _NEVER_READ_ONLY:
        return False
    return normalized.startswith(_READ_ONLY_PREFIXES)


def assert_read_only(operation: str) -> None:
    """The single enforcement point every adapter call must pass through."""
    if not is_read_only_operation(operation):
        raise ReadOnlyViolation(
            f"operation '{operation}' is not on the read-only allowlist. Phase 5 cloud adapters "
            f"are read-only by construction (Part 6): live infrastructure mutation requires "
            f"explicit human approval and is not performed by this platform."
        )


@dataclass
class CloudResource:
    """One resource observed live. `attributes` is intentionally a flat
    map of normalized, provider-neutral keys (`public`, `encrypted`,
    `logging`, ...) so `infra/drift.py` can compare it against repository
    state without knowing which cloud it came from."""
    resource_id: str
    resource_type: str
    capability: CloudCapability
    region: Optional[str] = None
    attributes: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["capability"] = self.capability.value
        return d


@dataclass
class CloudDiscoveryResult:
    provider: str
    status: CloudAdapterStatus
    reason: str
    account_id: Optional[str] = None
    resources: list[CloudResource] = field(default_factory=list)
    capabilities_attempted: list[CloudCapability] = field(default_factory=list)
    capabilities_failed: dict = field(default_factory=dict)  # capability -> error string

    @property
    def is_real(self) -> bool:
        return self.status == CloudAdapterStatus.AVAILABLE

    def to_dict(self) -> dict:
        return {
            "provider": self.provider, "status": self.status.value, "reason": self.reason,
            # The account id is an identifier, not a credential, but it is
            # still tenant-identifying - masked to its last 4 digits, the
            # same instinct as Phase 4's redacted secret previews.
            "account_id": (f"****{self.account_id[-4:]}" if self.account_id
                            and len(self.account_id) >= 4 else self.account_id),
            "resource_count": len(self.resources),
            "capabilities_attempted": [c.value for c in self.capabilities_attempted],
            "capabilities_failed": self.capabilities_failed,
            "resources": [r.to_dict() for r in self.resources],
        }


class CloudProviderAdapter(Protocol):
    """Every adapter exposes exactly this surface. Note the absence of any
    create/update/delete verb - that is the point."""

    provider: str
    supported_capabilities: set[CloudCapability]

    def status(self) -> tuple[CloudAdapterStatus, str]: ...

    def discover(self, capabilities: Optional[list[CloudCapability]] = None
                  ) -> CloudDiscoveryResult: ...
