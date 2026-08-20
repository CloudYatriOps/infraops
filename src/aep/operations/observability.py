"""Part 2: provider-neutral observability adapter contract.

Mirrors `security/scanners/base.py`'s adapter shape: a fixed
`check_availability()`/`describe()`/query surface every concrete provider
implements identically, so the correlation/RCA engines never need to know
which provider (if any) is behind an adapter.

Discovery surfaces (Part 2): metrics, logs, traces, alerts, service health,
deployment/version information.

Environment fact (Phase 7, checked live in this sandbox - see
ARCHITECTURE.md §28): there is no running Prometheus/Grafana/Datadog/OTel
collector reachable here, and outbound network to any of Datadog's or a
cloud monitoring vendor's real API is not configured. Every concrete
"live monitoring system" adapter below therefore honestly reports
NOT_IMPLEMENTED - implementing a fake local Prometheus and calling it
"real" would violate this platform's entire evidentiary discipline. The
one genuinely REAL adapter in this phase (`DeploymentHistoryAdapter`)
answers the "deployment/version information" and "service health" surfaces
using this platform's OWN durable Phase 6 deployment evidence - a real,
already-running, already-queried system in this sandbox, not a stand-in.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class AdapterAvailability(str, Enum):
    REAL = "REAL"
    MOCKED = "MOCKED"
    UNAVAILABLE = "UNAVAILABLE"
    BLOCKED = "BLOCKED"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"


@dataclass
class AvailabilityResult:
    status: AdapterAvailability
    detail: str = ""


@dataclass
class ObservationResult:
    """Result of any single discovery query (metrics/logs/traces/alerts/
    health/deployment-info). `status` must never read REAL/MOCKED unless
    the adapter genuinely produced data - an UNAVAILABLE/BLOCKED/
    NOT_IMPLEMENTED adapter must never be silently treated as an empty-but-
    passing result (Phase 7 spec: "Never report PASS when a required tool
    or integration was unavailable")."""
    surface: str  # "metrics" | "logs" | "traces" | "alerts" | "health" | "deployment_info"
    status: AdapterAvailability
    data: list[dict]
    detail: str = ""

    def to_dict(self) -> dict:
        return {"surface": self.surface, "status": self.status.value, "data": self.data,
                "detail": self.detail}


class ObservabilityAdapter:
    """Contract every concrete provider adapter implements. Subclasses must
    not fabricate data for a surface they cannot genuinely reach - see
    `NotImplementedAdapter` below for the honest default."""

    provider_name: str = "base"

    def check_availability(self) -> AvailabilityResult:
        raise NotImplementedError

    def describe(self) -> dict:
        return {"provider": self.provider_name, "availability": self.check_availability().status.value}

    def metrics(self, service: Optional[str] = None) -> ObservationResult:
        raise NotImplementedError

    def logs(self, service: Optional[str] = None) -> ObservationResult:
        raise NotImplementedError

    def traces(self, service: Optional[str] = None) -> ObservationResult:
        raise NotImplementedError

    def alerts(self, service: Optional[str] = None) -> ObservationResult:
        raise NotImplementedError

    def service_health(self, service: Optional[str] = None) -> ObservationResult:
        raise NotImplementedError

    def deployment_info(self, service: Optional[str] = None) -> ObservationResult:
        raise NotImplementedError


class NotImplementedAdapter(ObservabilityAdapter):
    """Honest placeholder for a provider whose contract is defined but for
    which this sandbox has no genuine, reachable backend. Used for
    Prometheus/Grafana/Datadog/OpenTelemetry-compatible/cloud-monitoring
    providers - implementing the contract now (Part 2) without ever
    claiming a live integration that does not exist here."""

    def __init__(self, provider_name: str, reason: str = "no reachable backend in this environment"):
        self.provider_name = provider_name
        self._reason = reason

    def check_availability(self) -> AvailabilityResult:
        return AvailabilityResult(AdapterAvailability.NOT_IMPLEMENTED, self._reason)

    def _unimpl(self, surface: str) -> ObservationResult:
        return ObservationResult(surface=surface, status=AdapterAvailability.NOT_IMPLEMENTED,
                                  data=[], detail=self._reason)

    def metrics(self, service: Optional[str] = None) -> ObservationResult:
        return self._unimpl("metrics")

    def logs(self, service: Optional[str] = None) -> ObservationResult:
        return self._unimpl("logs")

    def traces(self, service: Optional[str] = None) -> ObservationResult:
        return self._unimpl("traces")

    def alerts(self, service: Optional[str] = None) -> ObservationResult:
        return self._unimpl("alerts")

    def service_health(self, service: Optional[str] = None) -> ObservationResult:
        return self._unimpl("service_health")

    def deployment_info(self, service: Optional[str] = None) -> ObservationResult:
        return self._unimpl("deployment_info")


PROMETHEUS = "prometheus"
GRAFANA = "grafana"
DATADOG = "datadog"
OPENTELEMETRY = "opentelemetry"
CLOUD_MONITORING = "cloud_monitoring"

KNOWN_UNIMPLEMENTED_PROVIDERS = (PROMETHEUS, GRAFANA, DATADOG, OPENTELEMETRY, CLOUD_MONITORING)


def build_unimplemented_registry() -> dict[str, NotImplementedAdapter]:
    """Every future-provider adapter the Phase 7 spec names, all honestly
    NOT_IMPLEMENTED in this sandbox (Part 2)."""
    return {name: NotImplementedAdapter(name) for name in KNOWN_UNIMPLEMENTED_PROVIDERS}


class DeploymentHistoryAdapter(ObservabilityAdapter):
    """The one genuinely REAL adapter in this phase: it answers
    `deployment_info`/`service_health` from this platform's OWN durable
    Phase 6 deployment evidence (`deployment/evidence.py`), which is a
    real, already-persisted record of what this platform itself deployed -
    not a mock and not a third-party integration. `metrics`/`logs`/
    `traces`/`alerts` are outside what deployment evidence can answer, so
    those surfaces report UNAVAILABLE (not NOT_IMPLEMENTED - the contract
    IS implemented, the data genuinely does not exist for this adapter)."""

    provider_name = "deployment_history"

    def __init__(self, list_evidence_fn):
        """`list_evidence_fn` is a zero-arg callable returning
        `list[DeploymentRecord]` - callers supply this via the existing
        capability-scoped `deployment.list_evidence` tool (agents) or
        directly via `deployment/evidence.py` (tests), never a raw
        StateStore handed to this adapter, so this module stays agnostic
        to how evidence is actually retrieved."""
        self._list_evidence_fn = list_evidence_fn

    def check_availability(self) -> AvailabilityResult:
        return AvailabilityResult(AdapterAvailability.REAL,
                                   "reads this platform's own durable deployment evidence")

    def _records(self):
        return self._list_evidence_fn()

    def _unavailable(self, surface: str) -> ObservationResult:
        return ObservationResult(surface=surface, status=AdapterAvailability.UNAVAILABLE, data=[],
                                  detail="deployment evidence cannot answer this surface")

    def metrics(self, service: Optional[str] = None) -> ObservationResult:
        return self._unavailable("metrics")

    def logs(self, service: Optional[str] = None) -> ObservationResult:
        return self._unavailable("logs")

    def traces(self, service: Optional[str] = None) -> ObservationResult:
        return self._unavailable("traces")

    def alerts(self, service: Optional[str] = None) -> ObservationResult:
        return self._unavailable("alerts")

    def service_health(self, service: Optional[str] = None) -> ObservationResult:
        records = self._records()
        if not records:
            return ObservationResult(surface="service_health", status=AdapterAvailability.REAL,
                                      data=[], detail="no deployment evidence recorded yet")
        latest = records[-1]
        healthy = latest.final_state.value in ("VERIFIED", "DEPLOYED")
        return ObservationResult(
            surface="service_health", status=AdapterAvailability.REAL,
            data=[{"environment": latest.environment, "final_state": latest.final_state.value,
                   "healthy": healthy, "commit_sha": latest.commit_sha}],
            detail=f"derived from latest recorded deployment ({latest.final_state.value})",
        )

    def deployment_info(self, service: Optional[str] = None) -> ObservationResult:
        records = self._records()
        return ObservationResult(
            surface="deployment_info", status=AdapterAvailability.REAL,
            data=[{"commit_sha": r.commit_sha, "artifact_id": r.artifact_id,
                   "environment": r.environment, "final_state": r.final_state.value,
                   "started_at": r.started_at} for r in records],
            detail=f"{len(records)} recorded deployment(s)",
        )
