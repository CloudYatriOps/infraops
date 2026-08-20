"""Part 3: deterministic Incident Correlation Engine.

Groups related `OperationalEvent`s into `Incident`s using: time proximity,
service identity, deployment/version, environment, and error-signature
(category) match - all of which are cheap, deterministic properties of the
events themselves, never a model call, so the same input list always
produces the same incidents (a hard requirement for testability, Part 3).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from .models import Incident, OperationalEvent

DEFAULT_WINDOW = timedelta(minutes=10)


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def _fingerprint(service, environment, deployment_version, category) -> str:
    return "|".join(str(x) for x in (service or "-", environment or "-",
                                      deployment_version or "-", category or "-"))


class IncidentCorrelationEngine:
    def __init__(self, window: timedelta = DEFAULT_WINDOW):
        self.window = window

    def correlate(self, events: list[OperationalEvent]) -> list[Incident]:
        """Groups events sharing the same service+environment when they
        fall within `window` of each other (chained: A groups with B if
        within window of A, B groups with C if within window of B, etc -
        this is what lets "deploy -> error rate up -> pods restart ->
        readiness fails" become one incident even though the last event may
        be well outside the window of the FIRST one)."""
        by_key: dict[tuple, list[OperationalEvent]] = {}
        for event in events:
            key = (event.service, event.environment)
            by_key.setdefault(key, []).append(event)

        incidents: list[Incident] = []
        for (service, environment), group in by_key.items():
            group_sorted = sorted(group, key=lambda e: _parse(e.timestamp))
            cluster: list[OperationalEvent] = []
            last_time = None
            for event in group_sorted:
                t = _parse(event.timestamp)
                if last_time is not None and (t - last_time) > self.window:
                    incidents.append(self._build_incident(service, environment, cluster))
                    cluster = []
                cluster.append(event)
                last_time = t
            if cluster:
                incidents.append(self._build_incident(service, environment, cluster))
        return sorted(incidents, key=lambda i: i.created_at)

    def _build_incident(self, service, environment, cluster: list[OperationalEvent]) -> Incident:
        versions = sorted({e.deployment_version for e in cluster if e.deployment_version})
        version = versions[0] if len(versions) == 1 else (versions[-1] if versions else None)
        categories = sorted({e.category.value for e in cluster})
        reasons = [f"{len(cluster)} event(s) for service={service!r} environment={environment!r} "
                   f"within a {self.window.total_seconds() / 60:.0f}-minute correlation window",
                   f"categories involved: {categories}"]
        if len(versions) > 1:
            reasons.append(f"multiple deployment versions present ({versions}) - correlation "
                            f"grouped by time/service/environment only; version is NOT used to "
                            f"split the cluster since a bad deploy legitimately spans two "
                            f"versions (old failing, new just rolled out)")
        confidence = min(1.0, 0.5 + 0.1 * len(cluster))
        fingerprint = _fingerprint(service, environment, version, "+".join(categories))
        return Incident(
            incident_id=str(uuid.uuid4()), fingerprint=fingerprint,
            event_ids=[e.event_id for e in cluster], service=service, environment=environment,
            deployment_version=version, confidence=round(confidence, 2),
            reasoning="; ".join(reasons),
        )
