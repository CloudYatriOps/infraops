from aep.operations.correlation import IncidentCorrelationEngine
from aep.operations.models import EventCategory, EventSeverity, OperationalEvent


def _event(eid, ts, category, service="svc-a", environment="production", version=None):
    return OperationalEvent(event_id=eid, timestamp=ts, source="test", category=category,
                             severity=EventSeverity.HIGH, environment=environment, service=service,
                             deployment_version=version)


def test_correlates_deploy_then_error_then_restart_into_one_incident():
    events = [
        _event("e1", "2026-01-01T00:00:00+00:00", EventCategory.DEPLOYMENT_REGRESSION, version="v2"),
        _event("e2", "2026-01-01T00:03:00+00:00", EventCategory.PERFORMANCE_DEGRADATION, version="v2"),
        _event("e3", "2026-01-01T00:05:00+00:00", EventCategory.REPEATED_RESTART, version="v2"),
        _event("e4", "2026-01-01T00:07:00+00:00", EventCategory.READINESS_FAILURE, version="v2"),
    ]
    incidents = IncidentCorrelationEngine().correlate(events)
    assert len(incidents) == 1
    assert set(incidents[0].event_ids) == {"e1", "e2", "e3", "e4"}
    assert incidents[0].deployment_version == "v2"
    assert incidents[0].confidence > 0.5


def test_events_outside_window_become_separate_incidents():
    events = [
        _event("e1", "2026-01-01T00:00:00+00:00", EventCategory.APPLICATION_CRASH),
        _event("e2", "2026-01-01T01:00:00+00:00", EventCategory.APPLICATION_CRASH),
    ]
    incidents = IncidentCorrelationEngine().correlate(events)
    assert len(incidents) == 2


def test_different_services_never_grouped_together():
    events = [
        _event("e1", "2026-01-01T00:00:00+00:00", EventCategory.APPLICATION_CRASH, service="svc-a"),
        _event("e2", "2026-01-01T00:01:00+00:00", EventCategory.APPLICATION_CRASH, service="svc-b"),
    ]
    incidents = IncidentCorrelationEngine().correlate(events)
    assert len(incidents) == 2
    assert {i.service for i in incidents} == {"svc-a", "svc-b"}


def test_correlation_is_deterministic_across_runs():
    events = [
        _event("e1", "2026-01-01T00:00:00+00:00", EventCategory.APPLICATION_CRASH),
        _event("e2", "2026-01-01T00:01:00+00:00", EventCategory.REPEATED_RESTART),
    ]
    engine = IncidentCorrelationEngine()
    first = [i.fingerprint for i in engine.correlate(events)]
    second = [i.fingerprint for i in engine.correlate(events)]
    assert first == second
