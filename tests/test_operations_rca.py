from aep.operations.correlation import IncidentCorrelationEngine
from aep.operations.models import EventCategory, EventSeverity, OperationalEvent, RCAConfidence, RootCauseCategory
from aep.operations.rca import RootCauseAnalyzer


def _event(eid, ts, category, version=None):
    return OperationalEvent(event_id=eid, timestamp=ts, source="test", category=category,
                             severity=EventSeverity.HIGH, environment="production", service="svc-a",
                             deployment_version=version)


def test_bad_deployment_with_version_is_high_confidence():
    events = [
        _event("e1", "2026-01-01T00:00:00+00:00", EventCategory.DEPLOYMENT_REGRESSION, version="v2"),
        _event("e2", "2026-01-01T00:01:00+00:00", EventCategory.READINESS_FAILURE, version="v2"),
    ]
    incident = IncidentCorrelationEngine().correlate(events)[0]
    diagnosis = RootCauseAnalyzer().diagnose(incident, events)
    assert diagnosis.hypothesis == RootCauseCategory.BAD_DEPLOYMENT
    assert diagnosis.confidence == RCAConfidence.HIGH_CONFIDENCE
    assert diagnosis.safe_to_auto_remediate


def test_symptom_only_events_are_unknown_and_never_auto_remediated():
    events = [
        _event("e1", "2026-01-01T00:00:00+00:00", EventCategory.READINESS_FAILURE),
        _event("e2", "2026-01-01T00:01:00+00:00", EventCategory.REPEATED_RESTART),
    ]
    incident = IncidentCorrelationEngine().correlate(events)[0]
    diagnosis = RootCauseAnalyzer().diagnose(incident, events)
    assert diagnosis.hypothesis == RootCauseCategory.UNKNOWN
    assert diagnosis.confidence == RCAConfidence.UNKNOWN
    assert not diagnosis.safe_to_auto_remediate
    assert "Insufficient evidence" in diagnosis.recommended_next_diagnostic_action


def test_bad_deployment_without_version_is_downgraded_to_possible():
    events = [_event("e1", "2026-01-01T00:00:00+00:00", EventCategory.DEPLOYMENT_REGRESSION)]
    incident = IncidentCorrelationEngine().correlate(events)[0]
    diagnosis = RootCauseAnalyzer().diagnose(incident, events)
    assert diagnosis.confidence == RCAConfidence.POSSIBLE
    assert not diagnosis.safe_to_auto_remediate
    assert diagnosis.missing_evidence


def test_multiple_competing_explanatory_categories_lowers_confidence():
    events = [
        _event("e1", "2026-01-01T00:00:00+00:00", EventCategory.DATABASE_CONNECTIVITY_FAILURE),
        _event("e2", "2026-01-01T00:01:00+00:00", EventCategory.NETWORK_FAILURE),
    ]
    incident = IncidentCorrelationEngine().correlate(events)[0]
    diagnosis = RootCauseAnalyzer().diagnose(incident, events)
    assert diagnosis.confidence == RCAConfidence.POSSIBLE
    assert diagnosis.contradicting_evidence


def test_no_events_is_unknown():
    from aep.operations.models import Incident
    incident = Incident(incident_id="i1", fingerprint="f", event_ids=[], service=None,
                         environment=None, deployment_version=None, confidence=0.0, reasoning="")
    diagnosis = RootCauseAnalyzer().diagnose(incident, [])
    assert diagnosis.confidence == RCAConfidence.UNKNOWN
