from aep.operations.models import (
    Diagnosis, EventCategory, EventSeverity, OperationalEvent, RCAConfidence, RootCauseCategory,
)


def test_event_round_trips_through_dict():
    e = OperationalEvent(event_id="e1", timestamp="2026-01-01T00:00:00+00:00", source="k8s",
                          category=EventCategory.APPLICATION_CRASH, severity=EventSeverity.HIGH,
                          environment="production", service="svc-a")
    d = e.to_dict()
    assert d["category"] == "APPLICATION_CRASH"
    back = OperationalEvent.from_dict(d)
    assert back == e


def test_diagnosis_safe_to_auto_remediate_only_for_confident_confidences():
    for confidence, expected in (
        (RCAConfidence.CONFIRMED, True), (RCAConfidence.HIGH_CONFIDENCE, True),
        (RCAConfidence.LIKELY, True), (RCAConfidence.POSSIBLE, False), (RCAConfidence.UNKNOWN, False),
    ):
        d = Diagnosis(hypothesis=RootCauseCategory.BAD_DEPLOYMENT, confidence=confidence)
        assert d.safe_to_auto_remediate is expected
