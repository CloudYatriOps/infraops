from aep.operations.escalation import build_escalation
from aep.operations.models import Diagnosis, Incident, RCAConfidence, RootCauseCategory


def test_escalation_is_operationally_useful_not_vague():
    incident = Incident(incident_id="i1", fingerprint="fp1", event_ids=["e1", "e2"],
                         service="svc-a", environment="production", deployment_version="v2",
                         confidence=0.8, reasoning="2 events correlated")
    diagnosis = Diagnosis(hypothesis=RootCauseCategory.BAD_DEPLOYMENT,
                           confidence=RCAConfidence.HIGH_CONFIDENCE,
                           supporting_evidence=["deployment v2 correlates with incident window"],
                           recommended_next_diagnostic_action="compare v1 vs v2 diffs")
    escalation = build_escalation(
        incident, diagnosis, attempted=["inspect_deployment"], changed=[],
        failed=[], required_action="approve production rollback",
        recommended_step="roll back to v1 after approval",
    )
    text = escalation.to_text()
    for required_phrase in ("WHAT HAPPENED", "CURRENT IMPACT", "CONFIRMED FACTS",
                             "LIKELY ROOT CAUSE", "CONFIDENCE", "WHAT AEP TRIED",
                             "WHAT CHANGED", "WHAT DID NOT WORK",
                             "WHAT HUMAN APPROVAL OR ACTION IS REQUIRED",
                             "RECOMMENDED NEXT STEP"):
        assert required_phrase in text
    assert "svc-a" in text
    assert "BAD_DEPLOYMENT" in text
    assert "approve production rollback" in text
    # never a vague placeholder message
    assert "something failed" not in text.lower()
