"""Part 4: Root Cause Analysis engine.

Deterministic, signal-shape-based classification - same discipline as
`failure.classify()` and `cicd/failure_classification.py`: never "ask a
model what went wrong." A diagnosis is built from the event categories
present in an incident plus whether a deployment happened recently
relative to the incident (`deployment_version` set on the incident), and
always states what evidence is missing rather than inventing certainty.
"""
from __future__ import annotations

from .dependency_graph import ServiceDependencyGraph
from .models import Diagnosis, EventCategory, Incident, OperationalEvent, RCAConfidence, RootCauseCategory

_CATEGORY_TO_ROOT_CAUSE: dict[EventCategory, RootCauseCategory] = {
    EventCategory.DEPLOYMENT_REGRESSION: RootCauseCategory.BAD_DEPLOYMENT,
    EventCategory.CI_DEPLOYMENT_FAILURE: RootCauseCategory.BAD_DEPLOYMENT,
    EventCategory.APPLICATION_CRASH: RootCauseCategory.APPLICATION_DEFECT,
    EventCategory.DEPENDENCY_OUTAGE: RootCauseCategory.DEPENDENCY_FAILURE,
    EventCategory.DATABASE_CONNECTIVITY_FAILURE: RootCauseCategory.DATABASE_FAILURE,
    EventCategory.NETWORK_FAILURE: RootCauseCategory.NETWORK_FAILURE,
    EventCategory.DNS_FAILURE: RootCauseCategory.DNS_FAILURE,
    EventCategory.CERTIFICATE_EXPIRATION: RootCauseCategory.CERTIFICATE_FAILURE,
    EventCategory.SECURITY_INCIDENT: RootCauseCategory.SECURITY_POLICY_FAILURE,
    EventCategory.INFRASTRUCTURE_DRIFT: RootCauseCategory.INFRASTRUCTURE_MISCONFIGURATION,
    EventCategory.CPU_SATURATION: RootCauseCategory.CAPACITY_EXHAUSTION,
    EventCategory.MEMORY_EXHAUSTION: RootCauseCategory.CAPACITY_EXHAUSTION,
    EventCategory.DISK_PRESSURE: RootCauseCategory.CAPACITY_EXHAUSTION,
    EventCategory.RESOURCE_EXHAUSTION: RootCauseCategory.CAPACITY_EXHAUSTION,
}

# Categories that, on their own with no deployment correlation, are never
# enough to name a specific root cause - they are downstream SYMPTOMS
# (a readiness failure could be caused by almost anything upstream).
_SYMPTOM_ONLY = {
    EventCategory.READINESS_FAILURE, EventCategory.LIVENESS_FAILURE,
    EventCategory.HEALTH_CHECK_FAILURE, EventCategory.REPEATED_RESTART,
    EventCategory.PERFORMANCE_DEGRADATION,
}


class RootCauseAnalyzer:
    def diagnose(self, incident: Incident, events: list[OperationalEvent],
                 graph: ServiceDependencyGraph | None = None) -> Diagnosis:
        categories = {e.category for e in events if e.event_id in incident.event_ids}
        explanatory = categories - _SYMPTOM_ONLY
        supporting: list[str] = []
        contradicting: list[str] = []
        missing: list[str] = []

        if not categories:
            return Diagnosis(
                hypothesis=RootCauseCategory.UNKNOWN, confidence=RCAConfidence.UNKNOWN,
                missing_evidence=["no events attached to this incident"],
                recommended_next_diagnostic_action="collect events before diagnosing",
            )

        if explanatory:
            # Prefer BAD_DEPLOYMENT when a deployment-shaped category is
            # present AND a deployment_version is recorded on the incident -
            # a version being present is itself the corroborating evidence
            # that a deploy actually happened near this incident.
            ranked = sorted(explanatory, key=lambda c: (
                0 if _CATEGORY_TO_ROOT_CAUSE[c] == RootCauseCategory.BAD_DEPLOYMENT else 1,
                c.value,
            ))
            primary = ranked[0]
            hypothesis = _CATEGORY_TO_ROOT_CAUSE[primary]
            supporting.append(f"event category {primary.value} observed in this incident")
            if hypothesis == RootCauseCategory.BAD_DEPLOYMENT:
                if incident.deployment_version:
                    supporting.append(f"deployment version {incident.deployment_version} "
                                       f"correlates with this incident's time window")
                    confidence = RCAConfidence.HIGH_CONFIDENCE
                else:
                    missing.append("no deployment/version identifier correlated to this incident")
                    confidence = RCAConfidence.POSSIBLE
            else:
                confidence = RCAConfidence.LIKELY if len(explanatory) == 1 else RCAConfidence.POSSIBLE
                if len(explanatory) > 1:
                    contradicting.append(f"multiple distinct explanatory categories present "
                                          f"({sorted(c.value for c in explanatory)}) - competing "
                                          f"hypotheses, confidence lowered")

            symptoms = categories & _SYMPTOM_ONLY
            if symptoms:
                supporting.append(f"consistent with downstream symptom(s): "
                                   f"{sorted(c.value for c in symptoms)}")

            next_action = "none - evidence is sufficient to proceed to remediation planning" \
                if confidence in (RCAConfidence.CONFIRMED, RCAConfidence.HIGH_CONFIDENCE) \
                else "collect additional deployment/version evidence to raise confidence " \
                     "before automating remediation"
            return Diagnosis(hypothesis=hypothesis, confidence=confidence,
                              supporting_evidence=supporting, contradicting_evidence=contradicting,
                              missing_evidence=missing,
                              recommended_next_diagnostic_action=next_action)

        # Only symptom-shaped categories present: Part 4's explicit
        # "insufficient evidence" case - never guess a specific root cause
        # from a readiness/liveness/restart symptom alone.
        return Diagnosis(
            hypothesis=RootCauseCategory.UNKNOWN, confidence=RCAConfidence.UNKNOWN,
            supporting_evidence=[f"symptom-only categories observed: "
                                  f"{sorted(c.value for c in categories)}"],
            missing_evidence=["no explanatory (non-symptom) event category present",
                               "no deployment/version correlation", "no dependency-graph evidence "
                               "isolating a failing upstream service"],
            recommended_next_diagnostic_action=(
                "Insufficient evidence - do not remediate automatically. Collect logs/metrics for "
                "the affected service and its direct dependencies before forming a hypothesis."
            ),
        )
