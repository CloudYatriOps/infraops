"""Part 10: structured human escalation, built from real diagnosis/
remediation state rather than a vague "something failed, please
investigate" message.
"""
from __future__ import annotations

from .models import Diagnosis, Escalation, Incident


def build_escalation(incident: Incident, diagnosis: Diagnosis, attempted: list[str],
                      changed: list[str], failed: list[str],
                      required_action: str, recommended_step: str,
                      impact: str | None = None) -> Escalation:
    what_happened = (f"Incident {incident.incident_id} on service={incident.service!r} "
                      f"environment={incident.environment!r} "
                      f"(deployment_version={incident.deployment_version!r}): "
                      f"{incident.reasoning}")
    impact = impact or (f"{len(incident.event_ids)} correlated event(s); confidence of "
                         f"correlation={incident.confidence}")
    return Escalation(
        what_happened=what_happened,
        current_impact=impact,
        confirmed_facts=list(diagnosis.supporting_evidence),
        likely_root_cause=diagnosis.hypothesis.value,
        confidence=diagnosis.confidence.value,
        what_aep_tried=attempted,
        what_changed=changed,
        what_did_not_work=failed,
        what_human_action_required=required_action,
        recommended_next_step=recommended_step or diagnosis.recommended_next_diagnostic_action,
    )
