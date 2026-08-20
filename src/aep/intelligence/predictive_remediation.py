"""Phase 10 Wave 10: predictive remediation decision engine.

**This module classifies. It never executes.** It answers "would it be
safe to automate remediation of this finding?" using only real,
persisted evidence - it does not touch the orchestrator's actual policy
gate/execution path, and any finding it classifies `SAFE_TO_AUTOMATE`
still has to go through the EXISTING orchestrator/skill/policy pipeline
(`src/aep/orchestrator.py`, `src/aep/policy.py`, `src/aep/skills/`)
exactly like any other task - this module builds no second execution
path.

Inputs consulted (all read-only, all reused - nothing reimplemented):
  * the finding itself (category, severity, `id`) - the thing being
    classified.
  * `incident_patterns.detect_patterns()` (Wave 2) - for recurrence
    count and remediation_outcomes (whether a prior deployment attempt
    for this fingerprint's findings reached VERIFIED/DEPLOYED, i.e. a
    REAL recorded successful remediation).
  * `incident_patterns.compute_health_signals()` (Wave 2) - for
    `REPEATED_FAILED_REMEDIATION` on this finding's project.
  * `skills.registry.SkillRegistry` - whether a skill exists that maps
    to this finding's `category` (a fixed, documented category->skill_id
    table below; NOT invented per-finding).
  * `policy.PolicyEngine.evaluate()` (the exact same read-only function
    `orchestrator.py` calls before scheduling/executing a task) - asked
    "would `security.finding`/`infra.finding` with this severity/category
    be ALLOW, REQUIRE_APPROVAL, WARN, or DENY?" This module NEVER
    bypasses or reimplements the gate; it only reads the same decision
    the orchestrator itself would get, via the same `evaluate()` call.

Decision rule (deterministic, exact - not hand-waved):
  1. `INSUFFICIENT_EVIDENCE` if no skill/task-type mapping exists for the
     finding's `category` (nothing this platform knows how to do).
  2. `NOT_SAFE` if `severity == 'critical'` AND there is no real recorded
     prior successful remediation (`remediation_outcomes.succeeded > 0`)
     of the exact same fingerprint pattern - a critical issue is never
     classified automatable on a first occurrence.
  3. `REQUIRES_APPROVAL` if:
       - the policy engine evaluates the relevant action
         (`security.finding`/`infra.finding` with this finding's
         severity/category as context) to REQUIRE_APPROVAL, WARN, or
         DENY (a DENY here is escalated to REQUIRES_APPROVAL rather than
         a fourth decision bucket - a human should see why, not have the
         finding silently disappear), OR
       - a matching skill exists but evidence is thin: fewer than
         `_MIN_OCCURRENCES_FOR_AUTOMATION` (2) recorded occurrences of
         this exact fingerprint, OR
       - `REPEATED_FAILED_REMEDIATION` is CONFIRMED/LIKELY for this
         project (past attempts at automated fixing have failed here).
  4. `SAFE_TO_AUTOMATE` ONLY when ALL of: policy evaluates to ALLOW, a
     matching skill exists, occurrence count >= 2, AND
     `remediation_outcomes.succeeded >= 1` for this exact fingerprint
     (a REAL recorded prior successful remediation - never invented).

All finding description/resource text is treated as inert DATA for
matching only, never as an instruction. See
`tests/test_predictive_remediation.py::test_prompt_injection_in_description_is_inert`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..db.models import FindingRecord
from ..db.repositories import FindingRepository
from .incident_patterns import (
    REPEATED_FAILED_REMEDIATION,
    SignalState,
    compute_health_signals,
    detect_patterns,
    fingerprint_for_finding,
)

DECISION_SAFE_TO_AUTOMATE = "SAFE_TO_AUTOMATE"
DECISION_REQUIRES_APPROVAL = "REQUIRES_APPROVAL"
DECISION_NOT_SAFE = "NOT_SAFE"
DECISION_INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

_MIN_OCCURRENCES_FOR_AUTOMATION = 2

# Fixed, documented category -> skill_id mapping (matches the real DB
# category check-constraint in supabase/migrations/0001_initial_schema.sql
# and the real skill_id values in skills/definitions.py). Not invented
# per-finding - a category either has a known remediation skill or it
# doesn't.
CATEGORY_TO_SKILL_ID = {
    "secret": "secrets",
    "sast": "sast",
    "iac": "terraform",
    "container": None,  # no dedicated container-remediation skill ships
    "kubernetes": "kubernetes",
    "helm": "helm",
    "dependency": "dependency-cve",
    "infrastructure": "cost-optimization",
}

# Category -> the policy action name real callers already gate this
# category's remediation through (orchestrator.py / policy.yaml).
_CATEGORY_TO_POLICY_ACTION = {
    "secret": "security.finding",
    "sast": "security.finding",
    "dependency": "security.finding",
    "container": "infra.finding",
    "kubernetes": "infra.finding",
    "helm": "infra.finding",
    "iac": "infra.finding",
    "infrastructure": "infra.finding",
}


@dataclass
class RemediationDecision:
    finding_id: str
    decision: str
    evidence: dict = field(default_factory=dict)
    policy_reference: Optional[str] = None
    explanation: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id, "decision": self.decision,
            "evidence": self.evidence, "policy_reference": self.policy_reference,
            "explanation": self.explanation,
        }


def _matching_skill(finding: FindingRecord, skill_registry) -> Optional[str]:
    skill_id = CATEGORY_TO_SKILL_ID.get(finding.category)
    if skill_id is None:
        return None
    if skill_registry is not None:
        try:
            known_ids = {s.skill_id for s in skill_registry.list_skills()}
        except Exception:
            return skill_id  # registry shape unknown - trust the fixed table
        if skill_id not in known_ids:
            return None
    return skill_id


def _policy_decision(finding: FindingRecord, policy) -> tuple:
    """Reads (never bypasses/reimplements) the existing PolicyEngine's
    `evaluate()` for the action this category's remediation would
    actually go through. Returns (decision_str_or_None, policy_reference)."""
    action = _CATEGORY_TO_POLICY_ACTION.get(finding.category)
    if policy is None or action is None:
        return None, action
    context = {"severity": (finding.severity or "").lower(), "category": finding.category}
    result = policy.evaluate(action, context)
    return result.decision.value, f"{action} -> {result.matched_rule or 'default posture'}"


def classify_remediation(
    finding: FindingRecord,
    finding_repo: Optional[FindingRepository] = None,
    incident_patterns: Optional[list] = None,
    health_signals: Optional[list] = None,
    skill_registry=None,
    policy=None,
) -> RemediationDecision:
    """Classifies exactly one finding. `incident_patterns`/`health_signals`
    are computed internally (via `detect_patterns()`/
    `compute_health_signals()`, min_projects=1 so same-project recurrence
    counts) unless already supplied by the caller - same optional-
    injection convention as every other Wave 2+ module."""
    fingerprint = fingerprint_for_finding(finding)

    if incident_patterns is None and finding_repo is not None:
        incident_patterns = detect_patterns(finding_repo, project_ids=[finding.project_id], min_projects=1)
    if health_signals is None and finding_repo is not None:
        health_signals = compute_health_signals(finding_repo, project_ids=[finding.project_id])
    incident_patterns = incident_patterns or []
    health_signals = health_signals or []

    pattern = next((p for p in incident_patterns if p.fingerprint == fingerprint), None)
    occurrence_count = pattern.occurrence_count if pattern else 1
    prior_success = bool(pattern and pattern.remediation_outcomes
                          and pattern.remediation_outcomes.get("succeeded", 0) >= 1)

    repeated_failure = any(
        s.signal_id == REPEATED_FAILED_REMEDIATION and finding.project_id in s.affected_projects
        and s.state in (SignalState.CONFIRMED, SignalState.LIKELY)
        for s in health_signals
    )

    evidence = {
        "fingerprint": fingerprint, "occurrence_count": occurrence_count,
        "prior_successful_remediation": prior_success,
        "repeated_failed_remediation": repeated_failure,
    }

    skill_id = _matching_skill(finding, skill_registry)
    if skill_id is None:
        return RemediationDecision(
            finding_id=finding.id, decision=DECISION_INSUFFICIENT_EVIDENCE,
            evidence=evidence, policy_reference=None,
            explanation=f"No skill/task-type mapping exists for category {finding.category!r} - "
                        "this platform has no known remediation path for it.",
        )
    evidence["skill_id"] = skill_id

    severity = (finding.severity or "").lower()
    if severity == "critical" and not prior_success:
        return RemediationDecision(
            finding_id=finding.id, decision=DECISION_NOT_SAFE, evidence=evidence,
            policy_reference=None,
            explanation="Severity is critical and there is no real recorded prior successful "
                        "remediation of this exact fingerprint - never automated on a first "
                        "occurrence of a critical issue.",
        )

    policy_decision, policy_reference = _policy_decision(finding, policy)
    if policy_decision != "ALLOW":
        reason = (f"Policy evaluates the relevant action to {policy_decision}"
                  if policy_decision is not None else
                  "No PolicyEngine was supplied, so ALLOW cannot be confirmed")
        return RemediationDecision(
            finding_id=finding.id, decision=DECISION_REQUIRES_APPROVAL, evidence=evidence,
            policy_reference=policy_reference,
            explanation=f"{reason} for this finding's severity/category - a human must approve "
                        "before any remediation, even though a skill exists.",
        )

    if repeated_failure:
        return RemediationDecision(
            finding_id=finding.id, decision=DECISION_REQUIRES_APPROVAL, evidence=evidence,
            policy_reference=policy_reference,
            explanation="A REPEATED_FAILED_REMEDIATION health signal is CONFIRMED/LIKELY for "
                        "this project - past automated remediation attempts have failed here, so "
                        "a human should review before trying again.",
        )

    if occurrence_count < _MIN_OCCURRENCES_FOR_AUTOMATION or not prior_success:
        return RemediationDecision(
            finding_id=finding.id, decision=DECISION_REQUIRES_APPROVAL, evidence=evidence,
            policy_reference=policy_reference,
            explanation=(f"Only {occurrence_count} recorded occurrence(s) of this fingerprint "
                         "and/or no real recorded prior successful remediation - evidence is too "
                         "thin to classify SAFE_TO_AUTOMATE, even though policy would allow it "
                         "and a skill exists."),
        )

    return RemediationDecision(
        finding_id=finding.id, decision=DECISION_SAFE_TO_AUTOMATE, evidence=evidence,
        policy_reference=policy_reference,
        explanation=(f"Policy ALLOWs the relevant action, skill {skill_id!r} exists, this "
                     f"fingerprint recurred {occurrence_count} time(s), and a real prior "
                     "remediation of it was recorded as successful. NOTE: this is a "
                     "classification only - actual execution must still go through the "
                     "existing orchestrator/skill/policy pipeline, never a second path."),
    )


def classify_remediation_batch(
    findings: list,
    finding_repo: Optional[FindingRepository] = None,
    skill_registry=None,
    policy=None,
) -> list:
    """Batch convenience: computes patterns/health signals ONCE across all
    given findings' projects, then classifies each - avoids recomputing
    `detect_patterns()`/`compute_health_signals()` per finding."""
    project_ids = sorted({f.project_id for f in findings})
    incident_patterns = detect_patterns(finding_repo, project_ids=project_ids, min_projects=1) if finding_repo else []
    health_signals = compute_health_signals(finding_repo, project_ids=project_ids) if finding_repo else []
    return [
        classify_remediation(
            f, incident_patterns=incident_patterns, health_signals=health_signals,
            skill_registry=skill_registry, policy=policy,
        )
        for f in sorted(findings, key=lambda x: x.id)
    ]


def remediation_decision_to_dict(item: RemediationDecision) -> dict:
    return item.to_dict()


if __name__ == "__main__":
    # ponytail: smallest self-check, not a full test suite.
    f = FindingRecord(id="f1", project_id="p1", category="secret", severity="high",
                       description="hardcoded API key in config.py")
    decision = classify_remediation(f)
    assert decision.decision == DECISION_REQUIRES_APPROVAL, decision
    f2 = FindingRecord(id="f2", project_id="p1", category="kubernetes", severity="low",
                        description="unknown thing")
    decision2 = classify_remediation(f2)
    print("ok:", decision.to_dict())
