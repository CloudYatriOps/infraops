"""Part 1: normalized operational event model, plus the shared enums used
by correlation/RCA/remediation/escalation below.

Raw evidence is never duplicated in memory: an `OperationalEvent` carries an
`evidence_ref` (a durable `Evidence`/event id, or a free-text pointer into
the existing evidence mechanism) rather than the raw log/metric payload
itself - the same "reference, not a copy" discipline `deployment/evidence.py`
already uses for deployment records.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EventCategory(str, Enum):
    APPLICATION_CRASH = "APPLICATION_CRASH"
    REPEATED_RESTART = "REPEATED_RESTART"
    HEALTH_CHECK_FAILURE = "HEALTH_CHECK_FAILURE"
    READINESS_FAILURE = "READINESS_FAILURE"
    LIVENESS_FAILURE = "LIVENESS_FAILURE"
    CI_DEPLOYMENT_FAILURE = "CI_DEPLOYMENT_FAILURE"
    RESOURCE_EXHAUSTION = "RESOURCE_EXHAUSTION"
    CPU_SATURATION = "CPU_SATURATION"
    MEMORY_EXHAUSTION = "MEMORY_EXHAUSTION"
    DISK_PRESSURE = "DISK_PRESSURE"
    NETWORK_FAILURE = "NETWORK_FAILURE"
    DNS_FAILURE = "DNS_FAILURE"
    DEPENDENCY_OUTAGE = "DEPENDENCY_OUTAGE"
    DATABASE_CONNECTIVITY_FAILURE = "DATABASE_CONNECTIVITY_FAILURE"
    CERTIFICATE_EXPIRATION = "CERTIFICATE_EXPIRATION"
    SECURITY_INCIDENT = "SECURITY_INCIDENT"
    INFRASTRUCTURE_DRIFT = "INFRASTRUCTURE_DRIFT"
    DEPLOYMENT_REGRESSION = "DEPLOYMENT_REGRESSION"
    PERFORMANCE_DEGRADATION = "PERFORMANCE_DEGRADATION"


class EventSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class OperationalEvent:
    event_id: str
    timestamp: str
    source: str
    category: EventCategory
    severity: EventSeverity
    environment: Optional[str] = None
    service: Optional[str] = None
    repository: Optional[str] = None
    deployment_version: Optional[str] = None
    evidence_ref: Optional[str] = None
    correlation_ids: list[str] = field(default_factory=list)
    detail: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        return d

    @staticmethod
    def from_dict(d: dict) -> "OperationalEvent":
        d = dict(d)
        d["category"] = EventCategory(d["category"])
        d["severity"] = EventSeverity(d["severity"])
        return OperationalEvent(**d)


# ---- Part 4: Root Cause Analysis --------------------------------------

class RCAConfidence(str, Enum):
    CONFIRMED = "CONFIRMED"
    HIGH_CONFIDENCE = "HIGH_CONFIDENCE"
    LIKELY = "LIKELY"
    POSSIBLE = "POSSIBLE"
    UNKNOWN = "UNKNOWN"


class RootCauseCategory(str, Enum):
    BAD_DEPLOYMENT = "BAD_DEPLOYMENT"
    APPLICATION_DEFECT = "APPLICATION_DEFECT"
    DEPENDENCY_FAILURE = "DEPENDENCY_FAILURE"
    DEPENDENCY_VERSION_REGRESSION = "DEPENDENCY_VERSION_REGRESSION"
    INFRASTRUCTURE_MISCONFIGURATION = "INFRASTRUCTURE_MISCONFIGURATION"
    CAPACITY_EXHAUSTION = "CAPACITY_EXHAUSTION"
    DATABASE_FAILURE = "DATABASE_FAILURE"
    NETWORK_FAILURE = "NETWORK_FAILURE"
    DNS_FAILURE = "DNS_FAILURE"
    CERTIFICATE_FAILURE = "CERTIFICATE_FAILURE"
    SECURITY_POLICY_FAILURE = "SECURITY_POLICY_FAILURE"
    EXTERNAL_PROVIDER_OUTAGE = "EXTERNAL_PROVIDER_OUTAGE"
    UNKNOWN = "UNKNOWN"


@dataclass
class Diagnosis:
    hypothesis: RootCauseCategory
    confidence: RCAConfidence
    supporting_evidence: list[str] = field(default_factory=list)
    contradicting_evidence: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    recommended_next_diagnostic_action: str = ""

    @property
    def safe_to_auto_remediate(self) -> bool:
        """Part 4: 'Insufficient evidence - do not remediate automatically.'
        Only CONFIRMED/HIGH_CONFIDENCE/LIKELY diagnoses are ever eligible
        for automated remediation; POSSIBLE/UNKNOWN never are."""
        return self.confidence in (RCAConfidence.CONFIRMED, RCAConfidence.HIGH_CONFIDENCE,
                                    RCAConfidence.LIKELY)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["hypothesis"] = self.hypothesis.value
        d["confidence"] = self.confidence.value
        return d


# ---- Part 3: Incident Correlation --------------------------------------

@dataclass
class Incident:
    incident_id: str
    fingerprint: str
    event_ids: list[str]
    service: Optional[str]
    environment: Optional[str]
    deployment_version: Optional[str]
    confidence: float
    reasoning: str
    created_at: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        return asdict(self)


# ---- Part 6: Remediation Decision Engine -------------------------------

class RemediationCategory(str, Enum):
    READ_ONLY = "READ_ONLY"
    SAFE_AUTOMATION = "SAFE_AUTOMATION"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"


@dataclass
class RemediationAction:
    action_id: str
    category: RemediationCategory
    policy_action: str  # fixed literal passed to ctx.policy.evaluate() - never an f-string
    description: str
    reversible: bool = True

    def to_dict(self) -> dict:
        d = asdict(self)
        d["category"] = self.category.value
        return d


# ---- Part 10: Human Escalation -----------------------------------------

@dataclass
class Escalation:
    what_happened: str
    current_impact: str
    confirmed_facts: list[str]
    likely_root_cause: str
    confidence: str
    what_aep_tried: list[str]
    what_changed: list[str]
    what_did_not_work: list[str]
    what_human_action_required: str
    recommended_next_step: str

    def to_dict(self) -> dict:
        return asdict(self)

    def to_text(self) -> str:
        lines = [
            f"WHAT HAPPENED: {self.what_happened}",
            f"CURRENT IMPACT: {self.current_impact}",
            "CONFIRMED FACTS: " + ("; ".join(self.confirmed_facts) or "none"),
            f"LIKELY ROOT CAUSE: {self.likely_root_cause}",
            f"CONFIDENCE: {self.confidence}",
            "WHAT AEP TRIED: " + ("; ".join(self.what_aep_tried) or "nothing - insufficient "
                                                                     "evidence to act"),
            "WHAT CHANGED: " + ("; ".join(self.what_changed) or "nothing"),
            "WHAT DID NOT WORK: " + ("; ".join(self.what_did_not_work) or "n/a"),
            f"WHAT HUMAN APPROVAL OR ACTION IS REQUIRED: {self.what_human_action_required}",
            f"RECOMMENDED NEXT STEP: {self.recommended_next_step}",
        ]
        return "\n".join(lines)
