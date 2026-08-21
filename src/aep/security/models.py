"""Normalized security data model (Phase 4 Part 1/2).

This package is Phase 4's parallel to `dependency/` (Phase 3): plain
dataclasses used as structured evidence payloads and scanner return values,
never stored directly by StateStore. Task/Evidence (`src/aep/models.py`)
remain the only durable schema.

Naming note: `SecurityFinding` here is deliberately richer than Phase 3's
`dependency.models.VulnerabilityFinding` (adds category, confidence,
resource, status, false-positive state, task linkage, verification
evidence) because Part 2 of the Phase 4 spec asks for all of those
explicitly, across four scanner categories rather than one. It is a
*sibling* model, not a replacement - dependency/CVE findings continue to
use VulnerabilityFinding unmodified.

Hard rule enforced by every scanner adapter in `security/scanners/`, not
just documented here: no field on `SecurityFinding` may ever contain a raw
secret value. `evidence`/`description` carry only redacted previews (the
same `raw[:4] + "...redacted..."` shape `redaction.SecretMatch` already
uses) - see `security/scanners/gitleaks_scanner.py`.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional


class SecurityCategory(str, Enum):
    SECRET = "secret"
    SAST = "sast"
    IAC = "iac"
    CONTAINER = "container"
    # Phase 5 additions. These are ADDITIVE only: Phase 4's `ALL_SCANNERS`
    # and `discover_scanners()` still cover exactly the original four
    # categories, and Phase 5's scanners live in their own
    # `infra/scanners/` registry passed explicitly to the existing
    # `run_security_scan(..., scanners=...)` injection point - so no Phase
    # 4 behavior or test changes. Terraform stays under IAC (Phase 4's
    # checkov adapter already owns it); Kubernetes and Helm are separate
    # because their scanners, availability, and remediation shapes are
    # genuinely different, and collapsing them into IAC would hide a
    # BLOCKED Helm scanner behind a passing Terraform one.
    KUBERNETES = "kubernetes"
    HELM = "helm"


class SecuritySeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Explicit rank rather than relying on declaration order staying stable -
# used by posture/policy code that needs "is this at least HIGH" logic.
_SEVERITY_RANK = {
    SecuritySeverity.CRITICAL: 4,
    SecuritySeverity.HIGH: 3,
    SecuritySeverity.MEDIUM: 2,
    SecuritySeverity.LOW: 1,
    SecuritySeverity.INFO: 0,
}


def severity_at_least(severity: SecuritySeverity, floor: SecuritySeverity) -> bool:
    return _SEVERITY_RANK[severity] >= _SEVERITY_RANK[floor]


class ScannerAvailability(str, Enum):
    """Part 1's explicit four-state availability contract - distinct from
    (and more granular than) Phase 3's roadmap-level `blocked: true/false`.
    AVAILABLE and NOT_APPLICABLE both mean "nothing stopped the scan from
    running" (the latter because there was nothing for this category to
    scan, e.g. no Dockerfile in the repo); UNAVAILABLE and BLOCKED both
    mean "the scan did not run", split by *why* - UNAVAILABLE is a local
    tooling gap (binary not installed) that a different environment could
    fix by installing it, BLOCKED is an environment/network constraint
    (e.g. an unreachable registry) that installing the same binary would
    not fix in this sandbox."""
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    BLOCKED = "BLOCKED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    REMEDIATION_PLANNED = "REMEDIATION_PLANNED"
    REMEDIATED = "REMEDIATED"
    VERIFIED_RESOLVED = "VERIFIED_RESOLVED"
    SUPPRESSED = "SUPPRESSED"
    ESCALATED = "ESCALATED"


@dataclass
class AvailabilityResult:
    status: ScannerAvailability
    reason: str

    def to_dict(self) -> dict:
        return {"status": self.status.value, "reason": self.reason}


@dataclass
class SecurityFinding:
    """One normalized finding, from whichever of the four scanner
    categories produced it. `id` is a stable fingerprint
    (`scanner:rule:file:line[:resource]`) used for suppression lookups and
    rescan matching - it is deterministic and content-based, never a random
    uuid, so the *same* finding gets the *same* id across scan runs (Part 9
    needs this: a suppression is keyed by fingerprint and must keep
    matching the same finding on every future scan).
    """
    id: str
    scanner: str
    category: SecurityCategory
    severity: SecuritySeverity
    confidence: str  # "high" | "medium" | "low"
    file: Optional[str]
    line: Optional[int]
    resource: Optional[str]
    description: str
    evidence: str
    remediation: str
    rule_id: Optional[str] = None
    cwe: Optional[str] = None
    cve: Optional[str] = None
    ghsa: Optional[str] = None
    status: FindingStatus = FindingStatus.OPEN
    false_positive: bool = False
    task_id: Optional[str] = None
    verification_evidence: Optional[str] = None
    detected_at: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        return d


@dataclass
class ScannerDescriptor:
    """Part 1's required scanner abstraction: every real scanner adapter in
    `security/scanners/` is described by one of these, produced by that
    module's `describe(run_shell)` function. This is intentionally a
    superset of Phase 3's minimal duck-typed scanner shape
    (`dependency/scanners/base.py`) - Part 1 asks for explicit fields
    (scanner id, capability, supported languages/files, command/tool,
    findings schema, severity, evidence, remediation support, availability
    status) that Phase 3's scanners left implicit."""
    scanner_id: str
    capability: str
    category: SecurityCategory
    supported: list[str]
    tool: str
    findings_schema: str  # human-readable pointer, e.g. "SecurityFinding (this module)"
    severity_levels: list[str]
    evidence_kind: str
    remediation_supported: bool
    availability: AvailabilityResult

    def to_dict(self) -> dict:
        return {
            "scanner_id": self.scanner_id, "capability": self.capability,
            "category": self.category.value, "supported": self.supported, "tool": self.tool,
            "findings_schema": self.findings_schema, "severity_levels": self.severity_levels,
            "evidence_kind": self.evidence_kind, "remediation_supported": self.remediation_supported,
            "availability": self.availability.to_dict(),
        }


@dataclass
class SecurityScanRecord:
    """Durable, machine-verifiable evidence of one real scanner invocation
    - Phase 3 Part B's evidence requirement, extended to security scanners
    (Part 3 step 11: 'record evidence')."""
    scanner: str
    scanner_version: str
    category: SecurityCategory
    scanned_at: str
    target: str
    availability: ScannerAvailability
    exit_code: int
    finding_count: int
    findings: list[SecurityFinding] = field(default_factory=list)
    raw_output_ref: Optional[str] = None
    note: str = ""  # why exit_code/finding_count are 0 when availability != AVAILABLE
    # Trust P0.3: a scanner that ran but produced output it could not parse
    # must never be reported as "0 findings" (indistinguishable from a real
    # clean scan). Set this instead of silently defaulting finding_count to
    # 0 - see scan.py::_from_record, which treats this as FAIL, never PASS.
    parse_error: bool = False

    def to_dict(self) -> dict:
        return {
            "scanner": self.scanner, "scanner_version": self.scanner_version,
            "category": self.category.value, "scanned_at": self.scanned_at,
            "target": self.target, "availability": self.availability.value,
            "exit_code": self.exit_code, "finding_count": self.finding_count,
            "findings": [f.to_dict() for f in self.findings],
            "raw_output_ref": self.raw_output_ref, "note": self.note,
            "parse_error": self.parse_error,
        }
