"""Plain data model for dependency/CVE intelligence.

These are used as structured evidence payloads (serialized into
`Evidence.summary` / `Task.payload` as plain dicts via `to_dict()`) and as
return values of the scanner/inventory/remediation functions in this
package. They are never stored directly by StateStore - Task/Evidence
(src/aep/models.py) remain the only durable schema, untouched by Phase 3.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional


class Ecosystem(str, Enum):
    PYTHON = "python"
    NODE = "node"
    GO = "go"
    CONTAINER = "container"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class DependencyManifest:
    ecosystem: Ecosystem
    path: str  # relative to project_root
    format: str  # e.g. "requirements.txt", "package.json", "go.mod", "Dockerfile"


@dataclass
class VulnerabilityFinding:
    id: str  # canonical scanner id, e.g. PYSEC-2021-142 / npm advisory source id
    aliases: list[str]  # e.g. ["GHSA-8q59-q68h-6hv4", "CVE-2020-14343"]
    ecosystem: Ecosystem
    manifest_path: str
    package: str
    installed_version: str
    vulnerable_range: str
    fixed_versions: list[str]  # empty = no fixed version published yet
    severity: Severity
    summary: str
    source: str  # "pip-audit" | "npm-audit" | ...
    scanned_at: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["ecosystem"] = self.ecosystem.value
        d["severity"] = self.severity.value
        return d


@dataclass
class RemediationPlan:
    package: str
    ecosystem: Ecosystem
    manifest_path: str
    from_version: str
    to_version: Optional[str]
    finding_ids: list[str]
    safe: bool
    major_version_bump: bool
    reason: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["ecosystem"] = self.ecosystem.value
        return d


@dataclass
class ScanRecord:
    """Durable, machine-verifiable evidence of one real scanner invocation -
    Phase 3 Part B's evidence requirement (scanner/timestamp/finding)."""
    scanner: str
    scanner_version: str
    scanned_at: str
    manifest_path: str
    ecosystem: Ecosystem
    exit_code: int
    finding_count: int
    findings: list[VulnerabilityFinding] = field(default_factory=list)
    raw_output_ref: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "scanner": self.scanner, "scanner_version": self.scanner_version,
            "scanned_at": self.scanned_at, "manifest_path": self.manifest_path,
            "ecosystem": self.ecosystem.value, "exit_code": self.exit_code,
            "finding_count": self.finding_count,
            "findings": [f.to_dict() for f in self.findings],
            "raw_output_ref": self.raw_output_ref,
        }
