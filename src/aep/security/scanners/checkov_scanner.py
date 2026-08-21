"""Real checkov-backed IaC scanner (Phase 4 Part 1/6).

Verified during Phase 4 investigation: `checkov` (3.3.10, installed via
`pip install --break-system-packages checkov`) scans a Terraform fixture
fully offline - unlike semgrep's registry-config path, checkov's built-in
policy set ships with the package and needs no network access, confirmed
by a real run against a fixture with a public-ACL S3 bucket and an
open-ingress security group (both correctly flagged: CKV2_AWS_6,
CKV_AWS_24, plus several lower-priority checks).

Severity note: open-source checkov does not populate a `severity` field on
most checks (that's a Bridgecrew/Prisma Cloud paid-tier feature) - every
real run observed here returned `severity: null`. `_infer_severity()`
below is therefore an explicit, documented, best-effort heuristic over the
check name/id (keyword match for public exposure / open ingress /
unencrypted / hardcoded-credential / root-privilege patterns -> HIGH,
else MEDIUM) - NOT an authoritative CVSS score. This is called out here
rather than silently presenting a guess as ground truth.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from ..models import (
    AvailabilityResult, ScannerAvailability, ScannerDescriptor, SecurityCategory,
    SecurityFinding, SecurityScanRecord, SecuritySeverity,
)

SCANNER_ID = "checkov"
CATEGORY = SecurityCategory.IAC
SUPPORTED = ["*.tf", "*.yaml (Kubernetes/Helm)", "*.json (CloudFormation)"]
TOOL_NAME = "checkov"
REMEDIATION_SUPPORTED = True

_HIGH_KEYWORDS = (
    "public", "0.0.0.0", "unencrypted", "encryption", "hardcoded", "credential",
    "privilege", "root", "wildcard", "unrestricted", "world",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _infer_severity(check_name: str) -> SecuritySeverity:
    lowered = (check_name or "").lower()
    if any(kw in lowered for kw in _HIGH_KEYWORDS):
        return SecuritySeverity.HIGH
    return SecuritySeverity.MEDIUM


def check_availability(run_shell) -> AvailabilityResult:
    result = run_shell(["checkov", "--version"], timeout=15)
    if result.get("ok"):
        return AvailabilityResult(ScannerAvailability.AVAILABLE,
                                   "checkov binary present; built-in policy set requires no network")
    return AvailabilityResult(
        ScannerAvailability.UNAVAILABLE,
        "checkov binary not found on PATH (install via "
        "`pip install --break-system-packages checkov`)",
    )


def describe(run_shell) -> ScannerDescriptor:
    return ScannerDescriptor(
        scanner_id=SCANNER_ID, capability="security.iac_scan", category=CATEGORY,
        supported=SUPPORTED, tool=TOOL_NAME, findings_schema="SecurityFinding (security/models.py)",
        severity_levels=[s.value for s in SecuritySeverity],
        evidence_kind="resource address + failed check id", remediation_supported=REMEDIATION_SUPPORTED,
        availability=check_availability(run_shell),
    )


def _version(run_shell) -> str:
    result = run_shell(["checkov", "--version"], timeout=15)
    return (result.get("stdout") or "").strip() or "unknown"


def scan(project_root: str, run_shell) -> SecurityScanRecord:
    scanned_at = _now()
    availability = check_availability(run_shell)
    if availability.status != ScannerAvailability.AVAILABLE:
        return SecurityScanRecord(
            scanner=SCANNER_ID, scanner_version="unknown", category=CATEGORY, scanned_at=scanned_at,
            target=project_root, availability=availability.status, exit_code=0, finding_count=0,
            findings=[], note=availability.reason,
        )

    tool_version = _version(run_shell)
    result = run_shell(
        ["checkov", "-d", ".", "--framework", "terraform", "-o", "json", "--compact", "--quiet"],
        cwd=project_root, timeout=120,
    )
    try:
        data = json.loads(result.get("stdout") or "{}")
    except json.JSONDecodeError:
        # checkov exits 1 both when it finds failed checks (expected,
        # not an error) AND on a real internal error - only "stdout wasn't
        # JSON at all" is treated as a genuine scanner failure here.
        return SecurityScanRecord(
            scanner=SCANNER_ID, scanner_version=tool_version, category=CATEGORY,
            scanned_at=scanned_at, target=project_root, availability=ScannerAvailability.AVAILABLE,
            exit_code=result.get("exit_code", -1), finding_count=0, findings=[], parse_error=True,
            note=f"checkov did not return valid JSON: {(result.get('stderr') or '')[:300]}",
        )
    if isinstance(data, list):
        # checkov emits a JSON array (one object per framework) when more
        # than one framework's checks ran; a single `--framework terraform`
        # run returns one object directly, but this stays correct either way.
        reports = data
    else:
        reports = [data]

    findings: list[SecurityFinding] = []
    for report in reports:
        for fc in (report.get("results", {}) or {}).get("failed_checks", []) or []:
            line_range = fc.get("file_line_range") or [None, None]
            # checkov reports file_path relative to `-d .` with a leading
            # "/" (e.g. "/main.tf") - strip it once and reuse everywhere,
            # so the fingerprint and the path handed to the filesystem
            # tool (which requires a project-root-relative path) agree.
            rel_path = (fc.get("file_path") or "").lstrip("/")
            findings.append(SecurityFinding(
                id=f"checkov:{fc.get('check_id')}:{rel_path}:{fc.get('resource')}",
                scanner=SCANNER_ID, category=CATEGORY,
                severity=_infer_severity(fc.get("check_name", "")), confidence="medium",
                file=rel_path, line=line_range[0],
                resource=fc.get("resource"),
                description=fc.get("check_name", "IaC misconfiguration"),
                evidence=f"resource {fc.get('resource')} failed {fc.get('check_id')} "
                          f"(lines {line_range[0]}-{line_range[1]})",
                remediation=fc.get("guideline") or "see checkov documentation for "
                                                    f"{fc.get('check_id')}",
                rule_id=fc.get("check_id"), detected_at=scanned_at,
            ))

    return SecurityScanRecord(
        scanner=SCANNER_ID, scanner_version=tool_version, category=CATEGORY, scanned_at=scanned_at,
        target=project_root, availability=ScannerAvailability.AVAILABLE,
        exit_code=result.get("exit_code", 0), finding_count=len(findings), findings=findings,
        raw_output_ref=f"checkov summary: {reports[0].get('summary') if reports else {}}",
    )
