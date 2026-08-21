"""Real gitleaks-backed secret scanner (Phase 4 Part 1/4).

Genuinely verified during Phase 4 investigation: `gitleaks` (8.16.0) is
installable via `apt-get install -y gitleaks` (Ubuntu universe repo) in
this sandbox and produces real findings against a fixture AWS-credential
pattern - see ARCHITECTURE.md's Phase 4 addendum for the exact transcript.

gitleaks' own exit-code convention is unusual and easy to misread as
failure: 0 = no leaks found, 1 = leaks found (this is the *expected*,
successful-scan-with-results case, not an error), anything else = a real
tool error. `scan()` below treats {0, 1} as "the scan ran"; only other
exit codes (or a non-JSON stdout) are treated as a genuine scanner error.

Hard rule (see security/models.py's module docstring): the raw secret
value ("Secret"/"Match" in gitleaks' JSON) is read here ONLY to compute a
redacted preview - it is never copied into a `SecurityFinding` field, an
`Evidence.summary`, or any other string that becomes durable state or gets
printed. `remediation.py`'s secret-remediation code re-derives the raw
value itself (from the source file + line/column, never from this
scanner's output) only when it actually needs to perform a text
replacement, and never logs it either.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from ..models import (
    AvailabilityResult, ScannerAvailability, ScannerDescriptor, SecurityCategory,
    SecurityFinding, SecurityScanRecord, SecuritySeverity,
)

SCANNER_ID = "gitleaks"
CATEGORY = SecurityCategory.SECRET
SUPPORTED = ["*"]  # gitleaks scans file content regardless of language
TOOL_NAME = "gitleaks"
REMEDIATION_SUPPORTED = True

# gitleaks doesn't emit a severity itself - every real secret leak is
# treated as HIGH by default (a live credential in source control is
# always at least a HIGH-severity exposure), matching Part 8's "secret
# detected -> block commit" policy regardless of which specific rule
# matched.
_DEFAULT_SEVERITY = SecuritySeverity.HIGH


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def check_availability(run_shell) -> AvailabilityResult:
    result = run_shell(["gitleaks", "version"], timeout=10)
    if result.get("ok"):
        return AvailabilityResult(ScannerAvailability.AVAILABLE, "gitleaks binary responds to --version")
    return AvailabilityResult(
        ScannerAvailability.UNAVAILABLE,
        "gitleaks binary not found on PATH (install via `apt-get install -y gitleaks` or "
        "https://github.com/gitleaks/gitleaks)",
    )


def describe(run_shell) -> ScannerDescriptor:
    return ScannerDescriptor(
        scanner_id=SCANNER_ID, capability="security.secret_scan", category=CATEGORY,
        supported=SUPPORTED, tool=TOOL_NAME, findings_schema="SecurityFinding (security/models.py)",
        severity_levels=[s.value for s in SecuritySeverity], evidence_kind="redacted match preview",
        remediation_supported=REMEDIATION_SUPPORTED, availability=check_availability(run_shell),
    )


def _redacted_preview(raw_secret: str) -> str:
    # Same shape as redaction.SecretMatch.snippet - first 4 chars only,
    # never the full value, even in a "just for evidence" string. Below 4
    # chars there is nothing safe to preview at all.
    if not raw_secret or len(raw_secret) <= 4:
        return "…redacted…"
    return raw_secret[:4] + "…redacted…"


def _version(run_shell) -> str:
    result = run_shell(["gitleaks", "version"], timeout=10)
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
        ["gitleaks", "detect", "--source", ".", "--no-git", "--no-banner", "-f", "json", "-r",
         "aep_gitleaks_report.json"],
        cwd=project_root, timeout=120,
    )
    # gitleaks writes findings to the `-r` report file, not stdout - read it
    # back through the same run_shell wrapper (`cat`) would add another
    # allowlisted binary for no reason; reading the file directly here is
    # fine because this module (like every scanner adapter) already runs
    # in-process, only the scanner *subprocess itself* is capability-gated.
    report_path = os.path.join(project_root, "aep_gitleaks_report.json")
    raw_findings = []
    report_parse_error = False
    if os.path.exists(report_path):
        try:
            with open(report_path) as f:
                raw_findings = json.load(f) or []
        except json.JSONDecodeError:
            # BUG: previously swallowed to `raw_findings = []`, which reads
            # identically to a real clean scan even though gitleaks' own
            # exit code (checked below) may say leaks WERE found - see
            # BUGFIX.md. Trust P0.3: never let malformed output become PASS.
            report_parse_error = True
        finally:
            os.remove(report_path)

    if report_parse_error:
        return SecurityScanRecord(
            scanner=SCANNER_ID, scanner_version=tool_version, category=CATEGORY,
            scanned_at=scanned_at, target=project_root, availability=ScannerAvailability.AVAILABLE,
            exit_code=result.get("exit_code", -1), finding_count=0, findings=[], parse_error=True,
            note="gitleaks report file was not valid JSON - result unknown",
        )

    if result.get("exit_code") not in (0, 1):
        return SecurityScanRecord(
            scanner=SCANNER_ID, scanner_version=tool_version, category=CATEGORY,
            scanned_at=scanned_at, target=project_root, availability=ScannerAvailability.AVAILABLE,
            exit_code=result.get("exit_code", -1), finding_count=0, findings=[],
            note=f"gitleaks exited with an unexpected code (not 0=clean or 1=leaks-found): "
                 f"{(result.get('stderr') or '')[:300]}",
        )

    findings: list[SecurityFinding] = []
    for raw in raw_findings:
        raw_secret = raw.get("Secret") or raw.get("Match") or ""
        findings.append(SecurityFinding(
            id=f"gitleaks:{raw.get('RuleID', 'unknown')}:{raw.get('File', '')}:"
               f"{raw.get('StartLine', 0)}",
            scanner=SCANNER_ID, category=CATEGORY, severity=_DEFAULT_SEVERITY, confidence="high",
            file=raw.get("File"), line=raw.get("StartLine"), resource=None,
            description=f"likely {raw.get('Description', 'secret')} credential matched by "
                        f"gitleaks rule '{raw.get('RuleID', 'unknown')}'",
            evidence=f"redacted match: {_redacted_preview(raw_secret)} (entropy="
                      f"{raw.get('Entropy', 0):.2f})",
            remediation="move this value to an environment variable or secret manager reference "
                        "and remove the literal from source (see security/secret_manager.py)",
            rule_id=raw.get("RuleID"), detected_at=scanned_at,
        ))

    return SecurityScanRecord(
        scanner=SCANNER_ID, scanner_version=tool_version, category=CATEGORY, scanned_at=scanned_at,
        target=project_root, availability=ScannerAvailability.AVAILABLE,
        exit_code=result.get("exit_code", 0), finding_count=len(findings), findings=findings,
        raw_output_ref=f"{len(raw_findings)} raw gitleaks finding(s); values redacted before "
                       f"normalization",
    )
