"""Real semgrep-backed SAST scanner (Phase 4 Part 1/5).

Two real environment gotchas found during Phase 4 investigation, both
network-related (same egress-proxy-blocks-external-services pattern
documented for api.github.com/proxy.golang.org/registry-1.docker.io in
earlier phases) and both fixed with explicit flags rather than by faking
output:

1. `--config auto` (or any `p/...` registry shorthand) needs
   semgrep.dev/c.semgrep.dev, which this sandbox cannot reach (`curl`
   returns `000` for both). Fixed by always invoking semgrep against the
   LOCAL rule file bundled at `security/rules/semgrep_rules.yaml` - see
   that file's docstring for the exact ruleset and its CWE coverage.

2. Even with a local `--config`, semgrep's *default-on* version check
   (`--enable-version-check`, on unless disabled) tries to reach a
   semgrep.dev server on every invocation and hangs until that network
   call gives up - observed adding ~90+ seconds of pure wall-clock wait
   (`real` vastly exceeds `user`+`sys` time) despite `--metrics=off`
   already being passed, which only disables a *different* network call.
   Fixed by always passing `--disable-version-check` explicitly; verified
   this brings a real scan down from ~99s to ~2s in this sandbox.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ..models import (
    AvailabilityResult, ScannerAvailability, ScannerDescriptor, SecurityCategory,
    SecurityFinding, SecurityScanRecord, SecuritySeverity,
)

SCANNER_ID = "semgrep"
CATEGORY = SecurityCategory.SAST
SUPPORTED = ["*.py"]  # the bundled ruleset only has python rules today
TOOL_NAME = "semgrep"
REMEDIATION_SUPPORTED = True

RULES_PATH = str(Path(__file__).resolve().parent.parent / "rules" / "semgrep_rules.yaml")

_SEVERITY_MAP = {
    "critical": SecuritySeverity.CRITICAL, "high": SecuritySeverity.HIGH,
    "medium": SecuritySeverity.MEDIUM, "low": SecuritySeverity.LOW, "info": SecuritySeverity.INFO,
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def check_availability(run_shell) -> AvailabilityResult:
    result = run_shell(["semgrep", "--version", "--disable-version-check"], timeout=15)
    if not result.get("ok"):
        return AvailabilityResult(
            ScannerAvailability.UNAVAILABLE,
            "semgrep binary not found on PATH (install via "
            "`pip install --break-system-packages semgrep`)",
        )
    if not Path(RULES_PATH).exists():
        return AvailabilityResult(
            ScannerAvailability.UNAVAILABLE,
            f"bundled local ruleset missing at {RULES_PATH}",
        )
    return AvailabilityResult(ScannerAvailability.AVAILABLE,
                               "semgrep binary present and local ruleset found "
                               "(semgrep.dev registry is unreachable in this sandbox, so only the "
                               "bundled local rule file is used - see this module's docstring)")


def describe(run_shell) -> ScannerDescriptor:
    return ScannerDescriptor(
        scanner_id=SCANNER_ID, capability="security.sast_scan", category=CATEGORY,
        supported=SUPPORTED, tool=TOOL_NAME, findings_schema="SecurityFinding (security/models.py)",
        severity_levels=[s.value for s in SecuritySeverity], evidence_kind="matched code snippet reference",
        remediation_supported=REMEDIATION_SUPPORTED, availability=check_availability(run_shell),
    )


def _version(run_shell) -> str:
    result = run_shell(["semgrep", "--version", "--disable-version-check"], timeout=15)
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
        ["semgrep", "--config", RULES_PATH, "--json", "--metrics=off",
         "--disable-version-check", "--quiet", "."],
        cwd=project_root, timeout=90,
    )
    try:
        data = json.loads(result.get("stdout") or "{}")
    except json.JSONDecodeError:
        return SecurityScanRecord(
            scanner=SCANNER_ID, scanner_version=tool_version, category=CATEGORY,
            scanned_at=scanned_at, target=project_root, availability=ScannerAvailability.AVAILABLE,
            exit_code=result.get("exit_code", -1), finding_count=0, findings=[],
            note=f"semgrep did not return valid JSON: {(result.get('stderr') or '')[:300]}",
        )

    findings: list[SecurityFinding] = []
    for r in data.get("results", []):
        meta = (r.get("extra", {}) or {}).get("metadata", {}) or {}
        rule_id = r.get("check_id", "unknown").rsplit(".", 1)[-1]
        line = r.get("start", {}).get("line")
        file_path = r.get("path")
        sev_key = str(meta.get("aep_severity", "medium")).lower()
        code_snippet = (r.get("extra", {}) or {}).get("lines", "")[:200]
        findings.append(SecurityFinding(
            id=f"semgrep:{rule_id}:{file_path}:{line}",
            scanner=SCANNER_ID, category=CATEGORY,
            severity=_SEVERITY_MAP.get(sev_key, SecuritySeverity.MEDIUM), confidence="high",
            file=file_path, line=line, resource=None,
            description=(r.get("extra", {}) or {}).get("message", "semgrep finding")[:400],
            evidence=f"matched: {code_snippet}",
            remediation=f"see rule '{rule_id}' (CWE {meta.get('cwe', 'n/a')}) for the safe pattern",
            rule_id=rule_id, cwe=meta.get("cwe"), detected_at=scanned_at,
        ))

    return SecurityScanRecord(
        scanner=SCANNER_ID, scanner_version=tool_version, category=CATEGORY, scanned_at=scanned_at,
        target=project_root, availability=ScannerAvailability.AVAILABLE,
        exit_code=result.get("exit_code", 0), finding_count=len(findings), findings=findings,
        raw_output_ref=f"{len(data.get('errors', []))} semgrep-internal error(s) alongside "
                       f"{len(findings)} finding(s)",
    )
