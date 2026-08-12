"""Real checkov-backed Kubernetes manifest scanner (Phase 5 Part 3).

Conforms to the EXACT same adapter contract as Phase 4's
`security/scanners/*` (`check_availability(run_shell)` / `describe(run_shell)`
/ `scan(project_root, run_shell)` returning a `SecurityScanRecord` of
`SecurityFinding`s) — Part 3's "integrate with the existing
SecurityScanner framework rather than creating a duplicate scanner
architecture" is satisfied structurally: this module imports the Phase 4
model and is driven by the Phase 4 `run_security_scan()` runner via its
existing `scanners=` injection point. Nothing here re-implements scanning
infrastructure.

Verified against a deliberately-insecure fixture during Phase 5
investigation: checkov's built-in Kubernetes policy set (offline, no
network) returned 29 real failed checks covering every category Part 3
asks for — privileged containers (CKV_K8S_16), hostNetwork (CKV_K8S_19),
hostPID (CKV_K8S_17), added capabilities (CKV_K8S_25/37), root execution
(CKV_K8S_23), missing CPU/memory requests+limits (CKV_K8S_10/11/12/13),
missing probes (CKV_K8S_8/9), wildcard RBAC (CKV_K8S_49), and
service-account token mounting (CKV_K8S_38).

Severity: open-source checkov leaves `severity` null (a paid-tier field),
exactly as Phase 4 documented for Terraform. `_infer_severity()` here is a
rule-id-keyed table for the checks Part 3 names explicitly — a documented,
auditable mapping rather than the keyword heuristic Phase 4's Terraform
adapter had to fall back on, because the Kubernetes check ids are a small
known set.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from ...security.models import (
    AvailabilityResult, ScannerAvailability, ScannerDescriptor, SecurityCategory,
    SecurityFinding, SecurityScanRecord, SecuritySeverity,
)

SCANNER_ID = "checkov-kubernetes"
CATEGORY = SecurityCategory.KUBERNETES
SUPPORTED = ["*.yaml (Kubernetes manifests)", "*.yml", "*.json"]
TOOL_NAME = "checkov"
REMEDIATION_SUPPORTED = True

# Explicit severity table for the checks Part 3 names. Anything not listed
# falls back to MEDIUM - deliberately not "guess from the check name",
# because a wrong HIGH here directly inflates the risk score and the
# security-readiness gate.
_SEVERITY_BY_RULE = {
    # Container escape / host namespace access - the highest-impact set.
    "CKV_K8S_16": SecuritySeverity.CRITICAL,   # privileged container
    "CKV_K8S_17": SecuritySeverity.HIGH,       # hostPID
    "CKV_K8S_18": SecuritySeverity.HIGH,       # hostIPC
    "CKV_K8S_19": SecuritySeverity.HIGH,       # hostNetwork
    "CKV_K8S_20": SecuritySeverity.HIGH,       # allowPrivilegeEscalation
    "CKV_K8S_21": SecuritySeverity.LOW,        # default namespace
    "CKV_K8S_22": SecuritySeverity.MEDIUM,     # read-only root filesystem
    "CKV_K8S_23": SecuritySeverity.HIGH,       # root containers
    "CKV_K8S_25": SecuritySeverity.HIGH,       # added capabilities
    "CKV_K8S_27": SecuritySeverity.HIGH,       # docker socket mount
    "CKV_K8S_28": SecuritySeverity.MEDIUM,     # NET_RAW capability
    "CKV_K8S_37": SecuritySeverity.HIGH,       # capabilities not dropped
    "CKV_K8S_38": SecuritySeverity.MEDIUM,     # service account token
    # hostPath volumes
    "CKV_K8S_30": SecuritySeverity.MEDIUM,     # securityContext missing
    "CKV_K8S_31": SecuritySeverity.MEDIUM,     # seccomp profile
    # Resource exhaustion / availability
    "CKV_K8S_10": SecuritySeverity.MEDIUM,     # CPU requests
    "CKV_K8S_11": SecuritySeverity.MEDIUM,     # CPU limits
    "CKV_K8S_12": SecuritySeverity.MEDIUM,     # memory requests
    "CKV_K8S_13": SecuritySeverity.MEDIUM,     # memory limits
    "CKV_K8S_8": SecuritySeverity.LOW,         # liveness probe
    "CKV_K8S_9": SecuritySeverity.LOW,         # readiness probe
    # Image hygiene
    "CKV_K8S_14": SecuritySeverity.MEDIUM,     # image tag :latest
    "CKV_K8S_15": SecuritySeverity.LOW,        # image pull policy
    "CKV_K8S_43": SecuritySeverity.LOW,        # image digest
    # RBAC
    "CKV_K8S_49": SecuritySeverity.HIGH,       # wildcard in Roles/ClusterRoles
    "CKV_K8S_155": SecuritySeverity.HIGH,      # admission webhook control
    "CKV_K8S_156": SecuritySeverity.HIGH,      # CSR approval
    "CKV_K8S_157": SecuritySeverity.HIGH,      # rolebinding creation
    "CKV_K8S_158": SecuritySeverity.CRITICAL,  # role escalation
}

# Which findings this platform is able to fix mechanically and safely -
# consumed by `infra/remediation.py`. Anything not in this set is
# escalated, never guessed at (Part 9: "Do NOT automatically fix ambiguous
# IAM/network policies").
AUTO_REMEDIABLE_RULES = {
    "CKV_K8S_16", "CKV_K8S_17", "CKV_K8S_19", "CKV_K8S_20", "CKV_K8S_23",
    "CKV_K8S_37", "CKV_K8S_10", "CKV_K8S_11", "CKV_K8S_12", "CKV_K8S_13",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _infer_severity(rule_id: str) -> SecuritySeverity:
    return _SEVERITY_BY_RULE.get(rule_id, SecuritySeverity.MEDIUM)


def check_availability(run_shell) -> AvailabilityResult:
    result = run_shell(["checkov", "--version"], timeout=15)
    if result.get("ok"):
        return AvailabilityResult(
            ScannerAvailability.AVAILABLE,
            "checkov binary present; the Kubernetes policy set is bundled and needs no network "
            "and no live cluster",
        )
    return AvailabilityResult(
        ScannerAvailability.UNAVAILABLE,
        "checkov binary not found on PATH (install via "
        "`pip install --break-system-packages checkov`)",
    )


def describe(run_shell) -> ScannerDescriptor:
    return ScannerDescriptor(
        scanner_id=SCANNER_ID, capability="infra.kubernetes_scan", category=CATEGORY,
        supported=SUPPORTED, tool=TOOL_NAME,
        findings_schema="SecurityFinding (security/models.py) - Phase 4 model reused, not forked",
        severity_levels=[s.value for s in SecuritySeverity],
        evidence_kind="kubernetes resource id + failed check id",
        remediation_supported=REMEDIATION_SUPPORTED, availability=check_availability(run_shell),
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
        ["checkov", "-d", ".", "--framework", "kubernetes", "-o", "json", "--compact", "--quiet"],
        cwd=project_root, timeout=180,
    )
    try:
        data = json.loads(result.get("stdout") or "{}")
    except json.JSONDecodeError:
        return SecurityScanRecord(
            scanner=SCANNER_ID, scanner_version=tool_version, category=CATEGORY,
            scanned_at=scanned_at, target=project_root, availability=ScannerAvailability.AVAILABLE,
            exit_code=result.get("exit_code", -1), finding_count=0, findings=[],
            note=f"checkov did not return valid JSON: {(result.get('stderr') or '')[:300]}",
        )
    reports = data if isinstance(data, list) else [data]

    # A repo with no Kubernetes manifests at all is NOT_APPLICABLE, not
    # "PASS" - reporting a clean bill of health for a category that had
    # nothing to check is exactly the kind of false assurance Part 3's
    # "do not fake results" rule exists to prevent.
    total_resources = sum((r.get("summary", {}) or {}).get("resource_count", 0) for r in reports)
    if total_resources == 0:
        return SecurityScanRecord(
            scanner=SCANNER_ID, scanner_version=tool_version, category=CATEGORY,
            scanned_at=scanned_at, target=project_root,
            availability=ScannerAvailability.NOT_APPLICABLE, exit_code=result.get("exit_code", 0),
            finding_count=0, findings=[],
            note="no Kubernetes resources found in this repository - nothing to scan (this is "
                 "NOT_APPLICABLE, deliberately not reported as a passing scan)",
        )

    findings: list[SecurityFinding] = []
    for report in reports:
        for fc in (report.get("results", {}) or {}).get("failed_checks", []) or []:
            rule_id = fc.get("check_id", "")
            line_range = fc.get("file_line_range") or [None, None]
            rel_path = (fc.get("file_path") or "").lstrip("/")
            resource = fc.get("resource")
            findings.append(SecurityFinding(
                id=f"checkov-k8s:{rule_id}:{rel_path}:{resource}",
                scanner=SCANNER_ID, category=CATEGORY, severity=_infer_severity(rule_id),
                confidence="high", file=rel_path, line=line_range[0], resource=resource,
                description=fc.get("check_name", "Kubernetes misconfiguration"),
                evidence=f"resource {resource} failed {rule_id} "
                          f"(lines {line_range[0]}-{line_range[1]})",
                remediation=fc.get("guideline")
                             or f"see checkov documentation for {rule_id}"
                             + (" (auto-remediable by this platform)"
                                if rule_id in AUTO_REMEDIABLE_RULES else
                                " (requires human review - not auto-remediated)"),
                rule_id=rule_id, detected_at=scanned_at,
            ))

    return SecurityScanRecord(
        scanner=SCANNER_ID, scanner_version=tool_version, category=CATEGORY, scanned_at=scanned_at,
        target=project_root, availability=ScannerAvailability.AVAILABLE,
        exit_code=result.get("exit_code", 0), finding_count=len(findings), findings=findings,
        raw_output_ref=f"checkov kubernetes summary: "
                       f"{reports[0].get('summary') if reports else {}}",
    )
