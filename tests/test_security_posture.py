"""Security score / posture (Phase 4 Part 10/13). Deterministic and
offline: built from constructed SecurityScanRecord/ScanRecord fixtures,
not a live scan - live wiring is exercised separately by
tests/test_cli_security_status.py and by manually running
`aep security-status` (see ARCHITECTURE.md's Phase 4 addendum)."""
from __future__ import annotations

from aep.dependency.models import Ecosystem
from aep.dependency.models import ScanRecord as DependencyScanRecord
from aep.security.models import (
    ScannerAvailability, SecurityCategory, SecurityFinding, SecurityScanRecord, SecuritySeverity,
)
from aep.security.posture import NOT_READY, READY, compute_security_posture
from aep.security.suppressions import Suppression


def _record(category, availability=ScannerAvailability.AVAILABLE, findings=None, note=""):
    findings = findings or []
    return SecurityScanRecord(
        scanner=category.value, scanner_version="1.0", category=category,
        scanned_at="2026-01-01T00:00:00+00:00", target="/tmp/x", availability=availability,
        exit_code=0, finding_count=len(findings), findings=findings, note=note,
    )


def _finding(category, severity, fid="f1"):
    return SecurityFinding(id=fid, scanner=category.value, category=category, severity=severity,
                            confidence="high", file="x", line=1, resource=None, description="d",
                            evidence="e", remediation="r")


def test_all_clean_categories_report_ready():
    records = [
        _record(SecurityCategory.SECRET), _record(SecurityCategory.SAST), _record(SecurityCategory.IAC),
    ]
    posture = compute_security_posture(records, dependency_records=[])
    names_status = {c.name: c.status for c in posture.categories}
    assert names_status["Secrets"] == "PASS"
    assert names_status["SAST"] == "PASS"
    assert names_status["IaC"] == "PASS"


def test_matches_the_spec_example_shape_exactly():
    # Reproduces the Phase 4 spec's own Part 10 example: Secrets PASS,
    # SAST PASS, Dependencies PASS, IaC 2 HIGH, Containers 1 MEDIUM.
    iac_findings = [_finding(SecurityCategory.IAC, SecuritySeverity.HIGH, "i1"),
                     _finding(SecurityCategory.IAC, SecuritySeverity.HIGH, "i2")]
    container_findings = [_finding(SecurityCategory.CONTAINER, SecuritySeverity.MEDIUM, "c1")]
    records = [
        _record(SecurityCategory.SECRET), _record(SecurityCategory.SAST),
        _record(SecurityCategory.IAC, findings=iac_findings),
        _record(SecurityCategory.CONTAINER, findings=container_findings),
    ]
    dep_records = [DependencyScanRecord(scanner="pip-audit", scanner_version="1", scanned_at="t",
                                          manifest_path="requirements.txt", ecosystem=Ecosystem.PYTHON,
                                          exit_code=0, finding_count=0, findings=[])]
    posture = compute_security_posture(records, dependency_records=dep_records)
    names_status = {c.name: c.status for c in posture.categories}
    assert names_status == {"Secrets": "PASS", "SAST": "PASS", "Dependencies": "PASS",
                              "IaC": "2 HIGH", "Containers": "1 MEDIUM"}
    text = posture.render_text()
    assert "SECURITY POSTURE" in text
    assert "IaC" in text and "2 HIGH" in text


def test_blocked_category_never_reads_as_pass():
    records = [
        _record(SecurityCategory.SECRET), _record(SecurityCategory.SAST), _record(SecurityCategory.IAC),
        _record(SecurityCategory.CONTAINER, availability=ScannerAvailability.BLOCKED,
                note="trivy blocked in this sandbox"),
    ]
    posture = compute_security_posture(records, dependency_records=[])
    containers = next(c for c in posture.categories if c.name == "Containers")
    assert containers.status == "BLOCKED"
    assert containers.status != "PASS"
    assert posture.readiness == NOT_READY
    assert any("Containers" in e for e in posture.explanation)


def test_unsuppressed_critical_blocks_readiness():
    findings = [_finding(SecurityCategory.SECRET, SecuritySeverity.CRITICAL, "f1")]
    records = [_record(SecurityCategory.SECRET, findings=findings), _record(SecurityCategory.SAST),
               _record(SecurityCategory.IAC)]
    posture = compute_security_posture(records, dependency_records=[])
    assert posture.readiness == NOT_READY


def test_suppressed_finding_does_not_block_readiness_but_is_still_counted():
    findings = [_finding(SecurityCategory.SECRET, SecuritySeverity.HIGH, "f1")]
    records = [_record(SecurityCategory.SECRET, findings=findings), _record(SecurityCategory.SAST),
               _record(SecurityCategory.IAC)]
    suppression = Suppression(finding_id="f1", justification="reviewed, false positive",
                                reviewer="kparmar", evidence="manual review", created_at="t",
                                expiry=None)
    posture = compute_security_posture(records, dependency_records=[], suppressions=[suppression])
    secrets = next(c for c in posture.categories if c.name == "Secrets")
    assert secrets.status == "PASS"
    assert secrets.suppressed_finding_count == 1
    # Suppression must be visible in the posture, not silently invisible.
    assert "suppressed" in secrets.detail


def test_medium_and_low_findings_are_tracked_but_do_not_block_readiness():
    findings = [_finding(SecurityCategory.IAC, SecuritySeverity.MEDIUM, "f1")]
    records = [_record(SecurityCategory.SECRET), _record(SecurityCategory.SAST),
               _record(SecurityCategory.IAC, findings=findings)]
    posture = compute_security_posture(records, dependency_records=[])
    assert posture.readiness == READY
    iac = next(c for c in posture.categories if c.name == "IaC")
    assert iac.status == "1 MEDIUM"
