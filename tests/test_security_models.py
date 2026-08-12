"""Normalized security model sanity (Phase 4 Part 2/13)."""
from __future__ import annotations

from aep.security.models import (
    AvailabilityResult, FindingStatus, ScannerAvailability, ScannerDescriptor, SecurityCategory,
    SecurityFinding, SecurityScanRecord, SecuritySeverity, severity_at_least,
)


def test_severity_ranking_is_total_order():
    assert severity_at_least(SecuritySeverity.CRITICAL, SecuritySeverity.HIGH)
    assert severity_at_least(SecuritySeverity.HIGH, SecuritySeverity.HIGH)
    assert not severity_at_least(SecuritySeverity.MEDIUM, SecuritySeverity.HIGH)
    assert severity_at_least(SecuritySeverity.LOW, SecuritySeverity.INFO)
    assert not severity_at_least(SecuritySeverity.INFO, SecuritySeverity.LOW)


def test_availability_has_all_four_required_states():
    # Part 1: AVAILABLE / UNAVAILABLE / BLOCKED / NOT_APPLICABLE, no more, no fewer.
    assert {s.value for s in ScannerAvailability} == {
        "AVAILABLE", "UNAVAILABLE", "BLOCKED", "NOT_APPLICABLE",
    }


def test_finding_to_dict_is_json_serializable_and_never_loses_fields():
    import json

    finding = SecurityFinding(
        id="gitleaks:aws-access-token:config.py:1", scanner="gitleaks", category=SecurityCategory.SECRET,
        severity=SecuritySeverity.HIGH, confidence="high", file="config.py", line=1, resource=None,
        description="likely AWS credential", evidence="redacted match: AKIA…redacted…",
        remediation="move to env var", rule_id="aws-access-token", status=FindingStatus.OPEN,
    )
    d = finding.to_dict()
    assert json.dumps(d)  # fully serializable
    assert d["category"] == "secret"
    assert d["severity"] == "high"
    assert d["status"] == "OPEN"
    # The hard rule from this module's own docstring: nothing here embeds a
    # raw-looking full AWS key (our fixtures always use a 4-char-prefix
    # redacted preview, never the full value).
    assert "AKIAABCD1234EFGH5678" not in json.dumps(d)
    assert "AKIAZZZZ9999QQQQ1111" not in json.dumps(d)


def test_scanner_descriptor_and_scan_record_round_trip_to_dict():
    descriptor = ScannerDescriptor(
        scanner_id="gitleaks", capability="security.secret_scan", category=SecurityCategory.SECRET,
        supported=["*"], tool="gitleaks", findings_schema="SecurityFinding", severity_levels=["high"],
        evidence_kind="redacted preview", remediation_supported=True,
        availability=AvailabilityResult(ScannerAvailability.AVAILABLE, "ok"),
    )
    d = descriptor.to_dict()
    assert d["scanner_id"] == "gitleaks"
    assert d["availability"]["status"] == "AVAILABLE"

    record = SecurityScanRecord(
        scanner="gitleaks", scanner_version="8.16.0", category=SecurityCategory.SECRET,
        scanned_at="2026-01-01T00:00:00+00:00", target="/tmp/x",
        availability=ScannerAvailability.AVAILABLE, exit_code=1, finding_count=0, findings=[],
    )
    rd = record.to_dict()
    assert rd["availability"] == "AVAILABLE"
    assert rd["findings"] == []
