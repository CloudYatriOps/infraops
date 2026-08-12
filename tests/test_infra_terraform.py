"""Terraform deep analysis (Phase 5 Part 2/16). Real python-hcl2 parsing,
fully offline, no `terraform` binary (which is BLOCKED here)."""
from __future__ import annotations

import json
from pathlib import Path

from aep.infra.scanners import terraform_deep_scanner
from aep.security.models import ScannerAvailability, SecurityCategory, SecuritySeverity

FIXTURE = str(Path(__file__).resolve().parent / "fixtures" / "infra" / "terraform")


def _run_shell(args, cwd=None, timeout=60):
    return {"ok": False, "exit_code": -1, "stdout": "", "stderr": "not invoked"}


def test_scanner_is_available_without_any_binary():
    availability = terraform_deep_scanner.check_availability(_run_shell)
    assert availability.status == ScannerAvailability.AVAILABLE
    assert "no network" in availability.reason or "in-process" in availability.reason


def test_detects_hardcoded_provider_credentials():
    record = terraform_deep_scanner.scan(FIXTURE, _run_shell)
    credential_findings = [f for f in record.findings if f.rule_id == "TF_PROVIDER_CREDENTIAL"]
    # Both access_key and secret_key are literals in the fixture.
    assert len(credential_findings) == 2
    assert all(f.severity == SecuritySeverity.CRITICAL for f in credential_findings)
    assert all(f.cwe == "CWE-798" for f in credential_findings)


def test_credential_values_are_never_included_in_the_finding():
    record = terraform_deep_scanner.scan(FIXTURE, _run_shell)
    dumped = json.dumps([f.to_dict() for f in record.findings])
    # The fixture's fake values must not leak into evidence/description.
    assert "AKIAFAKEFIXTURE00001" not in dumped
    assert "wJalrFAKEfixtureEXAMPLEKEY000000000000000" not in dumped
    assert "redacted" in dumped


def test_variable_references_are_not_reported_as_hardcoded(tmp_path):
    (tmp_path / "main.tf").write_text(
        'provider "aws" {\n'
        '  region     = "us-east-1"\n'
        '  access_key = var.access_key\n'
        '  secret_key = "${local.secret}"\n'
        "}\n"
    )
    record = terraform_deep_scanner.scan(str(tmp_path), _run_shell)
    assert not [f for f in record.findings if f.rule_id == "TF_PROVIDER_CREDENTIAL"]


def test_detects_local_state_backend():
    record = terraform_deep_scanner.scan(FIXTURE, _run_shell)
    finding = next(f for f in record.findings if f.rule_id == "TF_STATE_LOCAL_BACKEND")
    assert finding.severity == SecuritySeverity.HIGH
    assert finding.cwe == "CWE-312"


def test_detects_unencrypted_remote_state(tmp_path):
    (tmp_path / "main.tf").write_text(
        'terraform {\n  backend "s3" {\n    bucket  = "state"\n    encrypt = false\n  }\n}\n')
    record = terraform_deep_scanner.scan(str(tmp_path), _run_shell)
    finding = next(f for f in record.findings if f.rule_id == "TF_STATE_UNENCRYPTED")
    assert finding.severity == SecuritySeverity.HIGH


def test_encrypted_remote_state_is_not_flagged(tmp_path):
    (tmp_path / "main.tf").write_text(
        'terraform {\n  backend "s3" {\n    bucket  = "state"\n    encrypt = true\n  }\n}\n')
    record = terraform_deep_scanner.scan(str(tmp_path), _run_shell)
    assert not [f for f in record.findings if f.rule_id.startswith("TF_STATE")]


def test_detects_unpinned_provider():
    record = terraform_deep_scanner.scan(FIXTURE, _run_shell)
    finding = next(f for f in record.findings if f.rule_id == "TF_PROVIDER_UNPINNED")
    assert finding.severity == SecuritySeverity.MEDIUM
    assert "reproducible" in finding.evidence


def test_pinned_provider_is_not_flagged(tmp_path):
    (tmp_path / "main.tf").write_text(
        'terraform {\n  required_providers {\n'
        '    aws = {\n      source  = "hashicorp/aws"\n      version = "~> 5.0"\n    }\n'
        "  }\n}\n"
    )
    record = terraform_deep_scanner.scan(str(tmp_path), _run_shell)
    assert not [f for f in record.findings if f.rule_id == "TF_PROVIDER_UNPINNED"]


def test_unparseable_file_becomes_a_finding_not_a_silent_skip(tmp_path):
    (tmp_path / "broken.tf").write_text('resource "aws_s3_bucket" "b" { unclosed = \n')
    record = terraform_deep_scanner.scan(str(tmp_path), _run_shell)
    finding = next(f for f in record.findings if f.rule_id == "TF_UNPARSEABLE")
    # "We could not read it" must never look the same as "it was clean".
    assert "unverified rather than clean" in finding.remediation


def test_repository_with_no_terraform_is_not_applicable(tmp_path):
    (tmp_path / "readme.md").write_text("nothing here\n")
    record = terraform_deep_scanner.scan(str(tmp_path), _run_shell)
    assert record.availability == ScannerAvailability.NOT_APPLICABLE
    assert record.finding_count == 0


def test_credential_detection_is_provider_agnostic(tmp_path):
    (tmp_path / "main.tf").write_text(
        'provider "azurerm" {\n  client_secret = "literal-not-a-reference-value"\n}\n')
    record = terraform_deep_scanner.scan(str(tmp_path), _run_shell)
    finding = next(f for f in record.findings if f.rule_id == "TF_PROVIDER_CREDENTIAL")
    # Nothing in the scanner knows what "azurerm" is - it keys off the
    # argument NAME, which is why a provider it has never heard of works.
    assert finding.resource == "provider.azurerm"
    assert "literal-not-a-reference-value" not in json.dumps(finding.to_dict())


def test_findings_use_the_iac_category_not_a_new_one():
    record = terraform_deep_scanner.scan(FIXTURE, _run_shell)
    assert all(f.category == SecurityCategory.IAC for f in record.findings)
