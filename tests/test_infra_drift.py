"""Drift detection (Phase 5 Part 7/16). Pure dict comparison - fully
testable with no cloud access, which is the point of keeping every
provider-specific concern inside the adapter."""
from __future__ import annotations

from pathlib import Path

from aep.infra.drift import compare_state, desired_state_from_terraform

FIXTURE = str(Path(__file__).resolve().parent / "fixtures" / "infra" / "terraform")


def test_detects_attribute_drift():
    report = compare_state(
        desired={"aws_s3_bucket.data": {"acl": "private", "encryption": "AES256"}},
        actual={"aws_s3_bucket.data": {"acl": "public-read", "encryption": "AES256"}},
        source="fixture",
    )
    drift = [i for i in report.items if i.kind == "drift"]
    assert len(drift) == 1
    assert drift[0].resource_id == "aws_s3_bucket.data.acl"
    assert drift[0].desired == "private"
    assert drift[0].actual == "public-read"


def test_flags_security_relevant_attributes_separately_from_cosmetic_ones():
    report = compare_state(
        desired={"r": {"encryption": "AES256", "tags": "a"}},
        actual={"r": {"encryption": "none", "tags": "b"}},
        source="fixture",
    )
    security = {i.resource_id for i in report.security_relevant_items}
    assert "r.encryption" in security
    # A changed tag and a disabled encryption setting are not the same event.
    assert "r.tags" not in security


def test_unmanaged_resources_are_always_security_relevant():
    report = compare_state(
        desired={},
        actual={"aws_s3_bucket.shadow": {"acl": "public-read"}},
        source="aws:read_only",
    )
    item = next(i for i in report.items if i.kind == "unmanaged")
    assert item.security_relevant is True
    assert "not declared anywhere in the repository" in item.detail


def test_missing_resources_are_reported_without_assuming_deletion():
    report = compare_state(
        desired={"aws_s3_bucket.planned": {"acl": "private"}},
        actual={},
        source="aws:read_only",
    )
    item = next(i for i in report.items if i.kind == "missing")
    assert item.security_relevant is False
    assert "not applied yet" in item.detail


def test_report_never_reconciles():
    report = compare_state(desired={"r": {"a": 1}}, actual={"r": {"a": 2}}, source="fixture")
    assert report.reconciled is False
    assert any("was executed" in step or "does NOT" in step or "NOT execute" in step.upper()
                for step in report.remediation_plan)


def test_remediation_plan_is_ordered_and_triages_security_first():
    report = compare_state(
        desired={"r": {"encryption": "AES256"}},
        actual={"r": {"encryption": "none"}, "shadow": {"public": True}},
        source="aws:read_only",
    )
    assert report.remediation_plan[0].startswith("1. TRIAGE FIRST")
    assert any("IMPORT OR DELETE" in step for step in report.remediation_plan)


def test_deletion_is_never_proposed_as_an_automatic_action():
    report = compare_state(desired={}, actual={"shadow": {"a": 1}}, source="aws:read_only")
    plan_text = " ".join(report.remediation_plan)
    assert "DENY-by-default" in plan_text


def test_identical_state_reports_no_drift():
    report = compare_state(desired={"r": {"a": 1}}, actual={"r": {"a": 1}}, source="fixture")
    assert report.items == []
    assert "no drift detected" in report.remediation_plan[0]


def test_desired_state_is_built_from_real_terraform():
    desired = desired_state_from_terraform(FIXTURE)
    assert "aws_s3_bucket.public_data" in desired
    assert desired["aws_s3_bucket.public_data"]["acl"] == "public-read"
    assert "aws_security_group.wide_open" in desired


def test_interpolated_values_are_marked_computed_not_guessed(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "b" {\n  bucket = var.bucket_name\n  acl = "private"\n}\n')
    desired = desired_state_from_terraform(str(tmp_path))
    assert desired["aws_s3_bucket.b"]["bucket"] == "<computed>"
    assert desired["aws_s3_bucket.b"]["acl"] == "private"


def test_report_is_serializable():
    import json
    report = compare_state(desired={"r": {"a": 1}}, actual={"r": {"a": 2}}, source="fixture")
    assert json.dumps(report.to_dict())
