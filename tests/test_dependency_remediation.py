"""Remediation planning: safe-upgrade selection, severity handling,
ambiguous/unresolved-CVE escalation, and manifest mutation. Uses
hand-built VulnerabilityFinding objects (no scanner/network involved) so
this module tests the planning LOGIC in isolation from real scanner I/O -
the real-scanner-backed tests live in test_dependency_scanning.py.
"""
from __future__ import annotations

from aep.dependency.manifest_writer import apply_plan
from aep.dependency.models import Ecosystem, Severity, VulnerabilityFinding
from aep.dependency.remediation import plan_remediations


def _finding(package="urllib3", installed="1.26.4", fixed=None, finding_id="PYSEC-1",
             manifest_path="requirements.txt", ecosystem=Ecosystem.PYTHON,
             severity=Severity.HIGH) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        id=finding_id, aliases=[], ecosystem=ecosystem, manifest_path=manifest_path,
        package=package, installed_version=installed, vulnerable_range=f"<{installed}",
        fixed_versions=fixed or [], severity=severity, summary="test finding",
        source="test", scanned_at="2026-01-01T00:00:00+00:00",
    )


def test_picks_smallest_fixed_version_not_latest():
    finding = _finding(fixed=["1.26.5"])
    plans = plan_remediations([finding])
    assert len(plans) == 1
    assert plans[0].safe is True
    assert plans[0].to_version == "1.26.5"
    assert plans[0].major_version_bump is False


def test_multiple_findings_same_package_pick_largest_of_minimums():
    # finding A is fixed anywhere >=1.26.5; finding B needs >=1.26.17 or
    # >=2.0.6 - the smallest version that resolves BOTH at once is 1.26.17,
    # not a blind jump to 2.0.6.
    findings = [
        _finding(finding_id="PYSEC-A", fixed=["1.26.5"]),
        _finding(finding_id="PYSEC-B", fixed=["1.26.17", "2.0.6"]),
    ]
    plans = plan_remediations(findings)
    assert len(plans) == 1
    plan = plans[0]
    assert plan.safe is True
    assert plan.to_version == "1.26.17"
    assert plan.major_version_bump is False
    assert set(plan.finding_ids) == {"PYSEC-A", "PYSEC-B"}


def test_no_fixed_version_is_unsafe_and_escalated():
    finding = _finding(fixed=[])
    plans = plan_remediations([finding])
    assert plans[0].safe is False
    assert plans[0].to_version is None
    assert "no published fixed version" in plans[0].reason


def test_unparseable_fixed_version_is_unsafe_not_guessed():
    finding = _finding(fixed=["not-a-real-version"])
    plans = plan_remediations([finding])
    assert plans[0].safe is False
    assert plans[0].to_version is None


def test_major_version_bump_detected():
    finding = _finding(installed="1.9.9", fixed=["2.0.0"])
    plans = plan_remediations([finding])
    assert plans[0].safe is True
    assert plans[0].major_version_bump is True


def test_severity_is_preserved_through_the_pipeline():
    finding = _finding(severity=Severity.CRITICAL, fixed=["9.9.9"])
    assert finding.to_dict()["severity"] == "critical"


def test_apply_plan_rewrites_requirements_txt_pin():
    content = "flask==2.0.0\nurllib3==1.26.4\nrequests==2.25.0\n"
    plan = {"package": "urllib3", "from_version": "1.26.4", "to_version": "1.26.17"}
    new_content = apply_plan(content, Ecosystem.PYTHON, plan)
    assert "urllib3==1.26.17" in new_content
    assert "flask==2.0.0" in new_content
    assert "requests==2.25.0" in new_content


def test_apply_plan_missing_pin_raises_rather_than_silently_no_op():
    content = "flask==2.0.0\n"
    plan = {"package": "urllib3", "from_version": "1.26.4", "to_version": "1.26.17"}
    try:
        apply_plan(content, Ecosystem.PYTHON, plan)
        assert False, "expected a ValueError"
    except ValueError:
        pass


def test_apply_plan_rewrites_package_json_dependency():
    import json
    content = json.dumps({"name": "x", "dependencies": {"minimatch": "3.0.4"}})
    plan = {"package": "minimatch", "from_version": "3.0.4", "to_version": "3.1.5"}
    new_content = apply_plan(content, Ecosystem.NODE, plan)
    assert json.loads(new_content)["dependencies"]["minimatch"] == "3.1.5"
