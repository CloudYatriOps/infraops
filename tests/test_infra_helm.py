"""Helm analysis (Phase 5 Part 4/16).

The most important test in this file is
`test_helm_is_blocked_not_reported_as_passing`: `checkov --framework helm`
returns 0 findings and exit code 0 when the `helm` binary is missing,
which would render as a clean chart. This asserts the platform reports
BLOCKED instead.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from aep.infra.scanners import helm_scanner
from aep.security.models import ScannerAvailability, SecurityCategory, SecuritySeverity

FIXTURE = str(Path(__file__).resolve().parent / "fixtures" / "infra" / "helm")


def _run_shell(args, cwd=None, timeout=60):
    try:
        proc = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return {"ok": proc.returncode == 0, "exit_code": proc.returncode,
                "stdout": proc.stdout, "stderr": proc.stderr}
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return {"ok": False, "exit_code": -1, "stdout": "", "stderr": str(e)}


def test_helm_is_blocked_not_reported_as_passing():
    """The core honesty property of this scanner."""
    record = helm_scanner.scan(FIXTURE, _run_shell)
    if record.availability == ScannerAvailability.AVAILABLE:
        # A future environment genuinely has helm - nothing to assert here.
        return
    assert record.availability == ScannerAvailability.BLOCKED
    assert "get.helm.sh" in record.note or "helm" in record.note.lower()
    # The specific trap: checkov's helm framework exits 0 with 0 findings
    # when the binary is missing. This scanner must not inherit that.
    assert "checkov" in record.note
    assert record.finding_count > 0, (
        "the fixture chart has insecure defaults; a BLOCKED rendering path must not also "
        "suppress the values-level findings that CAN be computed"
    )


def test_detects_insecure_chart_defaults():
    record = helm_scanner.scan(FIXTURE, _run_shell)
    rules = {f.rule_id for f in record.findings}
    assert "HELM_VALUES_SECURITYCONTEXT_PRIVILEGED" in rules
    assert "HELM_VALUES_SECURITYCONTEXT_RUNASUSER" in rules
    assert "HELM_VALUES_HOSTNETWORK" in rules
    assert "HELM_VALUES_SERVICE_TYPE" in rules
    assert "HELM_VALUES_RBAC_CLUSTERWIDE" in rules
    assert "HELM_VALUES_NETWORKPOLICY_ENABLED" in rules
    assert "HELM_VALUES_INGRESS_TLS" in rules


def test_privileged_default_is_critical():
    record = helm_scanner.scan(FIXTURE, _run_shell)
    finding = next(f for f in record.findings
                    if f.rule_id == "HELM_VALUES_SECURITYCONTEXT_PRIVILEGED")
    assert finding.severity == SecuritySeverity.CRITICAL
    assert finding.category == SecurityCategory.HELM
    assert finding.file.endswith("values.yaml")


def test_findings_carry_the_values_key_path_and_a_line_number():
    record = helm_scanner.scan(FIXTURE, _run_shell)
    finding = next(f for f in record.findings if f.rule_id == "HELM_VALUES_HOSTNETWORK")
    assert finding.resource == "values.hostNetwork"
    assert finding.line is not None and finding.line > 0


def test_secure_chart_defaults_produce_no_findings(tmp_path):
    chart = tmp_path / "safe-chart"
    chart.mkdir()
    (chart / "Chart.yaml").write_text("apiVersion: v2\nname: safe\nversion: 0.1.0\n")
    (chart / "values.yaml").write_text(
        "securityContext:\n  privileged: false\n  runAsUser: 1000\n"
        "  allowPrivilegeEscalation: false\n"
        "service:\n  type: ClusterIP\n"
        "networkPolicy:\n  enabled: true\n"
    )
    record = helm_scanner.scan(str(tmp_path), _run_shell)
    assert record.finding_count == 0


def test_repository_with_no_chart_is_not_applicable(tmp_path):
    (tmp_path / "readme.md").write_text("no charts\n")
    record = helm_scanner.scan(str(tmp_path), _run_shell)
    assert record.availability == ScannerAvailability.NOT_APPLICABLE


def test_vendored_subcharts_are_skipped(tmp_path):
    parent = tmp_path / "parent"
    (parent / "charts" / "sub").mkdir(parents=True)
    (parent / "Chart.yaml").write_text("apiVersion: v2\nname: parent\nversion: 0.1.0\n")
    (parent / "values.yaml").write_text("service:\n  type: ClusterIP\n")
    (parent / "charts" / "sub" / "Chart.yaml").write_text(
        "apiVersion: v2\nname: sub\nversion: 0.1.0\n")
    (parent / "charts" / "sub" / "values.yaml").write_text(
        "securityContext:\n  privileged: true\n")
    record = helm_scanner.scan(str(tmp_path), _run_shell)
    # The subchart's defaults are overridden by the parent, so reporting
    # them would flag a problem the operator never actually receives.
    assert not [f for f in record.findings if "sub" in (f.file or "")]


def test_malformed_values_are_reported_not_swallowed(tmp_path):
    chart = tmp_path / "broken-chart"
    chart.mkdir()
    (chart / "Chart.yaml").write_text("apiVersion: v2\nname: broken\nversion: 0.1.0\n")
    (chart / "values.yaml").write_text("service:\n  type: [unclosed\n   bad: indent\n")
    record = helm_scanner.scan(str(tmp_path), _run_shell)
    assert "parse error" in record.note.lower()
