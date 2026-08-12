"""Kubernetes scanning (Phase 5 Part 3/16).

Real checkov + real in-process YAML analysis against the shipped
deliberately-insecure fixture. checkov tests are skipped (not faked) when
the binary is genuinely absent, matching the discipline in
test_dependency_scanning.py and test_security_scanners.py.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from aep.infra.scanners import checkov_k8s_scanner, k8s_native_scanner
from aep.security.models import ScannerAvailability, SecurityCategory, SecuritySeverity

FIXTURE = str(Path(__file__).resolve().parent / "fixtures" / "infra" / "kubernetes")


def _run_shell(args, cwd=None, timeout=180):
    try:
        proc = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return {"ok": proc.returncode == 0, "exit_code": proc.returncode,
                "stdout": proc.stdout, "stderr": proc.stderr}
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return {"ok": False, "exit_code": -1, "stdout": "", "stderr": str(e)}


_checkov_available = (checkov_k8s_scanner.check_availability(_run_shell).status
                       == ScannerAvailability.AVAILABLE)
_skip_checkov = pytest.mark.skipif(not _checkov_available,
                                    reason="checkov not installed in this environment")


# ---- checkov-backed policy scanning ---------------------------------------

@_skip_checkov
def test_checkov_detects_every_part3_workload_category():
    record = checkov_k8s_scanner.scan(FIXTURE, _run_shell)
    assert record.availability == ScannerAvailability.AVAILABLE
    rules = {f.rule_id for f in record.findings}

    assert "CKV_K8S_16" in rules   # privileged container
    assert "CKV_K8S_19" in rules   # hostNetwork
    assert "CKV_K8S_17" in rules   # hostPID
    assert "CKV_K8S_23" in rules   # root execution
    assert "CKV_K8S_25" in rules   # added capabilities
    assert "CKV_K8S_20" in rules   # allowPrivilegeEscalation
    assert {"CKV_K8S_10", "CKV_K8S_11", "CKV_K8S_12", "CKV_K8S_13"} & rules  # resource limits
    assert {"CKV_K8S_8", "CKV_K8S_9"} & rules                                # probes
    assert "CKV_K8S_49" in rules   # wildcard RBAC


@_skip_checkov
def test_privileged_container_is_critical_and_rbac_escalation_is_critical():
    record = checkov_k8s_scanner.scan(FIXTURE, _run_shell)
    by_rule = {f.rule_id: f for f in record.findings}
    assert by_rule["CKV_K8S_16"].severity == SecuritySeverity.CRITICAL
    assert by_rule["CKV_K8S_158"].severity == SecuritySeverity.CRITICAL
    assert by_rule["CKV_K8S_19"].severity == SecuritySeverity.HIGH
    assert by_rule["CKV_K8S_9"].severity == SecuritySeverity.LOW


@_skip_checkov
def test_findings_use_the_phase4_security_finding_model_unchanged():
    record = checkov_k8s_scanner.scan(FIXTURE, _run_shell)
    finding = record.findings[0]
    assert finding.category == SecurityCategory.KUBERNETES
    assert finding.scanner == "checkov-kubernetes"
    # Same model Phase 4 defines - no forked finding type in Phase 5.
    assert hasattr(finding, "to_dict") and "severity" in finding.to_dict()


@_skip_checkov
def test_repository_with_no_kubernetes_is_not_applicable_not_pass(tmp_path):
    (tmp_path / "readme.md").write_text("no kubernetes here\n")
    record = checkov_k8s_scanner.scan(str(tmp_path), _run_shell)
    # "nothing to scan" must never render as a clean bill of health.
    assert record.availability == ScannerAvailability.NOT_APPLICABLE
    assert record.finding_count == 0
    assert "NOT_APPLICABLE" in record.note or "nothing to scan" in record.note


# ---- native exposure/secret/network analysis ------------------------------

def test_native_scanner_needs_no_binary():
    assert (k8s_native_scanner.check_availability(_run_shell).status
            == ScannerAvailability.AVAILABLE)


def test_native_scanner_detects_nodeport_exposure():
    record = k8s_native_scanner.scan(FIXTURE, _run_shell)
    finding = next(f for f in record.findings if f.rule_id == "K8S_SERVICE_NODEPORT")
    assert finding.severity == SecuritySeverity.HIGH
    assert "30080" in finding.evidence


def test_native_scanner_detects_committed_secret_without_printing_it():
    record = k8s_native_scanner.scan(FIXTURE, _run_shell)
    finding = next(f for f in record.findings if f.rule_id == "K8S_SECRET_COMMITTED")
    assert finding.severity == SecuritySeverity.CRITICAL
    # The decoded value must never appear anywhere in the finding - only a
    # shape description. Phase 4's "never print the secret" rule applies
    # identically to Kubernetes Secrets.
    import json
    dumped = json.dumps(finding.to_dict())
    assert "fixture-not-a-real-password" not in dumped
    assert "Zml4dHVyZS1ub3QtYS1yZWFsLXBhc3N3b3Jk" not in dumped
    assert "characters of decodable plaintext" in finding.evidence


def test_native_scanner_detects_ingress_without_tls():
    record = k8s_native_scanner.scan(FIXTURE, _run_shell)
    finding = next(f for f in record.findings if f.rule_id == "K8S_INGRESS_NO_TLS")
    assert finding.severity == SecuritySeverity.HIGH


def test_native_scanner_detects_missing_network_policy():
    record = k8s_native_scanner.scan(FIXTURE, _run_shell)
    assert any(f.rule_id == "K8S_NO_NETWORK_POLICY" for f in record.findings)


def test_network_policy_finding_disappears_when_one_is_defined(tmp_path):
    (tmp_path / "app.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: a\n"
        "spec:\n  template:\n    spec:\n      containers:\n      - name: c\n        image: x\n")
    (tmp_path / "netpol.yaml").write_text(
        "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: deny\n"
        "spec:\n  podSelector: {}\n  policyTypes: [Ingress]\n")
    record = k8s_native_scanner.scan(str(tmp_path), _run_shell)
    assert not any(f.rule_id == "K8S_NO_NETWORK_POLICY" for f in record.findings)


def test_native_scanner_skips_helm_templates_rather_than_reporting_broken_yaml(tmp_path):
    chart = tmp_path / "templates"
    chart.mkdir()
    (chart / "d.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .Release.Name }}\n")
    record = k8s_native_scanner.scan(str(tmp_path), _run_shell)
    # Go templates are not YAML; treating them as malformed manifests
    # would produce pure noise.
    assert record.note == "" or "parse error" not in record.note.lower()


def test_native_scanner_reports_yaml_parse_errors_rather_than_silently_passing(tmp_path):
    (tmp_path / "app.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: a\n"
        "spec:\n  template:\n    spec:\n      containers:\n      - name: c\n        image: x\n")
    (tmp_path / "broken.yaml").write_text("apiVersion: v1\nkind: Pod\n  bad indent: [unclosed\n")
    record = k8s_native_scanner.scan(str(tmp_path), _run_shell)
    assert "broken.yaml" in record.note
