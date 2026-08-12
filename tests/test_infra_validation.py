"""Validation (Phase 5 Part 10/16).

The central property under test: a validator that could not RUN is never
counted as a pass. In this environment `terraform`/`helm` are BLOCKED, so
without that rule every Terraform and Helm remediation would report itself
"validated" on the strength of a validator that never executed.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from aep.infra.validation import (
    summarize, validate_helm_chart, validate_kubernetes_manifest, validate_terraform_change,
    validate_terraform_hcl,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "infra"


def _absent_shell(args, cwd=None, timeout=60):
    """Simulates (and in this sandbox, matches) a missing binary."""
    return {"ok": False, "exit_code": -1, "stdout": "", "stderr": "binary not found"}


def _real_shell(args, cwd=None, timeout=60):
    try:
        proc = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return {"ok": proc.returncode == 0, "exit_code": proc.returncode,
                "stdout": proc.stdout, "stderr": proc.stderr}
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return {"ok": False, "exit_code": -1, "stdout": "", "stderr": str(e)}


# ---- the three-state contract ---------------------------------------------

def test_blocked_validators_never_summarize_as_validated():
    results = validate_terraform_change(str(FIXTURES / "terraform"), "main.tf", _absent_shell)
    blocked_only = [r for r in results if not r.ran]
    assert blocked_only, "terraform CLI validators are expected to be blocked here"
    validated, explanation = summarize(blocked_only)
    assert validated is False
    assert "no validator was able to run" in explanation


def test_a_blocked_validator_is_reported_but_not_counted_as_passing():
    results = validate_terraform_change(str(FIXTURES / "terraform"), "main.tf", _absent_shell)
    validated, explanation = summarize(results)
    # The HCL2 structural parse DID run and pass, so the set as a whole is
    # validated - but the explanation must name what did not run.
    assert validated is True
    assert "could NOT run and were not counted as passing" in explanation
    assert "terraform validate" in explanation


def test_a_failing_validator_beats_a_passing_one():
    results = validate_terraform_change(str(FIXTURES / "terraform"), "main.tf", _absent_shell)
    from aep.infra.models import ValidationResult
    results.append(ValidationResult(validator="fake", ran=True, passed=False, detail="broke"))
    validated, explanation = summarize(results)
    assert validated is False
    assert "validation FAILED" in explanation


def test_empty_result_set_is_not_validated():
    validated, explanation = summarize([])
    assert validated is False
    assert "no validator was able to run" in explanation


# ---- Terraform ------------------------------------------------------------

def test_hcl_structural_parse_accepts_valid_terraform():
    result = validate_terraform_hcl(str(FIXTURES / "terraform"), "main.tf")
    assert result.ran and result.passed
    # Must be explicit that this is weaker than `terraform validate`.
    assert "NOT `terraform validate`" in result.detail


def test_hcl_structural_parse_rejects_malformed_terraform(tmp_path):
    (tmp_path / "bad.tf").write_text('resource "aws_s3_bucket" "b" { unclosed = \n')
    result = validate_terraform_hcl(str(tmp_path), "bad.tf")
    assert result.ran is True
    assert result.passed is False
    assert "parse failed" in result.detail


def test_terraform_cli_validators_report_blocked_in_this_environment():
    results = validate_terraform_change(str(FIXTURES / "terraform"), "main.tf", _real_shell)
    cli_results = [r for r in results if r.validator.startswith("terraform")]
    assert len(cli_results) == 2
    for result in cli_results:
        if not result.ran:
            assert "releases.hashicorp.com" in result.detail
            assert "NOT as a passing validation" in result.detail


# ---- Kubernetes -----------------------------------------------------------

def test_kubernetes_schema_validation_accepts_the_fixture():
    result = validate_kubernetes_manifest(str(FIXTURES / "kubernetes"), "workload.yaml")
    assert result.ran and result.passed
    assert "no cluster contacted" in result.detail


def test_kubernetes_schema_validation_rejects_a_type_error(tmp_path):
    (tmp_path / "bad.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: bad\n"
        'spec:\n  replicas: "three"\n  selector:\n    matchLabels:\n      app: bad\n'
        "  template:\n    spec:\n      containers:\n      - name: c\n        image: x\n"
    )
    result = validate_kubernetes_manifest(str(tmp_path), "bad.yaml")
    assert result.ran is True
    assert result.passed is False
    assert "schema violation" in result.detail


def test_kubernetes_validation_needs_no_cluster():
    # Proven by the fact the passing test above runs in a sandbox with no
    # kubectl, no kubeconfig, and no reachable cluster.
    result = validate_kubernetes_manifest(str(FIXTURES / "kubernetes"), "workload.yaml")
    assert result.validator == "kubernetes-validate"
    assert result.ran


def test_kubernetes_validation_reports_malformed_yaml(tmp_path):
    (tmp_path / "bad.yaml").write_text("apiVersion: v1\nkind: Pod\n  bad: [unclosed\n")
    result = validate_kubernetes_manifest(str(tmp_path), "bad.yaml")
    assert result.ran is True and result.passed is False
    assert "YAML parse failed" in result.detail


# ---- Helm -----------------------------------------------------------------

def test_helm_cli_validators_report_blocked_and_yaml_parse_still_runs():
    results = validate_helm_chart(str(FIXTURES / "helm"), "insecure-chart", _real_shell)
    validators = {r.validator: r for r in results}
    assert "yaml-parse:Chart.yaml" in validators
    assert validators["yaml-parse:Chart.yaml"].ran is True
    for name in ("helm lint", "helm template"):
        if name in validators and not validators[name].ran:
            assert "get.helm.sh" in validators[name].detail
            assert "NOT as a passing validation" in validators[name].detail
