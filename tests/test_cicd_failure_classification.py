"""CI failure classification (Phase 6 Part 3 step 5, Part 14)."""
from __future__ import annotations

from aep.cicd.failure_classification import classify_ci_failure
from aep.models import FailureClass


def test_classifies_security_scan_failure():
    diag = classify_ci_failure(
        failed_checks=[{"name": "security-scan", "summary": "gitleaks found a secret",
                         "text": ""}],
        jobs=[])
    assert diag.failure_class == FailureClass.SECURITY


def test_classifies_dependency_failure():
    diag = classify_ci_failure(
        failed_checks=[{"name": "install", "summary": "", "text": "no matching distribution "
                         "found for foo==9.9.9"}],
        jobs=[])
    assert diag.failure_class == FailureClass.DEPENDENCY


def test_classifies_build_failure():
    diag = classify_ci_failure(
        failed_checks=[{"name": "build", "summary": "docker build failed", "text": ""}], jobs=[])
    assert diag.failure_class == FailureClass.BUILD


def test_classifies_ci_configuration_failure():
    diag = classify_ci_failure(
        failed_checks=[{"name": "ci", "summary": "secret not found", "text": ""}], jobs=[])
    assert diag.failure_class == FailureClass.CI_CONFIGURATION


def test_classifies_infrastructure_failure():
    diag = classify_ci_failure(
        failed_checks=[{"name": "deploy", "summary": "terraform apply failed", "text": ""}],
        jobs=[])
    assert diag.failure_class == FailureClass.INFRASTRUCTURE


def test_classifies_deployment_failure():
    diag = classify_ci_failure(
        failed_checks=[{"name": "deploy", "summary": "rollout failed", "text": ""}], jobs=[])
    assert diag.failure_class == FailureClass.DEPLOYMENT


def test_classifies_health_failure():
    diag = classify_ci_failure(
        failed_checks=[{"name": "verify", "summary": "readiness probe failed", "text": ""}],
        jobs=[])
    assert diag.failure_class == FailureClass.HEALTH


def test_classifies_network_failure():
    diag = classify_ci_failure(
        failed_checks=[{"name": "deploy", "summary": "connection refused", "text": ""}], jobs=[])
    assert diag.failure_class == FailureClass.NETWORK


def test_classifies_external_service_failure():
    diag = classify_ci_failure(
        failed_checks=[{"name": "publish", "summary": "registry unavailable", "text": ""}],
        jobs=[])
    assert diag.failure_class == FailureClass.EXTERNAL_SERVICE


def test_classifies_test_failure():
    diag = classify_ci_failure(
        failed_checks=[{"name": "unit-tests", "summary": "AssertionError", "text": ""}], jobs=[])
    assert diag.failure_class == FailureClass.TEST


def test_classifies_flaky_when_previous_run_succeeded():
    diag = classify_ci_failure(failed_checks=[{"name": "unit-tests", "summary": "timeout"}],
                                jobs=[], previous_run_conclusion="success")
    assert diag.failure_class == FailureClass.FLAKY


def test_unrecognized_signal_is_unknown_never_guessed():
    diag = classify_ci_failure(failed_checks=[{"name": "mystery", "summary": "", "text": ""}],
                                jobs=[])
    assert diag.failure_class == FailureClass.UNKNOWN
    assert diag.matched_signal == ""


def test_next_action_is_never_empty_for_any_class():
    for failure_class in FailureClass:
        diag = classify_ci_failure(failed_checks=[], jobs=[])
        assert diag.next_action  # sanity: at minimum UNKNOWN's next_action is non-empty
        break
