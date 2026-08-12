"""Release gate engine (Phase 6 Part 5)."""
from __future__ import annotations

from aep.cicd.release_gates import evaluate_release_gates


_ALL_PASS = dict(
    tests_passed=True, cve_scan_clean=True, secrets_clean=True, sast_clean=True, iac_clean=True,
    ci_pipeline_green=True, artifact_built=True, artifact_provenance_recorded=True,
    required_approvals_met=True, environment_policy_satisfied=True,
)


def test_all_gates_passed_when_every_input_is_true_and_infra_not_required():
    result = evaluate_release_gates(**_ALL_PASS, infra_required=False)
    assert result.all_required_passed
    assert result.blockers == []


def test_infra_gates_are_required_only_when_infra_required():
    result = evaluate_release_gates(**_ALL_PASS, infra_required=False)
    infra_gates = [g for g in result.gates if g.category == "INFRASTRUCTURE"]
    assert all(not g.required for g in infra_gates)
    assert result.all_required_passed  # not-run infra gates don't block a non-infra release


def test_infra_gates_block_when_required_but_not_run():
    result = evaluate_release_gates(**_ALL_PASS, infra_required=True)
    assert not result.all_required_passed
    assert any("INFRASTRUCTURE" in b for b in result.blockers)


def test_not_run_never_counts_as_passed():
    result = evaluate_release_gates(tests_passed=None, infra_required=False)
    source_gate = next(g for g in result.gates if g.name == "unit_tests")
    assert source_gate.status.value == "NOT_RUN"
    assert not result.all_required_passed


def test_a_single_failed_required_gate_blocks_the_whole_release():
    inputs = dict(_ALL_PASS)
    inputs["secrets_clean"] = False
    result = evaluate_release_gates(**inputs, infra_required=False)
    assert not result.all_required_passed
    assert any("secrets_scan" in b for b in result.blockers)


def test_blockers_are_human_readable_and_named_by_category():
    result = evaluate_release_gates(infra_required=False)
    assert all("/" in b for b in result.blockers)  # "CATEGORY/name: STATUS"
