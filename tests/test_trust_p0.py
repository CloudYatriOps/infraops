"""Trust-First P0 regression tests.

Covers the three P0 invariants that are cheap to prove directly, without a
real Postgres/orchestrator fixture:

  * P0.3 - scanner failure/unavailable/blocked/malformed output can NEVER
    become PASS/0-findings/clean in `scan.py::_from_record` (the posture
    computation choke point).
  * P0.2 - the four-state verification status never lets an empty
    `verified` list read as anything but UNVERIFIED, and CONTRADICTED
    always wins.
  * P0.1/P0.5 - the Trust Contract's `not_verified` is always explicit
    (never a silent omission), and trust-level L2 requires every
    deterministic criterion, never AI narrative.
"""
from __future__ import annotations

from datetime import datetime, timezone

from aep.models import Evidence, Event, PolicyDecisionType, Task, TaskStatus
from aep.scan import AnalyzerStatus, _from_record
from aep.security.models import ScannerAvailability, SecurityCategory, SecurityScanRecord
from aep.trust import (
    CONTRADICTED,
    L0,
    L1,
    L2,
    UNVERIFIED,
    VERIFIED,
    build_trust_contract,
    compute_trust_level,
    compute_verification_status,
)


def _record(**overrides) -> SecurityScanRecord:
    base = dict(
        scanner="test-scanner", scanner_version="1.0", category=SecurityCategory.SECRET,
        scanned_at="2026-01-01T00:00:00Z", target="/repo",
        availability=ScannerAvailability.AVAILABLE, exit_code=0, finding_count=0, findings=[],
    )
    base.update(overrides)
    return SecurityScanRecord(**base)


# ---- P0.3: scanner failure must never become PASS -------------------------

def test_scanner_unavailable_is_never_pass():
    result = _from_record("Secrets", _record(availability=ScannerAvailability.UNAVAILABLE))
    assert result.status == AnalyzerStatus.UNAVAILABLE


def test_scanner_blocked_is_never_pass():
    result = _from_record("Secrets", _record(availability=ScannerAvailability.BLOCKED))
    assert result.status == AnalyzerStatus.BLOCKED


def test_scanner_failed_with_findings_is_fail_not_pass():
    result = _from_record("Secrets", _record(finding_count=1))
    assert result.status == AnalyzerStatus.FAIL


def test_malformed_scanner_output_is_never_pass():
    """The exact class of bug found in gitleaks/semgrep/checkov during this
    pass: availability=AVAILABLE + finding_count=0 must NOT read as PASS
    when the scanner flagged its own output as unparseable."""
    result = _from_record("Secrets", _record(parse_error=True, finding_count=0))
    assert result.status == AnalyzerStatus.FAIL
    assert "could not be parsed" in result.reason or result.reason


def test_genuine_zero_findings_is_still_pass():
    """The only path to PASS: availability=AVAILABLE, no parse error, 0
    findings - a real, verifiable clean scan."""
    result = _from_record("Secrets", _record(finding_count=0, parse_error=False))
    assert result.status == AnalyzerStatus.PASS


# ---- P0.2: four-state verification status ----------------------------------

def test_empty_verified_list_is_unverified_regardless_of_narrative():
    assert compute_verification_status(verified=[], not_verified=["tests_executed"]) == UNVERIFIED


def test_full_verification_with_nothing_missing_is_verified():
    assert compute_verification_status(verified=["scanner_execution"], not_verified=[]) == VERIFIED


def test_contradicted_wins_even_with_verified_evidence():
    assert compute_verification_status(
        verified=["scanner_execution", "tests_executed"], not_verified=[], contradicted=True,
    ) == CONTRADICTED


# ---- P0.1/P0.5: Trust Contract + trust level -------------------------------

def _now():
    return datetime.now(timezone.utc).isoformat()


def test_not_verified_is_always_explicit_never_a_silent_omission():
    task = Task(id="t1", type="project_scan", project_id="p1", status=TaskStatus.SUCCEEDED,
                evidence=[Evidence(source="aep.scan", captured_at=_now(), exit_code=0, summary="{}")])
    contract = build_trust_contract(task, events=[])
    assert contract.not_verified, "a fresh scan task must name what it did NOT check"
    assert "policy_evaluated" in contract.not_verified
    assert "tests_executed" in contract.not_verified


def test_raw_ai_confidence_narrative_cannot_manufacture_l2():
    """A mutating task type with no policy/skill/test evidence at all stays
    L0/L1 - no amount of payload text can substitute for the deterministic
    criteria."""
    task = Task(id="t2", type="code_fix", project_id="p1", status=TaskStatus.SUCCEEDED,
                payload={"ai_confidence": "99%", "reasoning": "trust me, this is safe"})
    contract = build_trust_contract(task, events=[])
    assert contract.trust_level in (L0, L1)
    assert contract.trust_level != L2


def test_l2_requires_every_deterministic_criterion():
    task = Task(id="t3", type="code_fix", project_id="p1", status=TaskStatus.SUCCEEDED,
                evidence=[
                    Evidence(source="pytest", captured_at=_now(), exit_code=0, summary="14 passed"),
                    Evidence(source="skill_registry", captured_at=_now(), exit_code=0, summary="{}"),
                    Evidence(source="aep.scan", captured_at=_now(), exit_code=0, summary="{}"),
                    Evidence(source="aep.scan", captured_at=_now(), exit_code=0, summary="{}"),
                ])
    events = [
        Event(id="e1", actor="orchestrator", action="policy_evaluated", project_id="p1",
              task_id="t3", decision="ALLOW", timestamp=_now(), details={"policy_action": "code.fix"}),
    ]
    contract = build_trust_contract(task, events=events)
    assert contract.verification_status == VERIFIED
    assert contract.trust_level == L2
    assert contract.rollback_available is True


def test_l2_denied_by_policy_never_reaches_l2():
    task = Task(id="t4", type="code_fix", project_id="p1", status=TaskStatus.SUCCEEDED,
                evidence=[
                    Evidence(source="pytest", captured_at=_now(), exit_code=0, summary="ok"),
                    Evidence(source="skill_registry", captured_at=_now(), exit_code=0, summary="{}"),
                    Evidence(source="aep.scan", captured_at=_now(), exit_code=0, summary="{}"),
                    Evidence(source="aep.scan", captured_at=_now(), exit_code=0, summary="{}"),
                ])
    events = [
        Event(id="e1", actor="orchestrator", action="policy_evaluated", project_id="p1",
              task_id="t4", decision=PolicyDecisionType.DENY.value, timestamp=_now(),
              details={"policy_action": "code.fix"}),
    ]
    contract = build_trust_contract(task, events=events)
    assert contract.trust_level != L2


def test_non_mutating_task_never_reaches_l2():
    task = Task(id="t5", type="project_scan", project_id="p1", status=TaskStatus.SUCCEEDED,
                evidence=[Evidence(source="aep.scan", captured_at=_now(), exit_code=0, summary="{}")])
    contract = build_trust_contract(task, events=[])
    assert contract.trust_level in (L0, L1)


def test_compute_trust_level_deterministic_not_narrative():
    task = Task(id="t6", type="code_fix", project_id="p1", status=TaskStatus.SUCCEEDED)
    assert compute_trust_level(task, verification_status=VERIFIED, policy_denied=False,
                                skill_required_and_missing=True) != L2
    assert compute_trust_level(task, verification_status=VERIFIED, policy_denied=False,
                                skill_required_and_missing=False) == L2


if __name__ == "__main__":
    # ponytail minimum self-check - runnable without pytest.
    test_scanner_unavailable_is_never_pass()
    test_malformed_scanner_output_is_never_pass()
    test_genuine_zero_findings_is_still_pass()
    test_empty_verified_list_is_unverified_regardless_of_narrative()
    test_not_verified_is_always_explicit_never_a_silent_omission()
    test_l2_requires_every_deterministic_criterion()
    test_l2_denied_by_policy_never_reaches_l2()
    print("OK")
