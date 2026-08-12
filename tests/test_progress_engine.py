"""Progress/phase/deployability calculation (Phase 3 Part C/D/H).

Uses a small, throwaway roadmap.yaml + dummy test files under `tmp_path`
rather than the real config/roadmap.yaml, so these stay fast and
deterministic regardless of the platform's actual current state (which
changes as more phases get built). The real roadmap is exercised
implicitly by `aep status`/`aep progress` against this repo itself - see
test_cli_status.py.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from aep.models import Event
from aep.progress.calculator import (
    PHASE_BLOCKED, PHASE_COMPLETE, PHASE_IN_PROGRESS, PHASE_NOT_STARTED, PHASE_VERIFIED,
    compute_progress, record_phase_verified,
)
from aep.progress.deployability import (
    DEVELOPMENT_READY, INTEGRATION_READY, NOT_DEPLOYABLE, PRODUCTION_CANDIDATE, STAGING_READY,
    compute_deployability,
)
from aep.state_store import StateStore


def _write_roadmap(repo_root: Path, phases_yaml: str) -> str:
    path = repo_root / "roadmap.yaml"
    path.write_text(f"version: 1\nphases:\n{textwrap.indent(phases_yaml, '  ')}\n")
    return str(path)


def _write_passing_test(repo_root: Path, name: str) -> None:
    (repo_root / name).write_text("def test_ok():\n    assert True\n")


def _write_failing_test(repo_root: Path, name: str) -> None:
    (repo_root / name).write_text("def test_bad():\n    assert False\n")


def test_capability_with_no_tests_is_pending_not_complete(tmp_path):
    roadmap_path = _write_roadmap(tmp_path, textwrap.dedent("""\
        - id: 1
          name: "P1"
          description: "d"
          capabilities:
            - id: cap.a
              description: "not implemented yet"
              test_paths: []
        """))
    progress = compute_progress(str(tmp_path), roadmap_path=roadmap_path)
    phase = progress.phase(1)
    assert phase.status == PHASE_NOT_STARTED
    assert phase.percent == 0.0
    assert phase.capabilities[0].status == "PENDING"


def test_capability_with_passing_tests_is_complete_and_phase_completes(tmp_path):
    _write_passing_test(tmp_path, "test_a.py")
    roadmap_path = _write_roadmap(tmp_path, textwrap.dedent("""\
        - id: 1
          name: "P1"
          description: "d"
          capabilities:
            - id: cap.a
              description: "implemented"
              test_paths: ["test_a.py"]
        """))
    progress = compute_progress(str(tmp_path), roadmap_path=roadmap_path)
    phase = progress.phase(1)
    assert phase.status == PHASE_COMPLETE
    assert phase.percent == 100.0
    assert phase.completed == ["cap.a"]
    assert progress.total_tests_failed == 0
    assert progress.total_tests_passed >= 1


def test_capability_entirely_failing_is_pending_not_complete(tmp_path):
    """'A phase is not complete merely because code exists' - a capability
    whose only test is currently RED must never read as COMPLETE."""
    _write_failing_test(tmp_path, "test_b.py")
    roadmap_path = _write_roadmap(tmp_path, textwrap.dedent("""\
        - id: 1
          name: "P1"
          description: "d"
          capabilities:
            - id: cap.b
              description: "broken"
              test_paths: ["test_b.py"]
        """))
    progress = compute_progress(str(tmp_path), roadmap_path=roadmap_path)
    phase = progress.phase(1)
    assert phase.capabilities[0].status == "PENDING"
    assert phase.status == PHASE_NOT_STARTED
    assert progress.total_tests_failed >= 1


def test_capability_partially_passing_is_in_progress_not_complete(tmp_path):
    (tmp_path / "test_c.py").write_text(
        "def test_ok():\n    assert True\n\n\ndef test_bad():\n    assert False\n"
    )
    roadmap_path = _write_roadmap(tmp_path, textwrap.dedent("""\
        - id: 1
          name: "P1"
          description: "d"
          capabilities:
            - id: cap.c
              description: "half-working"
              test_paths: ["test_c.py"]
        """))
    progress = compute_progress(str(tmp_path), roadmap_path=roadmap_path)
    phase = progress.phase(1)
    assert phase.capabilities[0].status == "IN_PROGRESS"
    assert phase.status == PHASE_IN_PROGRESS
    assert progress.total_tests_failed >= 1


def test_mixed_phase_is_in_progress_percent_reflects_only_completed(tmp_path):
    _write_passing_test(tmp_path, "test_a.py")
    roadmap_path = _write_roadmap(tmp_path, textwrap.dedent("""\
        - id: 1
          name: "P1"
          description: "d"
          capabilities:
            - id: cap.a
              description: "done"
              test_paths: ["test_a.py"]
            - id: cap.b
              description: "not started"
              test_paths: []
        """))
    progress = compute_progress(str(tmp_path), roadmap_path=roadmap_path)
    phase = progress.phase(1)
    assert phase.status == PHASE_IN_PROGRESS
    assert phase.percent == 50.0
    assert phase.completed == ["cap.a"]
    assert phase.pending == ["cap.b"]


def test_fully_blocked_phase_reads_as_blocked(tmp_path):
    roadmap_path = _write_roadmap(tmp_path, textwrap.dedent("""\
        - id: 1
          name: "P1"
          description: "d"
          capabilities:
            - id: cap.a
              description: "env-blocked"
              test_paths: []
              blocked: true
              blocked_reason: "tool not installed"
        """))
    progress = compute_progress(str(tmp_path), roadmap_path=roadmap_path)
    phase = progress.phase(1)
    assert phase.status == PHASE_BLOCKED
    assert phase.blocked == ["cap.a"]
    assert phase.capabilities[0].reason == "tool not installed"


def test_phase_complete_promotes_to_verified_only_with_explicit_event(tmp_path):
    _write_passing_test(tmp_path, "test_a.py")
    roadmap_path = _write_roadmap(tmp_path, textwrap.dedent("""\
        - id: 1
          name: "P1"
          description: "d"
          capabilities:
            - id: cap.a
              description: "done"
              test_paths: ["test_a.py"]
        """))
    store = StateStore(str(tmp_path / "state.db"))

    progress_before = compute_progress(str(tmp_path), roadmap_path=roadmap_path, store=store)
    assert progress_before.phase(1).status == PHASE_COMPLETE  # not VERIFIED yet

    record_phase_verified(store, phase_id=1, verified_by="test-operator")
    progress_after = compute_progress(str(tmp_path), roadmap_path=roadmap_path, store=store)
    assert progress_after.phase(1).status == PHASE_VERIFIED


def test_overall_percent_is_average_of_phase_percents(tmp_path):
    _write_passing_test(tmp_path, "test_a.py")
    roadmap_path = _write_roadmap(tmp_path, textwrap.dedent("""\
        - id: 1
          name: "P1"
          description: "d"
          capabilities:
            - id: cap.a
              description: "done"
              test_paths: ["test_a.py"]
        - id: 2
          name: "P2"
          description: "d"
          capabilities:
            - id: cap.b
              description: "not started"
              test_paths: []
        """))
    progress = compute_progress(str(tmp_path), roadmap_path=roadmap_path)
    assert progress.overall_percent == 50.0  # (100 + 0) / 2


def _fake_progress(phase_statuses: dict[int, str], total_tests_failed: int = 0):
    from aep.progress.calculator import PhaseProgress
    phases = [
        PhaseProgress(id=i, name=f"P{i}", description="", status=status, percent=100.0
                       if status in (PHASE_COMPLETE, PHASE_VERIFIED) else 0.0)
        for i, status in phase_statuses.items()
    ]
    from aep.progress.calculator import PlatformProgress
    return PlatformProgress(overall_percent=0.0, phases=phases, total_tests_passed=1,
                             total_tests_failed=total_tests_failed)


def test_deployability_not_deployable_when_phase1_incomplete():
    progress = _fake_progress({1: PHASE_IN_PROGRESS})
    result = compute_deployability(progress)
    assert result.level == NOT_DEPLOYABLE
    assert any("Phase 1" in b for b in result.blockers)


def test_deployability_not_deployable_when_tests_failing():
    progress = _fake_progress({1: PHASE_COMPLETE, 2: PHASE_COMPLETE, 3: PHASE_COMPLETE,
                                 4: PHASE_NOT_STARTED, 5: PHASE_NOT_STARTED, 6: PHASE_NOT_STARTED,
                                 7: PHASE_NOT_STARTED, 8: PHASE_NOT_STARTED, 9: PHASE_NOT_STARTED},
                                total_tests_failed=3)
    result = compute_deployability(progress)
    assert result.level == NOT_DEPLOYABLE
    assert any("3 test(s)" in b for b in result.blockers)


def test_deployability_development_ready_with_only_phase1():
    progress = _fake_progress({1: PHASE_COMPLETE, 2: PHASE_NOT_STARTED, 3: PHASE_NOT_STARTED,
                                 4: PHASE_NOT_STARTED, 5: PHASE_NOT_STARTED, 6: PHASE_NOT_STARTED,
                                 7: PHASE_NOT_STARTED, 8: PHASE_NOT_STARTED, 9: PHASE_NOT_STARTED})
    result = compute_deployability(progress)
    assert result.level == DEVELOPMENT_READY


def test_deployability_integration_ready_with_phase1_and_2():
    progress = _fake_progress({1: PHASE_COMPLETE, 2: PHASE_VERIFIED, 3: PHASE_IN_PROGRESS,
                                 4: PHASE_NOT_STARTED, 5: PHASE_NOT_STARTED, 6: PHASE_NOT_STARTED,
                                 7: PHASE_NOT_STARTED, 8: PHASE_NOT_STARTED, 9: PHASE_NOT_STARTED})
    result = compute_deployability(progress)
    assert result.level == INTEGRATION_READY
    assert any("Phase 3" in b for b in result.blockers)


def test_deployability_never_production_candidate_without_live_github_verification():
    progress = _fake_progress({1: PHASE_COMPLETE, 2: PHASE_COMPLETE, 3: PHASE_COMPLETE,
                                 4: PHASE_COMPLETE, 5: PHASE_COMPLETE, 6: PHASE_COMPLETE,
                                 7: PHASE_NOT_STARTED, 8: PHASE_NOT_STARTED, 9: PHASE_NOT_STARTED})
    result = compute_deployability(progress, live_github_verified=False)
    assert result.level == STAGING_READY  # capped, never reaches PRODUCTION_CANDIDATE
    assert any("Live GitHub" in b for b in result.blockers)


def test_deployability_reaches_production_candidate_when_all_gates_real():
    progress = _fake_progress({1: PHASE_VERIFIED, 2: PHASE_VERIFIED, 3: PHASE_VERIFIED,
                                 4: PHASE_VERIFIED, 5: PHASE_VERIFIED, 6: PHASE_VERIFIED,
                                 7: PHASE_NOT_STARTED, 8: PHASE_NOT_STARTED, 9: PHASE_NOT_STARTED})
    result = compute_deployability(progress, live_github_verified=True, live_cve_feed_verified=True)
    assert result.level == PRODUCTION_CANDIDATE
