"""Project Analysis Productization: `aep.scan_lifecycle` persists `aep
scan`'s results as a real, restart-surviving scan run instead of a
one-shot in-memory report. Reuses the existing Terraform fixture
(`tests/fixtures/infra/terraform`, already proven to trigger
TF_STATE_LOCAL_BACKEND in test_infra_terraform.py) so this exercises the
SAME real finding the WINFOTEST acceptance check does, not a synthetic
one invented for this file.
"""
from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from aep import scan_lifecycle
from aep.db.factory import build_state_store
from aep.db.models import ProjectRecord
from aep.db.postgres import ConnectionPool, PostgresProjectRepository
from aep.db.state_store_postgres import dsn_from_env
from aep.models import TaskStatus

FIXTURE = str(Path(__file__).resolve().parent / "fixtures" / "infra" / "terraform")


@pytest.fixture()
def project(tmp_path):
    pool = ConnectionPool(dsn_from_env())
    store = build_state_store(str(tmp_path / "state.db"))
    proj_repo = PostgresProjectRepository(pool)
    pid = str(uuid.uuid4())
    proj_repo.save(ProjectRecord(id=pid, name=f"scan-lifecycle-{pid[:8]}", repo_path=FIXTURE, policy_path="x"))
    yield pool, store, proj_repo, pid


def test_analysis_state_never_scanned_before_any_run():
    assert scan_lifecycle.analysis_state(None) == "NEVER_SCANNED"


def test_analysis_state_distinguishes_clean_from_findings():
    from aep.models import Task
    running = Task(id="t", type="project_scan", project_id="p", status=TaskStatus.RUNNING)
    succeeded = Task(id="t", type="project_scan", project_id="p", status=TaskStatus.SUCCEEDED)
    failed = Task(id="t", type="project_scan", project_id="p", status=TaskStatus.FAILED)
    assert scan_lifecycle.analysis_state(running) == "SCANNING"
    assert scan_lifecycle.analysis_state(succeeded, finding_count=0) == "COMPLETED"
    assert scan_lifecycle.analysis_state(succeeded, finding_count=1) == "COMPLETED_WITH_FINDINGS"
    assert scan_lifecycle.analysis_state(failed) == "FAILED"


def test_run_scan_persists_findings_across_a_fresh_lookup(project):
    """The actual product requirement (spec Part 5/6): a scan result must
    be visible after browser refresh / restart, i.e. from a query that
    knows nothing about the Python objects `run_scan` used internally."""
    pool, store, proj_repo, pid = project
    result = scan_lifecycle.run_scan(pool, store, pid, FIXTURE)
    assert result["status"] == "SUCCEEDED"
    assert result["analysis_state"] == "COMPLETED_WITH_FINDINGS"
    assert result["finding_count"] >= 1

    # Fresh repository objects, same as a brand-new request/process would use.
    fresh_pool = ConnectionPool(dsn_from_env())
    fresh_store = build_state_store("fresh-lookup.db")
    detail = scan_lifecycle.get_scan_run(fresh_pool, fresh_store, pid, result["task_id"])
    assert detail is not None
    assert len(detail["findings"]) == result["finding_count"]
    assert any(f["category"] == "iac" for f in detail["findings"])
    assert detail["report"]["security_readiness"] in ("NOT_READY", "READY", "INCOMPLETE")


def test_rerun_creates_a_new_run_and_preserves_the_old_one(project):
    pool, store, proj_repo, pid = project
    first = scan_lifecycle.run_scan(pool, store, pid, FIXTURE)
    second = scan_lifecycle.run_scan(pool, store, pid, FIXTURE)
    assert first["task_id"] != second["task_id"]

    runs = scan_lifecycle.list_scan_runs(pool, store, pid)
    assert len(runs) == 2
    # Old run's own detail is still fully retrievable, unmodified.
    old_detail = scan_lifecycle.get_scan_run(pool, store, pid, first["task_id"])
    assert old_detail["scan_id"] == first["task_id"]
    assert old_detail["finding_count"] == first["finding_count"]


def test_compare_scan_runs_reports_unchanged_for_an_unmodified_repo(project):
    pool, store, proj_repo, pid = project
    scan_lifecycle.run_scan(pool, store, pid, FIXTURE)
    scan_lifecycle.run_scan(pool, store, pid, FIXTURE)
    comparison = scan_lifecycle.compare_scan_runs(pool, store, pid)
    assert comparison is not None
    assert comparison["new_findings"] == []
    assert comparison["resolved_findings"] == []
    assert len(comparison["unchanged"]) >= 1


def test_compare_scan_runs_none_with_fewer_than_two_runs(project):
    pool, store, proj_repo, pid = project
    assert scan_lifecycle.compare_scan_runs(pool, store, pid) is None
    scan_lifecycle.run_scan(pool, store, pid, FIXTURE)
    assert scan_lifecycle.compare_scan_runs(pool, store, pid) is None


def test_run_scan_on_nonexistent_path_reports_incomplete_never_a_silent_clean_pass(project):
    """A scanner failure must never present as PASS (BUGFIX.md governance
    example). `scan_project()` itself never raises for a bad path - it
    reports `UNKNOWN` capabilities and marks the report `INCOMPLETE`
    (real, existing behavior, confirmed live before writing this test).
    The API layer validates the path BEFORE ever calling `run_scan` (see
    `app.py::_validated_repo_path`), so this exercises the defense-in-depth
    case: even bypassing that, the persisted report must stay honest
    about not having actually scanned anything - never silently promoted
    to a clean COMPLETED/READY result."""
    pool, store, proj_repo, pid = project
    result = scan_lifecycle.run_scan(pool, store, pid, str(Path(FIXTURE) / "does-not-exist"))
    assert result["status"] == "SUCCEEDED"  # the scan operation itself didn't crash
    assert result["report"]["security_readiness"] == "INCOMPLETE"  # but the ANALYSIS is honestly incomplete
    assert result["report"]["project"]["capabilities"] == ["UNKNOWN"]
    assert result["report"]["project"]["unreadable"]


def test_archive_hides_project_but_keeps_scan_history_queryable(project):
    pool, store, proj_repo, pid = project
    scan_lifecycle.run_scan(pool, store, pid, FIXTURE)
    assert proj_repo.archive(pid) is True
    assert pid not in {p.id for p in proj_repo.list()}
    assert pid in {p.id for p in proj_repo.list(include_archived=True)}
    # Retention: archiving a project must never touch its scan history.
    assert len(scan_lifecycle.list_scan_runs(pool, store, pid)) == 1


def test_render_markdown_report_distinguishes_sections(project):
    pool, store, proj_repo, pid = project
    scan_lifecycle.run_scan(pool, store, pid, FIXTURE)
    latest = scan_lifecycle.latest_scan_run(pool, store, pid)
    md = scan_lifecycle.render_markdown_report("fixture-project", FIXTURE, latest)
    assert "## Security posture" in md
    assert "## Findings" in md
    assert "## Recommendation" in md
    assert "AEP made no changes" in md
