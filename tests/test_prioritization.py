"""Phase 10 Wave 1: deterministic cross-project prioritization tests.

Uses the same `FakeFindingRepository`/`FakeProjectRepository` doubles the
rest of the fast unit-test suite already uses - zero network/Postgres
dependency, matching the pattern.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aep.db.fake import FakeFindingRepository, FakeProjectRepository
from aep.db.models import FindingRecord, ProjectRecord, MemoryRecord
from aep.intelligence.prioritization import (
    WEIGHT_SLA,
    prioritized_finding_to_dict,
    rank_findings,
)


def _project(project_id: str, posture: str = "allow") -> ProjectRecord:
    return ProjectRecord(id=project_id, name=project_id, repo_path="/tmp/x",
                          policy_path="config/policy.yaml", default_posture=posture)


def _finding(id_, project_id, category, severity, days_old, resource=None,
             status="OPEN", evidence=None) -> FindingRecord:
    discovered = datetime.now(timezone.utc) - timedelta(days=days_old)
    return FindingRecord(
        id=id_, project_id=project_id, category=category, severity=severity, status=status,
        resource=resource, description=f"{category} finding", evidence=evidence or {},
        discovered_at=discovered, updated_at=discovered,
    )


@pytest.fixture
def repos():
    projects = FakeProjectRepository()
    projects.save(_project("proj-a", posture="deny"))   # treated as production per heuristic
    projects.save(_project("proj-b", posture="allow"))
    findings = FakeFindingRepository()
    return projects, findings


def test_higher_severity_and_prod_impact_outranks_low_severity_dev_finding(repos):
    projects, findings = repos
    # A: critical, production (proj-a is deny-posture), old, recurring
    a = _finding("f-a", "proj-a", "sql_injection", "critical", days_old=40,
                 resource="api-gateway")
    # B: low severity, non-production, brand new, one-off
    b = _finding("f-b", "proj-b", "lint_style", "low", days_old=0, resource="scripts/x.py")
    findings.save(a)
    findings.save(b)

    ranked = rank_findings(findings, projects)
    assert [r.finding_id for r in ranked] == ["f-a", "f-b"]
    assert ranked[0].rank == 1
    assert ranked[0].score > ranked[1].score


def test_ordering_across_three_findings_two_projects_is_unambiguous(repos):
    projects, findings = repos
    # Clearly ordered by combined severity/age/recurrence/production signal.
    top = _finding("top", "proj-a", "exposed_secret", "critical", days_old=60,
                    resource="prod-db", evidence={"environment": "production"})
    mid = _finding("mid", "proj-a", "exposed_secret", "high", days_old=10, resource="prod-db")
    # recurrence bump for "exposed_secret" category on proj-a
    recur = _finding("recur", "proj-a", "exposed_secret", "medium", days_old=5,
                      status="REMEDIATED", resource="prod-db")
    low = _finding("low", "proj-b", "unused_import", "low", days_old=1, resource="util.py")
    for f in (top, mid, recur, low):
        findings.save(f)

    ranked = rank_findings(findings, projects)
    ids = [r.finding_id for r in ranked]
    # "recur" is RESOLVED so excluded from the default OPEN-only ranking.
    assert "recur" not in ids
    assert ids == ["top", "mid", "low"]


def test_breakdown_present_and_sums_to_score(repos):
    projects, findings = repos
    f = _finding("only", "proj-a", "misconfig", "high", days_old=15, resource="svc")
    findings.save(f)

    ranked = rank_findings(findings, projects)
    item = ranked[0]
    factors = {"severity", "risk", "production_impact", "recurrence", "age", "blast_radius", "sla"}
    assert set(item.breakdown.keys()) == factors
    total_from_breakdown = sum(v["contribution"] for v in item.breakdown.values())
    assert total_from_breakdown == pytest.approx(item.score)
    for factor, entry in item.breakdown.items():
        assert set(entry.keys()) >= {"raw", "score", "weight", "contribution"}


def test_sla_factor_is_an_explicit_documented_no_op(repos):
    projects, findings = repos
    f = _finding("f", "proj-a", "cat", "medium", days_old=1)
    findings.save(f)
    ranked = rank_findings(findings, projects)
    assert WEIGHT_SLA == 0.0
    assert ranked[0].breakdown["sla"]["weight"] == 0.0
    assert ranked[0].breakdown["sla"]["contribution"] == 0.0
    assert "note" in ranked[0].breakdown["sla"]


def test_project_filter(repos):
    projects, findings = repos
    findings.save(_finding("a", "proj-a", "x", "high", days_old=1))
    findings.save(_finding("b", "proj-b", "x", "high", days_old=1))

    ranked = rank_findings(findings, projects, project_ids=["proj-b"])
    assert [r.finding_id for r in ranked] == ["b"]


def test_recurrence_increases_score(repos):
    projects, findings = repos
    solo = _finding("solo", "proj-b", "flaky_test", "medium", days_old=5)
    findings.save(solo)
    ranked_before = rank_findings(findings, projects)
    solo_score_before = ranked_before[0].score

    # Add two more findings in the same (project, category) - recurrence should rise.
    findings.save(_finding("dup1", "proj-b", "flaky_test", "medium", days_old=5, status="REMEDIATED"))
    findings.save(_finding("dup2", "proj-b", "flaky_test", "medium", days_old=5, status="REMEDIATED"))
    ranked_after = rank_findings(findings, projects)
    solo_after = [r for r in ranked_after if r.finding_id == "solo"][0]
    assert solo_after.score > solo_score_before
    assert solo_after.breakdown["recurrence"]["raw"] == 2


def test_prioritized_finding_to_dict_roundtrip(repos):
    projects, findings = repos
    findings.save(_finding("f1", "proj-a", "x", "high", days_old=1))
    ranked = rank_findings(findings, projects)
    payload = prioritized_finding_to_dict(ranked[0])
    assert payload["finding_id"] == "f1"
    assert payload["rank"] == 1
    assert "breakdown" in payload and "score" in payload


def test_no_project_repo_still_works(repos):
    _, findings = repos
    findings.save(_finding("f1", "proj-a", "x", "high", days_old=1))
    ranked = rank_findings(findings, project_repo=None)
    assert len(ranked) == 1
    # No project posture info available -> production_impact falls back to 0.0
    # unless evidence tags environment directly.
    assert ranked[0].breakdown["production_impact"]["score"] == 0.0
