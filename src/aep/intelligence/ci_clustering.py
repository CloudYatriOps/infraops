"""Phase 10 Wave 11: CI failure clustering.

**Honest finding (checked before writing any clustering logic):** this
schema does not persist CI run/build/test-failure records anywhere.
Checked:
  * `src/aep/cicd/models.py` - `CIRun`/`CIStatusResult` are in-process
    dataclasses returned by a provider call (`CIRun.jobs` is a raw
    per-call list of dicts), never written to any repository/table.
  * `src/aep/cicd/failure_classification.py` - `classify_ci_failure()`
    classifies a single CI failure's job/step data at call time; it does
    not store a failure fingerprint anywhere for later clustering.
  * `src/aep/migrations_sql/*.sql` - no `ci_runs`/`ci_jobs`/
    `build_failures` table exists in any migration.
  * `incident_patterns.py` already documented this exact gap:
    `CI_FAILURE_CLUSTER` is listed in its signal vocabulary but "never
    emitted - no CI-run data in schema"; `deployment_risk.py` and
    `architecture.py` repeat the same honest omission.

Phase 6 CI/CD (`src/aep/cicd/`) triggers/orchestrates CI runs and
classifies a failure in the moment - it does not store a
failure-signature history across runs/projects. There is therefore no
real evidence to cluster.

Rather than reimplementing a second CI engine or inventing fixture data,
`analyze_ci_clusters()` returns a single, explicit `NOT_IMPLEMENTED`
result with the reason above - honestly reporting this is the wave's
correct, tested, documented outcome.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

STATUS_NOT_IMPLEMENTED = "NOT_IMPLEMENTED"

_REASON = (
    "no CI run/failure-signature evidence is persisted in this schema; "
    "Phase 6 CI/CD (src/aep/cicd/) triggers/orchestrates runs and classifies a failure "
    "in the moment (failure_classification.py) but does not store failure fingerprints "
    "across runs/projects for clustering. Checked: src/aep/cicd/models.py (CIRun is an "
    "in-process dataclass, never persisted), src/aep/migrations_sql/*.sql (no ci_runs table), "
    "and incident_patterns.py's own pre-existing CI_FAILURE_CLUSTER omission."
)


@dataclass
class CIClusterResult:
    status: str
    reason: str
    clusters: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"status": self.status, "reason": self.reason, "clusters": self.clusters}


def analyze_ci_clusters(
    project_ids: Optional[list[str]] = None,
    **_ignored,
) -> CIClusterResult:
    """Always returns a `NOT_IMPLEMENTED` `CIClusterResult` - see module
    docstring for the investigation. Accepts (and ignores) the same
    kind of optional kwargs other Wave modules accept, so the CLI/API
    call sites can follow the identical shape/convention as
    `analyze_technical_debt()`/`find_cross_project_insights()` without a
    special case."""
    return CIClusterResult(status=STATUS_NOT_IMPLEMENTED, reason=_REASON, clusters=[])


def ci_cluster_result_to_dict(item: CIClusterResult) -> dict:
    return item.to_dict()


if __name__ == "__main__":
    # ponytail: smallest self-check, not a full test suite.
    result = analyze_ci_clusters()
    assert result.status == STATUS_NOT_IMPLEMENTED
    assert result.clusters == []
    print("ok:", result.to_dict())
