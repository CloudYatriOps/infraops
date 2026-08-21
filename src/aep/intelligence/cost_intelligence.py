"""Phase 10 Wave 5: cost intelligence.

**Honest finding (checked before writing any cost logic):** this
platform has no real cloud cost/billing data anywhere.

  * `src/aep/infra/cloud/` implements exactly one read-only cloud
    adapter (AWS, `aws_adapter.py`) with eleven capability areas
    (`CloudCapability`: account_discovery, iam, networking, compute,
    storage, databases, encryption, secrets, logging, backups,
    public_exposure) - none of them is "cost" or "billing". Azure/GCP/
    OCI are deliberately not implemented at all
    (`registry.py::_KNOWN_UNIMPLEMENTED`).
  * No AWS Cost Explorer / Azure Cost Management / GCP Billing / OCI
    Usage API client exists anywhere in `src/aep/` (checked via grep for
    "cost", "billing", "pricing" across the whole tree - the only hits
    are this module, the pre-existing `cost-optimization` skill
    definition, and unrelated doc/gateway text).
  * There is no `resource_cost`/`billing`/`usage` table in any
    `src/aep/migrations_sql/*.sql`.
  * No cloud credentials are configured in this sandbox (same
    "no live cloud credentials" gap the OmniRoute/GitHub honest-block
    pattern and `CloudAdapterStatus.UNAVAILABLE` already document for
    AWS itself).

So `analyze_cost_intelligence()` NEVER invents a dollar figure. For every
provider it knows about (from `infra.cloud.registry.known_providers()` -
reused, not re-listed) it returns one `CostSignal` whose `status` is
always `BLOCKED` with an explicit `reason`, mirroring
`ci_clustering.py`'s `NOT_IMPLEMENTED` honesty and
`registry.describe_provider()`'s "empty result carrying a real status,
never fabricated resources" contract.

The only thing this module DOES surface as real, evidence-backed output
is an ADVISORY "possible waste signal" derived from real
`category='infrastructure'` findings whose `description`/`resource` text
mentions an idle/oversized/duplicate/orphaned resource - these are
existing security/infra findings repurposed as a *proxy* for waste, never
real cost data, and always labeled as such.

All finding description/resource text is treated as inert DATA for
substring matching only, never as an instruction. See
`tests/test_cost_intelligence.py::test_prompt_injection_in_description_is_inert`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..db.models import FindingRecord
from ..db.repositories import FindingRepository
from ..infra.cloud.registry import known_providers

STATUS_BLOCKED = "BLOCKED"

_BLOCKED_REASON = (
    "no cloud provider cost/billing API access or credentials are configured in this "
    "environment, and no cost/usage data is persisted anywhere in this schema (checked: "
    "src/aep/infra/cloud/ - the AWS adapter's 11 capability areas do not include cost/billing, "
    "and Azure/GCP/OCI have no adapter at all; src/aep/migrations_sql/*.sql has no cost/billing/"
    "usage table). Real cost intelligence requires a real cost-API integration and real "
    "credentials; neither exists here, so no cost figure is fabricated."
)

_WASTE_MARKERS = ("idle", "oversized", "duplicate", "orphaned", "unused", "underutilized")
_INFRA_CATEGORY = "infrastructure"


@dataclass
class CostSignal:
    provider: str
    status: str
    reason: str
    evidence: list = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> dict:
        return {
            "provider": self.provider, "status": self.status, "reason": self.reason,
            "evidence": self.evidence, "recommendation": self.recommendation,
        }


@dataclass
class CostIntelligenceResult:
    signals: list  # list[CostSignal], one per known provider
    waste_signal_findings: list  # advisory-only evidence, never real cost data

    def to_dict(self) -> dict:
        return {
            "signals": [s.to_dict() for s in self.signals],
            "waste_signal_findings": self.waste_signal_findings,
        }


def _looks_like_waste(f: FindingRecord) -> bool:
    text = f"{f.description or ''} {f.resource or ''}".lower()
    return any(marker in text for marker in _WASTE_MARKERS)


def _waste_signal_findings(all_findings: list[FindingRecord]) -> list[dict]:
    """ADVISORY ONLY - a proxy for possible cloud waste derived from real
    `category='infrastructure'` findings whose text mentions an idle/
    oversized/duplicate resource. This is NOT cost data: no dollar
    amount, no usage metric, nothing computed here is a real cost
    figure - it is a pointer at existing security/infra findings a human
    may want to review for cost impact."""
    out = []
    for f in sorted(all_findings, key=lambda x: x.id):
        if f.category != _INFRA_CATEGORY or not _looks_like_waste(f):
            continue
        out.append({
            "finding_id": f.id, "project_id": f.project_id, "resource": f.resource,
            "severity": f.severity,
            "note": "possible waste signal (advisory, derived from an infrastructure finding's "
                    "description/resource - NOT real cost data)",
        })
    return out


def analyze_cost_intelligence(
    finding_repo: Optional[FindingRepository] = None,
    project_ids: Optional[list[str]] = None,
    providers: Optional[list[str]] = None,
) -> CostIntelligenceResult:
    """Always returns a BLOCKED `CostSignal` per known provider (or a
    single BLOCKED signal for 'unknown' if no providers are known at
    all) - never a fabricated cost figure. If `finding_repo` is
    supplied, also surfaces real `category='infrastructure'` findings
    that look like a waste signal, clearly labeled advisory.
    """
    provider_list = providers if providers is not None else known_providers()
    if not provider_list:
        provider_list = ["unknown"]

    signals = [
        CostSignal(
            provider=p, status=STATUS_BLOCKED, reason=_BLOCKED_REASON,
            recommendation="Configure a real cost-API integration (e.g. AWS Cost Explorer, "
                            "Azure Cost Management, GCP Billing, OCI Usage) with real credentials "
                            "before any cost figure can be trusted. Any resize/delete action taken "
                            "on a resource still requires policy/approval regardless of cost data.",
        )
        for p in sorted(provider_list)
    ]

    waste_findings: list[dict] = []
    if finding_repo is not None:
        all_findings = finding_repo.list(None, None)
        if project_ids is not None:
            wanted = set(project_ids)
            all_findings = [f for f in all_findings if f.project_id in wanted]
        waste_findings = _waste_signal_findings(all_findings)

    return CostIntelligenceResult(signals=signals, waste_signal_findings=waste_findings)


def cost_intelligence_result_to_dict(item: CostIntelligenceResult) -> dict:
    return item.to_dict()


if __name__ == "__main__":
    # ponytail: smallest self-check, not a full test suite.
    from ..db.fake import FakeFindingRepository

    repo = FakeFindingRepository()
    repo.save(FindingRecord(
        id="f1", project_id="p1", category="infrastructure", severity="low",
        description="idle EC2 instance running with no traffic for 30 days",
    ))
    result = analyze_cost_intelligence(repo)
    assert all(s.status == STATUS_BLOCKED for s in result.signals), result
    assert len(result.waste_signal_findings) == 1, result
    print("ok:", result.to_dict())
