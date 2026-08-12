"""Release gate engine (Phase 6 Part 5).

A pure function of explicit, already-computed inputs - it does not scan,
build, or call anything itself (that is `SecurityAgent`/
`InfrastructureIntelligenceAgent`/`CIIntelligenceAgent`'s job). This keeps
the gate engine trivially testable and, more importantly, keeps the
"never fabricate a pass" rule in one place: every gate defaults to
`GateStatus.NOT_RUN`, and `NOT_RUN` never satisfies `all_required_passed`.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Optional

from .artifact import GateStatus


@dataclass
class Gate:
    name: str
    category: str  # SOURCE | DEPENDENCIES | SECURITY | INFRASTRUCTURE | CI | ARTIFACT | APPROVAL | DEPLOYMENT
    status: GateStatus = GateStatus.NOT_RUN
    required: bool = True
    detail: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class ReleaseGateResult:
    gates: list[Gate] = field(default_factory=list)

    @property
    def all_required_passed(self) -> bool:
        return all(g.status == GateStatus.PASSED for g in self.gates if g.required)

    @property
    def blockers(self) -> list[str]:
        return [f"{g.category}/{g.name}: {g.status.value}"
                + (f" - {g.detail}" if g.detail else "")
                for g in self.gates if g.required and g.status != GateStatus.PASSED]

    def to_dict(self) -> dict:
        return {"gates": [g.to_dict() for g in self.gates],
                "all_required_passed": self.all_required_passed, "blockers": self.blockers}


def _gate(name: str, category: str, passed: Optional[bool], required: bool = True,
          detail: str = "") -> Gate:
    if passed is None:
        return Gate(name, category, GateStatus.NOT_RUN, required, detail or "not evaluated")
    return Gate(name, category, GateStatus.PASSED if passed else GateStatus.FAILED, required, detail)


def evaluate_release_gates(*, tests_passed: Optional[bool] = None,
                            cve_scan_clean: Optional[bool] = None,
                            secrets_clean: Optional[bool] = None,
                            sast_clean: Optional[bool] = None,
                            iac_clean: Optional[bool] = None,
                            terraform_validated: Optional[bool] = None,
                            kubernetes_validated: Optional[bool] = None,
                            ci_pipeline_green: Optional[bool] = None,
                            artifact_built: Optional[bool] = None,
                            artifact_provenance_recorded: Optional[bool] = None,
                            required_approvals_met: Optional[bool] = None,
                            environment_policy_satisfied: Optional[bool] = None,
                            infra_required: bool = False) -> ReleaseGateResult:
    """Builds the exact eight-category example from the Phase 6 spec.
    `infra_required=False` means an infra project with no Terraform/K8s
    correctly reports those two gates as `required=False` (NOT_APPLICABLE
    in spirit) rather than blocking every non-infra release on a gate that
    has nothing to check - callers set it from real discovery output
    (`infra.discovery.discover_infrastructure(...).assets`), never
    hard-coded."""
    gates = [
        _gate("unit_tests", "SOURCE", tests_passed),
        _gate("cve_scan", "DEPENDENCIES", cve_scan_clean),
        _gate("secrets_scan", "SECURITY", secrets_clean),
        _gate("sast", "SECURITY", sast_clean),
        _gate("iac_scan", "SECURITY", iac_clean),
        _gate("terraform_validation", "INFRASTRUCTURE", terraform_validated,
              required=infra_required),
        _gate("kubernetes_validation", "INFRASTRUCTURE", kubernetes_validated,
              required=infra_required),
        _gate("pipeline_green", "CI", ci_pipeline_green),
        _gate("artifact_build", "ARTIFACT", artifact_built),
        _gate("artifact_provenance", "ARTIFACT", artifact_provenance_recorded),
        _gate("required_approvals", "APPROVAL", required_approvals_met),
        _gate("environment_policy", "DEPLOYMENT", environment_policy_satisfied),
    ]
    return ReleaseGateResult(gates=gates)
