"""Infrastructure risk model (Phase 5 Part 8).

Part 8 asks for infrastructure findings to be normalized into the EXISTING
`SecurityFinding` model (they are - every `infra/scanners/*` module
returns Phase 4 `SecurityFinding`s) with additional infrastructure
context: environment, blast radius, exploitability, and a resulting
priority in which "production resources should have higher risk weighting
than development resources."

Design decision worth stating explicitly: the computed risk **never
lowers** a finding's severity below what the scanner reported. Environment
and blast radius can escalate a finding (a HIGH in production with
account-wide blast radius becomes CRITICAL priority) but a CRITICAL in a
dev directory stays CRITICAL. De-escalating on an *inferred* environment
would mean a mis-inferred path silently hides a real problem - and
`infra/discovery.py::infer_environment` is explicitly a heuristic with a
confidence, not ground truth. Escalation-only keeps the heuristic's
failure mode noisy rather than dangerous.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

from ..security.models import SecurityFinding, SecuritySeverity
from .models import BlastRadius, Environment, Exploitability

_SEVERITY_ORDER = [SecuritySeverity.INFO, SecuritySeverity.LOW, SecuritySeverity.MEDIUM,
                   SecuritySeverity.HIGH, SecuritySeverity.CRITICAL]

# Multipliers, not additive bonuses: an INFO finding in production is
# still low priority, while a HIGH one is not. Additive weighting would
# flatten that distinction.
_ENVIRONMENT_WEIGHT = {
    Environment.PRODUCTION: 2.0,
    Environment.STAGING: 1.3,
    Environment.TEST: 0.9,
    Environment.DEVELOPMENT: 0.8,
    Environment.UNKNOWN: 1.0,
}

_BLAST_RADIUS_WEIGHT = {
    BlastRadius.ACCOUNT_WIDE: 1.8,
    BlastRadius.CLUSTER_WIDE: 1.5,
    BlastRadius.NAMESPACE: 1.1,
    BlastRadius.WORKLOAD: 1.0,
    BlastRadius.UNKNOWN: 1.0,
}

_EXPLOITABILITY_WEIGHT = {
    Exploitability.INTERNET_REACHABLE: 1.6,
    Exploitability.ADJACENT_NETWORK: 1.1,
    Exploitability.REQUIRES_LOCAL_ACCESS: 0.9,
    Exploitability.UNKNOWN: 1.0,
}

_BASE_SCORE = {
    SecuritySeverity.CRITICAL: 40.0,
    SecuritySeverity.HIGH: 25.0,
    SecuritySeverity.MEDIUM: 12.0,
    SecuritySeverity.LOW: 5.0,
    SecuritySeverity.INFO: 1.0,
}

# Rule ids whose reach is inherently beyond a single workload. Keyed off
# the rule, not the resource text, so a renamed resource can't change its
# own blast radius.
_ACCOUNT_WIDE_RULES = {
    "TF_PROVIDER_CREDENTIAL", "TF_STATE_CREDENTIAL", "TF_STATE_LOCAL_BACKEND",
    "TF_STATE_UNENCRYPTED", "CKV_AWS_1", "CKV2_AWS_56",
}
_CLUSTER_WIDE_RULES = {
    "CKV_K8S_49", "CKV_K8S_155", "CKV_K8S_156", "CKV_K8S_157", "CKV_K8S_158",
    "CKV_K8S_16", "CKV_K8S_17", "CKV_K8S_18", "CKV_K8S_19", "CKV_K8S_27",
    "K8S_SERVICE_NODEPORT", "K8S_CONTAINER_HOSTPORT", "HELM_VALUES_RBAC_CLUSTERWIDE",
}
_INTERNET_REACHABLE_RULES = {
    "K8S_SERVICE_NODEPORT", "K8S_SERVICE_PUBLIC_LB", "K8S_INGRESS_NO_TLS",
    "K8S_INGRESS_SSL_REDIRECT_DISABLED", "K8S_CONTAINER_HOSTPORT",
    "CKV_AWS_24", "CKV2_AWS_6", "CKV_AWS_20", "HELM_VALUES_SERVICE_TYPE",
}
_ADJACENT_NETWORK_RULES = {
    "K8S_NO_NETWORK_POLICY", "HELM_VALUES_NETWORKPOLICY_ENABLED", "CKV_K8S_19",
}


@dataclass
class InfraRiskScore:
    finding_id: str
    base_severity: str
    priority_severity: str
    score: float
    environment: str
    blast_radius: str
    exploitability: str
    rationale: str

    def to_dict(self) -> dict:
        return asdict(self)


def infer_blast_radius(finding: SecurityFinding) -> BlastRadius:
    rule = finding.rule_id or ""
    if rule in _ACCOUNT_WIDE_RULES:
        return BlastRadius.ACCOUNT_WIDE
    if rule in _CLUSTER_WIDE_RULES:
        return BlastRadius.CLUSTER_WIDE
    resource = (finding.resource or "")
    if resource.startswith(("ClusterRole", "ClusterRoleBinding")):
        return BlastRadius.CLUSTER_WIDE
    if resource.startswith("provider.") or resource.startswith("terraform.backend"):
        return BlastRadius.ACCOUNT_WIDE
    if finding.category.value in ("kubernetes", "helm"):
        return BlastRadius.WORKLOAD
    return BlastRadius.UNKNOWN


def infer_exploitability(finding: SecurityFinding) -> Exploitability:
    rule = finding.rule_id or ""
    if rule in _INTERNET_REACHABLE_RULES:
        return Exploitability.INTERNET_REACHABLE
    if rule in _ADJACENT_NETWORK_RULES:
        return Exploitability.ADJACENT_NETWORK
    if finding.category.value in ("secret", "iac") and "CREDENTIAL" in rule:
        # A committed credential is reachable by anyone with repo access,
        # which in practice is a much larger set than "local access".
        return Exploitability.INTERNET_REACHABLE
    return Exploitability.UNKNOWN


def _escalate(base: SecuritySeverity, steps: int) -> SecuritySeverity:
    index = min(len(_SEVERITY_ORDER) - 1, _SEVERITY_ORDER.index(base) + max(0, steps))
    return _SEVERITY_ORDER[index]


def score_finding(finding: SecurityFinding, environment: Environment = Environment.UNKNOWN,
                   blast_radius: BlastRadius | None = None,
                   exploitability: Exploitability | None = None) -> InfraRiskScore:
    blast_radius = blast_radius if blast_radius is not None else infer_blast_radius(finding)
    exploitability = (exploitability if exploitability is not None
                       else infer_exploitability(finding))

    env_weight = _ENVIRONMENT_WEIGHT[environment]
    blast_weight = _BLAST_RADIUS_WEIGHT[blast_radius]
    exploit_weight = _EXPLOITABILITY_WEIGHT[exploitability]
    score = round(_BASE_SCORE[finding.severity] * env_weight * blast_weight * exploit_weight, 1)

    # Escalation-only (see module docstring): a finding is promoted by one
    # severity step per strong aggravating factor, and never demoted.
    steps = 0
    if environment == Environment.PRODUCTION:
        steps += 1
    if blast_radius in (BlastRadius.ACCOUNT_WIDE, BlastRadius.CLUSTER_WIDE):
        steps += 1
    if exploitability == Exploitability.INTERNET_REACHABLE:
        steps += 1
    # One step per TWO aggravating factors, so a single factor doesn't
    # promote everything to CRITICAL and flatten the ranking.
    priority = _escalate(finding.severity, steps // 2)

    factors = []
    if environment != Environment.UNKNOWN:
        factors.append(f"environment={environment.value} (x{env_weight})")
    if blast_radius != BlastRadius.UNKNOWN:
        factors.append(f"blast_radius={blast_radius.value} (x{blast_weight})")
    if exploitability != Exploitability.UNKNOWN:
        factors.append(f"exploitability={exploitability.value} (x{exploit_weight})")
    rationale = (f"base {finding.severity.value} (score {_BASE_SCORE[finding.severity]})"
                 + (" adjusted by " + ", ".join(factors) if factors else " with no adjusting factors")
                 + f" -> {score}"
                 + (f"; promoted to {priority.value} by {steps} aggravating factor(s)"
                    if priority != finding.severity else ""))

    return InfraRiskScore(
        finding_id=finding.id, base_severity=finding.severity.value,
        priority_severity=priority.value, score=score, environment=environment.value,
        blast_radius=blast_radius.value, exploitability=exploitability.value, rationale=rationale,
    )


def prioritize(findings: list[SecurityFinding],
                environment_for: dict[str, Environment] | None = None
                ) -> list[tuple[SecurityFinding, InfraRiskScore]]:
    """Returns findings paired with their risk score, highest score first.
    `environment_for` maps a file path to its inferred environment (built
    by the caller from the discovery inventory) - findings on files not in
    the map score as UNKNOWN environment (weight 1.0), never as
    production."""
    environment_for = environment_for or {}
    scored = []
    for finding in findings:
        env = Environment.UNKNOWN
        if finding.file:
            env = environment_for.get(finding.file, Environment.UNKNOWN)
            if env == Environment.UNKNOWN:
                # Fall back to the closest enclosing directory that has a
                # known environment - findings are reported per-file, but
                # environment is usually a property of the directory tree.
                for path, candidate in environment_for.items():
                    if finding.file.startswith(path.rstrip("/") + "/") or finding.file == path:
                        env = candidate
                        break
        scored.append((finding, score_finding(finding, env)))
    scored.sort(key=lambda pair: pair[1].score, reverse=True)
    return scored
