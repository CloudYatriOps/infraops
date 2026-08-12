"""Infrastructure risk model (Phase 5 Part 8/16)."""
from __future__ import annotations

from aep.infra.models import BlastRadius, Environment, Exploitability
from aep.infra.risk import infer_blast_radius, infer_exploitability, prioritize, score_finding
from aep.security.models import SecurityCategory, SecurityFinding, SecuritySeverity


def _finding(rule_id="CKV_K8S_16", severity=SecuritySeverity.HIGH,
              category=SecurityCategory.KUBERNETES, resource="Deployment.default.app",
              file="k8s/app.yaml", finding_id=None) -> SecurityFinding:
    return SecurityFinding(
        id=finding_id or f"test:{rule_id}:{file}", scanner="test", category=category,
        severity=severity, confidence="high", file=file, line=1, resource=resource,
        description="d", evidence="e", remediation="r", rule_id=rule_id,
    )


def test_production_scores_higher_than_development():
    finding = _finding()
    production = score_finding(finding, Environment.PRODUCTION)
    development = score_finding(finding, Environment.DEVELOPMENT)
    assert production.score > development.score


def test_unknown_environment_is_neutral_not_production():
    finding = _finding()
    unknown = score_finding(finding, Environment.UNKNOWN)
    production = score_finding(finding, Environment.PRODUCTION)
    assert unknown.score < production.score


def test_severity_is_never_lowered_by_risk_context():
    """Escalation-only: a mis-inferred environment must never hide a real
    finding by demoting it."""
    critical = _finding(severity=SecuritySeverity.CRITICAL)
    scored = score_finding(critical, Environment.DEVELOPMENT,
                            blast_radius=BlastRadius.WORKLOAD,
                            exploitability=Exploitability.REQUIRES_LOCAL_ACCESS)
    assert scored.priority_severity == "critical"


def test_severity_is_escalated_by_multiple_aggravating_factors():
    finding = _finding(severity=SecuritySeverity.HIGH)
    scored = score_finding(finding, Environment.PRODUCTION,
                            blast_radius=BlastRadius.CLUSTER_WIDE,
                            exploitability=Exploitability.INTERNET_REACHABLE)
    assert scored.priority_severity == "critical"
    assert "promoted" in scored.rationale


def test_a_single_aggravating_factor_does_not_promote():
    finding = _finding(severity=SecuritySeverity.MEDIUM)
    scored = score_finding(finding, Environment.PRODUCTION,
                            blast_radius=BlastRadius.WORKLOAD,
                            exploitability=Exploitability.UNKNOWN)
    # One factor alone must not flatten the ranking by promoting everything.
    assert scored.priority_severity == "medium"


def test_blast_radius_inference_for_cluster_and_account_scope():
    assert infer_blast_radius(_finding(rule_id="CKV_K8S_49")) == BlastRadius.CLUSTER_WIDE
    assert infer_blast_radius(_finding(rule_id="TF_PROVIDER_CREDENTIAL",
                                        category=SecurityCategory.IAC,
                                        resource="provider.aws")) == BlastRadius.ACCOUNT_WIDE
    assert infer_blast_radius(
        _finding(rule_id="UNKNOWN_RULE", resource="ClusterRole.default.x")) == BlastRadius.CLUSTER_WIDE


def test_exploitability_inference_for_internet_reachable_findings():
    assert (infer_exploitability(_finding(rule_id="K8S_SERVICE_NODEPORT"))
            == Exploitability.INTERNET_REACHABLE)
    assert (infer_exploitability(_finding(rule_id="K8S_NO_NETWORK_POLICY"))
            == Exploitability.ADJACENT_NETWORK)


def test_rationale_explains_every_applied_factor():
    scored = score_finding(_finding(), Environment.PRODUCTION,
                            blast_radius=BlastRadius.CLUSTER_WIDE,
                            exploitability=Exploitability.INTERNET_REACHABLE)
    assert "environment=production" in scored.rationale
    assert "blast_radius=cluster_wide" in scored.rationale
    assert "exploitability=internet_reachable" in scored.rationale


def test_prioritize_orders_by_score_descending():
    findings = [
        _finding(rule_id="CKV_K8S_9", severity=SecuritySeverity.LOW, file="dev/app.yaml",
                 finding_id="low"),
        _finding(rule_id="CKV_K8S_16", severity=SecuritySeverity.CRITICAL, file="prod/app.yaml",
                 finding_id="crit"),
    ]
    scored = prioritize(findings, {"prod/app.yaml": Environment.PRODUCTION,
                                     "dev/app.yaml": Environment.DEVELOPMENT})
    assert scored[0][0].id == "crit"
    assert scored[0][1].score > scored[1][1].score


def test_prioritize_falls_back_to_enclosing_directory_environment():
    findings = [_finding(file="envs/prod/k8s/app.yaml")]
    scored = prioritize(findings, {"envs/prod": Environment.PRODUCTION})
    assert scored[0][1].environment == "production"


def test_findings_on_unmapped_files_are_never_assumed_production():
    findings = [_finding(file="somewhere/else.yaml")]
    scored = prioritize(findings, {"envs/prod": Environment.PRODUCTION})
    assert scored[0][1].environment == "unknown"


def test_score_is_serializable():
    import json
    scored = score_finding(_finding(), Environment.PRODUCTION)
    assert json.dumps(scored.to_dict())
