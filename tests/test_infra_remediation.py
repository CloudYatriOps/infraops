"""Infrastructure remediation (Phase 5 Part 9/16).

Part 9's line: deterministic repository-level issues are auto-fixed;
ambiguous IAM/network policy is not. Several tests below assert the
REFUSAL cases, because a fixer that silently does nothing and a fixer that
correctly declines are very different things.
"""
from __future__ import annotations

import pytest
import yaml

from aep.infra.remediation import (
    DEFAULT_RESOURCES, apply_plan, can_remediate, plan_for, plan_kubernetes_remediation,
    plan_terraform_remediation,
)
from aep.security.models import SecurityCategory, SecurityFinding, SecuritySeverity

_WORKLOAD = (
    "apiVersion: apps/v1\n"
    "kind: Deployment\n"
    "metadata:\n  name: app\n  namespace: default\n"
    "spec:\n"
    "  template:\n"
    "    spec:\n"
    "      hostNetwork: true\n"
    "      hostPID: true\n"
    "      containers:\n"
    "        - name: c\n"
    "          image: nginx:1.25\n"
    "          securityContext:\n"
    "            privileged: true\n"
    "            runAsUser: 0\n"
    "            allowPrivilegeEscalation: true\n"
    "            capabilities:\n"
    "              add: [\"SYS_ADMIN\"]\n"
)


def _finding(rule_id, resource="Deployment.default.app", file="k8s/app.yaml",
              category=SecurityCategory.KUBERNETES) -> SecurityFinding:
    return SecurityFinding(
        id=f"test:{rule_id}", scanner="test", category=category,
        severity=SecuritySeverity.HIGH, confidence="high", file=file, line=1, resource=resource,
        description="d", evidence="e", remediation="r", rule_id=rule_id,
    )


def _pod_spec(content: str) -> dict:
    doc = next(d for d in yaml.safe_load_all(content) if d.get("kind") == "Deployment")
    return doc["spec"]["template"]["spec"]


# ---- what is and isn't remediable ----------------------------------------

def test_can_remediate_only_the_declared_rule_set():
    assert can_remediate(_finding("CKV_K8S_16"))
    assert can_remediate(_finding("TF_STATE_UNENCRYPTED", category=SecurityCategory.IAC))
    # Wildcard RBAC needs to know what the workload actually does.
    assert not can_remediate(_finding("CKV_K8S_49"))
    # Choosing a "safe" CIDR needs operator knowledge.
    assert not can_remediate(_finding("CKV_AWS_24", category=SecurityCategory.IAC))
    assert not can_remediate(_finding("K8S_SERVICE_NODEPORT"))


def test_ambiguous_iam_findings_are_never_auto_fixed():
    for rule in ("CKV_K8S_49", "CKV_K8S_155", "CKV_K8S_158", "TF_PROVIDER_CREDENTIAL"):
        assert plan_for(_finding(rule), _WORKLOAD) is None


# ---- Kubernetes fixes ------------------------------------------------------

def test_removes_privileged():
    plan = plan_kubernetes_remediation(_finding("CKV_K8S_16"), _WORKLOAD)
    assert plan is not None
    fixed = apply_plan(_WORKLOAD, plan)
    assert _pod_spec(fixed)["containers"][0]["securityContext"]["privileged"] is False


def test_removes_host_network_and_host_pid():
    for rule, key in (("CKV_K8S_19", "hostNetwork"), ("CKV_K8S_17", "hostPID")):
        plan = plan_kubernetes_remediation(_finding(rule), _WORKLOAD)
        fixed = apply_plan(_WORKLOAD, plan)
        assert key not in _pod_spec(fixed)


def test_run_as_non_root_also_fixes_the_contradictory_run_as_user():
    """runAsNonRoot: true alongside runAsUser: 0 is rejected by the kubelet
    at admission - a "fix" that produced an unschedulable pod would be
    worse than the finding."""
    plan = plan_kubernetes_remediation(_finding("CKV_K8S_23"), _WORKLOAD)
    fixed = apply_plan(_WORKLOAD, plan)
    security_context = _pod_spec(fixed)["containers"][0]["securityContext"]
    assert security_context["runAsNonRoot"] is True
    assert security_context["runAsUser"] != 0


def test_drops_all_capabilities_and_removes_added_ones():
    plan = plan_kubernetes_remediation(_finding("CKV_K8S_37"), _WORKLOAD)
    fixed = apply_plan(_WORKLOAD, plan)
    capabilities = _pod_spec(fixed)["containers"][0]["securityContext"]["capabilities"]
    assert capabilities["drop"] == ["ALL"]
    assert "add" not in capabilities


def test_adds_resource_requests_and_limits():
    plan = plan_kubernetes_remediation(_finding("CKV_K8S_11"), _WORKLOAD)
    fixed = apply_plan(_WORKLOAD, plan)
    resources = _pod_spec(fixed)["containers"][0]["resources"]
    assert resources["requests"] == DEFAULT_RESOURCES["requests"]
    assert resources["limits"] == DEFAULT_RESOURCES["limits"]


def test_existing_resource_values_are_not_overwritten():
    content = _WORKLOAD.replace(
        "          image: nginx:1.25\n",
        "          image: nginx:1.25\n          resources:\n            limits:\n"
        "              cpu: 2\n")
    plan = plan_kubernetes_remediation(_finding("CKV_K8S_11"), content)
    fixed = apply_plan(content, plan)
    resources = _pod_spec(fixed)["containers"][0]["resources"]
    assert resources["limits"]["cpu"] == 2  # operator's value preserved
    assert "memory" in resources["limits"]  # missing one still filled in


def test_plan_carries_the_reserialization_caveat():
    plan = plan_kubernetes_remediation(_finding("CKV_K8S_16"), _WORKLOAD)
    assert "comments" in plan.caveat  # PyYAML cannot round-trip comments
    resources_plan = plan_kubernetes_remediation(_finding("CKV_K8S_11"), _WORKLOAD)
    assert "must tune" in resources_plan.caveat


def test_plan_refuses_when_the_resource_does_not_match():
    plan = plan_kubernetes_remediation(
        _finding("CKV_K8S_16", resource="Deployment.other-namespace.app"), _WORKLOAD)
    assert plan is None


def test_plan_refuses_on_unparseable_yaml():
    assert plan_kubernetes_remediation(_finding("CKV_K8S_16"), "not: [valid\n  yaml") is None


def test_apply_refuses_to_write_an_unchanged_file():
    plan = plan_kubernetes_remediation(_finding("CKV_K8S_16"), _WORKLOAD)
    other_document = (
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: unrelated\ndata:\n  a: b\n")
    with pytest.raises(ValueError):
        apply_plan(other_document, plan)


# ---- Terraform fixes -------------------------------------------------------

def test_enables_backend_encryption():
    content = ('terraform {\n  backend "s3" {\n    bucket  = "state"\n'
               "    encrypt = false\n  }\n}\n")
    finding = _finding("TF_STATE_UNENCRYPTED", resource="terraform.backend.s3",
                        file="main.tf", category=SecurityCategory.IAC)
    plan = plan_terraform_remediation(finding, content)
    fixed = apply_plan(content, plan)
    assert "encrypt = true" in fixed
    assert "encrypt = false" not in fixed


def test_backend_encryption_fix_refuses_when_the_line_is_absent():
    content = 'terraform {\n  backend "s3" {\n    bucket = "state"\n  }\n}\n'
    finding = _finding("TF_STATE_UNENCRYPTED", resource="terraform.backend.s3",
                        file="main.tf", category=SecurityCategory.IAC)
    assert plan_terraform_remediation(finding, content) is None


def test_pins_an_unpinned_provider_with_an_explicit_placeholder_caveat():
    content = ('terraform {\n  required_providers {\n'
               '    aws = {\n      source = "hashicorp/aws"\n    }\n  }\n}\n')
    finding = _finding("TF_PROVIDER_UNPINNED", resource="required_providers.aws",
                        file="main.tf", category=SecurityCategory.IAC)
    plan = plan_terraform_remediation(finding, content)
    assert plan is not None
    assert "MUST replace" in plan.caveat
    fixed = apply_plan(content, plan)
    assert "version" in fixed


def test_already_pinned_provider_is_not_touched():
    content = ('terraform {\n  required_providers {\n'
               '    aws = {\n      source = "hashicorp/aws"\n      version = "~> 5.0"\n    }\n'
               "  }\n}\n")
    finding = _finding("TF_PROVIDER_UNPINNED", resource="required_providers.aws",
                        file="main.tf", category=SecurityCategory.IAC)
    assert plan_terraform_remediation(finding, content) is None


def test_terraform_fixes_are_text_level_and_preserve_surrounding_formatting():
    content = ('# a comment worth keeping\n'
               'terraform {\n  backend "s3" {\n    bucket  = "state"\n'
               "    encrypt = false\n  }\n}\n")
    finding = _finding("TF_STATE_UNENCRYPTED", resource="terraform.backend.s3",
                        file="main.tf", category=SecurityCategory.IAC)
    fixed = apply_plan(content, plan_terraform_remediation(finding, content))
    # python-hcl2 can parse HCL but not write it - so Terraform fixes must
    # be anchored line rewrites, and comments must survive.
    assert "# a comment worth keeping" in fixed
