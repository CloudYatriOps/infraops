"""Safe, deterministic infrastructure remediation (Phase 5 Part 9).

Same discipline as Phase 4's `security/remediation.py`, and for the same
reason: every fixer here matches an exact, verified structural shape and
returns `None` when it doesn't, so an unrecognized case becomes a
human-approval task instead of a guess. Part 9 draws the line explicitly -
deterministic repository-level issues are auto-fixable; "ambiguous
IAM/network policies" are not, and become REQUIRE_APPROVAL.

Kubernetes fixes operate on the parsed YAML document and are re-serialized
with `yaml.safe_dump`. That reformats the file (comments are lost - PyYAML
has no round-trip mode and adding a round-trip YAML dependency for
comment preservation was judged not worth it for machine-generated
remediation PRs). This is stated in the PR body rather than hidden, since
a human reviews the diff.

Terraform fixes are deliberately TEXT-level, not parse-and-reserialize:
python-hcl2 can read HCL but cannot write it back, and reconstructing HCL
from a parse tree would mangle every file it touched. So Terraform
remediation is a narrow, anchored line rewrite - the same approach Phase
3's `dependency/manifest_writer.py` uses for `requirements.txt` pins.

NOT auto-fixed anywhere in this module, by design:
  - IAM policy documents (wildcard actions/resources) - choosing the
    correct least-privilege action list requires knowing what the workload
    actually does.
  - Security-group / NetworkPolicy CIDRs - choosing the "right" restricted
    range requires operator knowledge (identical reasoning to Phase 4's
    refusal to auto-fix `CKV_AWS_24`).
  - Anything touching live infrastructure. Part 6: repository remediation
    only.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Optional

import yaml

from ..security.models import SecurityFinding

# Rule ids this module can fix. Kept as an explicit set so
# `can_remediate()` is a lookup, never a "try it and see" attempt that
# might half-apply a change.
KUBERNETES_FIXABLE = {
    "CKV_K8S_16": "privileged",
    "CKV_K8S_17": "hostPID",
    "CKV_K8S_19": "hostNetwork",
    "CKV_K8S_18": "hostIPC",
    "CKV_K8S_20": "allowPrivilegeEscalation",
    "CKV_K8S_23": "runAsNonRoot",
    "CKV_K8S_37": "drop_capabilities",
    "CKV_K8S_10": "resources",
    "CKV_K8S_11": "resources",
    "CKV_K8S_12": "resources",
    "CKV_K8S_13": "resources",
}

TERRAFORM_FIXABLE = {
    "TF_STATE_UNENCRYPTED": "backend_encrypt",
    "TF_PROVIDER_UNPINNED": "pin_provider",
}

# Conservative defaults for missing resource limits. Deliberately generous
# enough not to OOM-kill a real workload on merge, and called out in the
# PR body as values a human must tune - the security win is that a limit
# EXISTS (bounding blast radius of a runaway pod), not that this number is
# correct for any particular service.
DEFAULT_RESOURCES = {
    "requests": {"cpu": "100m", "memory": "128Mi"},
    "limits": {"cpu": "500m", "memory": "512Mi"},
}


@dataclass
class InfraRemediationPlan:
    finding_id: str
    kind: str          # "kubernetes" | "terraform"
    fix: str           # which fixer applies
    file: str
    resource: Optional[str]
    description: str
    caveat: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def can_remediate(finding: SecurityFinding) -> bool:
    rule = finding.rule_id or ""
    return rule in KUBERNETES_FIXABLE or rule in TERRAFORM_FIXABLE


# ---------------------------------------------------------------------
# Kubernetes
# ---------------------------------------------------------------------

_WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"}


def _pod_spec_of(doc: dict) -> Optional[dict]:
    kind = doc.get("kind")
    spec = doc.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec")
    template = spec.get("template") or {}
    return template.get("spec")


def _matches_resource(doc: dict, resource: Optional[str]) -> bool:
    """checkov resource ids look like `Deployment.default.insecure-app`."""
    if not resource:
        return True
    parts = resource.split(".")
    if len(parts) < 3:
        return False
    kind, namespace, name = parts[0], parts[1], ".".join(parts[2:])
    metadata = doc.get("metadata") or {}
    doc_namespace = metadata.get("namespace", "default")
    return (doc.get("kind") == kind and doc_namespace == namespace
            and str(metadata.get("name", "")) == name.split(".")[0])


def plan_kubernetes_remediation(finding: SecurityFinding,
                                 file_content: str) -> Optional[InfraRemediationPlan]:
    rule = finding.rule_id or ""
    if rule not in KUBERNETES_FIXABLE:
        return None
    try:
        documents = list(yaml.safe_load_all(file_content))
    except yaml.YAMLError:
        return None
    target = next((d for d in documents
                    if isinstance(d, dict) and d.get("kind") in _WORKLOAD_KINDS
                    and _matches_resource(d, finding.resource)), None)
    if target is None or _pod_spec_of(target) is None:
        return None

    fix = KUBERNETES_FIXABLE[rule]
    caveat = ("re-serialized with yaml.safe_dump; YAML comments and original key ordering in this "
              "file are not preserved")
    if fix == "resources":
        caveat += (f"; inserted conservative default resource requests/limits "
                   f"({DEFAULT_RESOURCES}) that a human must tune for this workload")
    return InfraRemediationPlan(
        finding_id=finding.id, kind="kubernetes", fix=fix, file=finding.file or "",
        resource=finding.resource,
        description=f"apply `{fix}` fix for {rule} on {finding.resource}",
        caveat=caveat,
    )


def apply_kubernetes_remediation(file_content: str, plan: InfraRemediationPlan) -> str:
    documents = list(yaml.safe_load_all(file_content))
    changed = False
    for doc in documents:
        if not isinstance(doc, dict) or doc.get("kind") not in _WORKLOAD_KINDS:
            continue
        if not _matches_resource(doc, plan.resource):
            continue
        pod_spec = _pod_spec_of(doc)
        if pod_spec is None:
            continue

        if plan.fix == "hostNetwork":
            pod_spec.pop("hostNetwork", None)
            changed = True
        elif plan.fix == "hostPID":
            pod_spec.pop("hostPID", None)
            changed = True
        elif plan.fix == "hostIPC":
            pod_spec.pop("hostIPC", None)
            changed = True
        else:
            for container in (pod_spec.get("containers") or []):
                security_context = container.setdefault("securityContext", {})
                if plan.fix == "privileged":
                    security_context["privileged"] = False
                    changed = True
                elif plan.fix == "allowPrivilegeEscalation":
                    security_context["allowPrivilegeEscalation"] = False
                    changed = True
                elif plan.fix == "runAsNonRoot":
                    security_context["runAsNonRoot"] = True
                    # runAsUser: 0 and runAsNonRoot: true is a contradiction
                    # the kubelet rejects at admission - fix both together
                    # or the "fix" produces an unschedulable pod.
                    if security_context.get("runAsUser") == 0:
                        security_context["runAsUser"] = 1000
                    changed = True
                elif plan.fix == "drop_capabilities":
                    capabilities = security_context.setdefault("capabilities", {})
                    capabilities.pop("add", None)
                    capabilities["drop"] = ["ALL"]
                    changed = True
                elif plan.fix == "resources":
                    resources = container.setdefault("resources", {})
                    for section, values in DEFAULT_RESOURCES.items():
                        existing = resources.setdefault(section, {})
                        for key, value in values.items():
                            existing.setdefault(key, value)
                    changed = True
    if not changed:
        raise ValueError(f"kubernetes remediation `{plan.fix}` matched no document in "
                          f"{plan.file}; refusing to write an unchanged file")
    return yaml.safe_dump_all(documents, default_flow_style=False, sort_keys=False)


# ---------------------------------------------------------------------
# Terraform (text-level, anchored)
# ---------------------------------------------------------------------

_ENCRYPT_FALSE_RE = re.compile(r'^(\s*)encrypt\s*=\s*false\s*$', re.M)


def plan_terraform_remediation(finding: SecurityFinding,
                                file_content: str) -> Optional[InfraRemediationPlan]:
    rule = finding.rule_id or ""
    if rule not in TERRAFORM_FIXABLE:
        return None
    fix = TERRAFORM_FIXABLE[rule]
    if fix == "backend_encrypt":
        if not _ENCRYPT_FALSE_RE.search(file_content):
            return None
        return InfraRemediationPlan(
            finding_id=finding.id, kind="terraform", fix=fix, file=finding.file or "",
            resource=finding.resource, description="set backend `encrypt = true`",
            caveat="anchored single-line rewrite; no other formatting is touched",
        )
    if fix == "pin_provider":
        provider = (finding.resource or "").split(".")[-1]
        if not provider:
            return None
        # Only fixable if the provider block is a simple single-line or
        # `{ source = "..." }` form we can extend without reformatting.
        pattern = re.compile(rf'^(\s*){re.escape(provider)}\s*=\s*\{{([^}}]*)\}}', re.M)
        match = pattern.search(file_content)
        if not match or "version" in match.group(2):
            return None
        return InfraRemediationPlan(
            finding_id=finding.id, kind="terraform", fix=fix, file=finding.file or "",
            resource=finding.resource,
            description=f"add a version constraint to required_providers.{provider}",
            caveat="adds a permissive `>= 0.0.0` placeholder constraint that a human MUST replace "
                   "with the intended pin; the security win is that the field now exists and is "
                   "reviewed, not that this value is correct",
        )
    return None


def apply_terraform_remediation(file_content: str, plan: InfraRemediationPlan) -> str:
    if plan.fix == "backend_encrypt":
        updated, count = _ENCRYPT_FALSE_RE.subn(r"\1encrypt = true", file_content)
        if count == 0:
            raise ValueError("terraform remediation `backend_encrypt` matched nothing; "
                              "refusing to write an unchanged file")
        return updated
    if plan.fix == "pin_provider":
        provider = (plan.resource or "").split(".")[-1]
        pattern = re.compile(rf'^(\s*)({re.escape(provider)}\s*=\s*\{{)([^}}]*)(\}})', re.M)

        def _insert(match: re.Match) -> str:
            indent, opening, body, closing = match.groups()
            separator = "\n" if "\n" in body else " "
            inner_indent = indent + "  " if separator == "\n" else ""
            addition = f'{separator}{inner_indent}version = ">= 0.0.0"'
            return f"{indent}{opening}{body.rstrip()}{addition}{separator}{indent}{closing}"

        updated, count = pattern.subn(_insert, file_content)
        if count == 0:
            raise ValueError("terraform remediation `pin_provider` matched nothing; "
                              "refusing to write an unchanged file")
        return updated
    raise ValueError(f"unknown terraform fix: {plan.fix!r}")


def plan_for(finding: SecurityFinding, file_content: str) -> Optional[InfraRemediationPlan]:
    return (plan_kubernetes_remediation(finding, file_content)
            or plan_terraform_remediation(finding, file_content))


def apply_plan(file_content: str, plan: InfraRemediationPlan) -> str:
    if plan.kind == "kubernetes":
        return apply_kubernetes_remediation(file_content, plan)
    if plan.kind == "terraform":
        return apply_terraform_remediation(file_content, plan)
    raise ValueError(f"unknown remediation kind: {plan.kind!r}")
