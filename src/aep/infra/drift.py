"""Infrastructure drift detection (Phase 5 Part 7).

Compares DESIRED state (what the repository declares) against ACTUAL state
(what a `CloudProviderAdapter` reports from a live, read-only discovery)
and produces a `DriftReport` plus a remediation PLAN.

It never reconciles. `DriftReport.reconciled` is hard-coded `False` and
nothing in this module writes anywhere - Part 7 says "Do not automatically
reconcile production infrastructure yet", and Part 6 forbids the platform
from mutating live infrastructure without explicit approval. The output is
a plan a human executes, and the plan text says so.

Three drift kinds, all of which matter for different reasons:
  - `drift`      - the resource exists in both, but an attribute differs.
  - `unmanaged`  - the resource exists live but nothing in the repository
                   declares it. These are the ones that bite: nobody
                   reviews them, Terraform will not fix them, and they are
                   invisible to every repository-level scanner this
                   platform has.
  - `missing`    - declared in the repository but absent live (usually
                   "not applied yet", occasionally "deleted out of band").

Security-relevant drift is flagged separately from cosmetic drift, because
a changed tag and a disabled encryption setting are not the same event.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from .models import DriftItem, DriftReport

# Attribute names whose divergence is a security event rather than a
# configuration detail. Provider-agnostic: these are the concept names the
# `CloudProviderAdapter` contract normalizes to, not raw provider fields.
_SECURITY_ATTRIBUTES = {
    "public", "public_access", "encryption", "encrypted", "kms_key", "tls",
    "policy", "iam_policy", "role", "permissions", "ingress", "egress", "cidr",
    "logging", "audit_logging", "backup", "backup_retention", "versioning",
    "mfa_delete", "network_acl", "security_groups",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_security_relevant(attribute: str) -> bool:
    normalized = attribute.lower()
    return any(marker in normalized for marker in _SECURITY_ATTRIBUTES)


def compare_state(desired: dict[str, dict], actual: dict[str, dict], source: str,
                   compared_at: Optional[str] = None) -> DriftReport:
    """`desired`/`actual` are {resource_id: {attribute: value}} maps.

    The caller builds `desired` from the repository (e.g. parsed Terraform)
    and `actual` from a read-only `CloudProviderAdapter` call. Keeping this
    function a pure dict comparison is deliberate: it makes drift logic
    fully testable without any cloud access, and keeps every
    provider-specific concern in the adapter where it belongs.
    """
    report = DriftReport(source=source, compared_at=compared_at or _now())

    for resource_id in sorted(set(desired) | set(actual)):
        desired_attributes = desired.get(resource_id)
        actual_attributes = actual.get(resource_id)

        if desired_attributes is None:
            report.items.append(DriftItem(
                resource_id=resource_id, kind="unmanaged", desired=None,
                actual=f"{len(actual_attributes)} attribute(s) observed live",
                security_relevant=True,
                detail=f"{resource_id} exists in {source} but is not declared anywhere in the "
                       f"repository - it is outside code review, outside this platform's "
                       f"repository scanners, and will not be corrected by re-applying the "
                       f"configuration",
            ))
            continue

        if actual_attributes is None:
            report.items.append(DriftItem(
                resource_id=resource_id, kind="missing", desired="declared in repository",
                actual=None, security_relevant=False,
                detail=f"{resource_id} is declared in the repository but was not found in "
                       f"{source} - most likely not applied yet; confirm before treating this as "
                       f"an out-of-band deletion",
            ))
            continue

        for attribute in sorted(set(desired_attributes) | set(actual_attributes)):
            desired_value = desired_attributes.get(attribute, "<absent>")
            actual_value = actual_attributes.get(attribute, "<absent>")
            if desired_value == actual_value:
                continue
            security_relevant = _is_security_relevant(attribute)
            report.items.append(DriftItem(
                resource_id=f"{resource_id}.{attribute}", kind="drift",
                desired=str(desired_value), actual=str(actual_value),
                security_relevant=security_relevant,
                detail=(f"{'SECURITY-RELEVANT: ' if security_relevant else ''}"
                        f"{resource_id}.{attribute} is {actual_value!r} live but {desired_value!r} "
                        f"in the repository"),
            ))

    report.remediation_plan = build_remediation_plan(report)
    return report


def build_remediation_plan(report: DriftReport) -> list[str]:
    """Produces an ordered, human-executable plan. Every entry is an
    instruction for a person, never an action this platform takes: Part 7
    is explicit that reconciliation does not happen in this phase."""
    plan: list[str] = []
    security_items = [i for i in report.items if i.security_relevant]
    unmanaged = [i for i in report.items if i.kind == "unmanaged"]
    drifted = [i for i in report.items if i.kind == "drift"]
    missing = [i for i in report.items if i.kind == "missing"]

    if not report.items:
        return ["no drift detected between the repository and " + report.source]

    if security_items:
        plan.append(
            f"1. TRIAGE FIRST ({len(security_items)} security-relevant difference(s)): "
            + "; ".join(i.resource_id for i in security_items[:8])
            + " - a live security setting differs from what the repository declares, so the "
              "repository's own scanners are reporting on a configuration that is not what is "
              "actually running."
        )
    if unmanaged:
        plan.append(
            f"{len(plan) + 1}. IMPORT OR DELETE {len(unmanaged)} unmanaged resource(s): "
            + "; ".join(i.resource_id for i in unmanaged[:8])
            + " - either import them into the configuration so they are reviewed and scanned, or "
              "remove them. Deleting live resources is DENY-by-default in this platform's policy "
              "and requires explicit human action outside it."
        )
    if drifted:
        plan.append(
            f"{len(plan) + 1}. RECONCILE {len(drifted)} drifted attribute(s) by deciding, per "
            f"attribute, whether the repository or the live value is correct - then either update "
            f"the configuration or re-apply it. This platform does NOT choose for you and does NOT "
            f"apply."
        )
    if missing:
        plan.append(
            f"{len(plan) + 1}. CONFIRM {len(missing)} declared-but-absent resource(s) are simply "
            f"unapplied rather than deleted out of band."
        )
    plan.append(
        f"{len(plan) + 1}. NOTE: nothing above was executed. `terraform apply` and any live "
        f"infrastructure mutation are REQUIRE_APPROVAL/DENY under this platform's policy "
        f"(config/policy.yaml) and are out of scope for Phase 5."
    )
    return plan


def desired_state_from_terraform(project_root: str) -> dict[str, dict]:
    """Builds a desired-state map from the repository's Terraform, using
    the same in-process HCL2 parse the deep scanner uses (no `terraform`
    binary, which is BLOCKED here).

    Honest limitation, stated because it changes what drift means: this
    reads the *configuration*, not a `terraform plan` or state file. An
    attribute whose value is a variable/interpolation cannot be resolved
    statically and is recorded as `<computed>`, which `compare_state`
    treats as different from any concrete live value. Callers comparing
    against a real cloud should filter those out or accept the noise -
    `DriftItem.detail` makes the `<computed>` case visible rather than
    silent.
    """
    import io
    from pathlib import Path

    try:
        import hcl2
    except ImportError:
        return {}

    desired: dict[str, dict] = {}
    root = Path(project_root)
    for tf_file in sorted(root.rglob("*.tf")):
        if ".terraform" in tf_file.parts:
            continue
        try:
            parsed = hcl2.load(io.StringIO(tf_file.read_text()))
        except Exception:  # noqa: BLE001 - unparseable files are skipped here; the deep
            continue       # scanner already reports them as a real finding
        for block in parsed.get("resource", []) or []:
            for resource_type, bodies in block.items():
                for name, body in (bodies if isinstance(bodies, dict) else {}).items():
                    if not isinstance(body, dict):
                        continue
                    attributes = {}
                    for key, value in body.items():
                        if key.startswith("__"):
                            continue
                        unwrapped = value[0] if isinstance(value, list) and len(value) == 1 else value
                        if isinstance(unwrapped, str) and ("${" in unwrapped
                                                            or unwrapped.startswith(
                                                                ("var.", "local.", "data."))):
                            attributes[key] = "<computed>"
                        elif isinstance(unwrapped, (str, int, float, bool)):
                            attributes[key] = unwrapped
                    desired[f"{resource_type}.{name}"] = attributes
    return desired
