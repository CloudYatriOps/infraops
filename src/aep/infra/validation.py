"""Infrastructure change validation (Phase 5 Part 10).

Part 10's requirement is "Never report infrastructure remediation as
successful without evidence." The single most important design decision in
this module is therefore the three-state result, not the two-state one:

    ran=True,  passed=True   -> validated
    ran=True,  passed=False  -> validation FAILED, remediation is rejected
    ran=False, passed=False  -> validator could not run (BLOCKED tool)

`ran=False` is NEVER treated as success anywhere. This is not theoretical
tidiness: `terraform fmt`, `terraform validate`, `helm lint`, and
`helm template` are ALL unavailable in this sandbox (the terraform and
helm binaries cannot be installed - `releases.hashicorp.com` and
`get.helm.sh` both return `000` through the egress proxy, the same block
pattern documented in §23-§25). A two-state `bool` return would have
silently reported "validated" for every Terraform and Helm remediation
this platform makes here. `validate_terraform_change()` returns
`ran=False` for those, and `infra/remediation.py` refuses to mark a
remediation verified on the strength of a validator that never executed.

What genuinely runs here instead:
  - **Terraform**: a real HCL2 structural parse (`python-hcl2`). This is
    NOT `terraform validate` and is not presented as equivalent - it
    catches syntax errors and malformed blocks (verified: it rejects
    unbalanced HCL with `UnexpectedToken`) but knows nothing about
    provider schemas, variable types, or resource references.
  - **Kubernetes**: real schema validation via `kubernetes-validate`,
    which ships the upstream Kubernetes OpenAPI schemas and needs no
    cluster. Verified during Phase 5 investigation to accept a valid
    Deployment and reject `replicas: "three"` with a type error - i.e. it
    is doing genuine schema work, not a YAML well-formedness check.
"""
from __future__ import annotations

import io
from pathlib import Path

import yaml

from .models import ValidationResult

# The Kubernetes API version whose bundled schemas are used. Pinned
# explicitly rather than "latest" so a validation result means the same
# thing across runs.
K8S_SCHEMA_VERSION = "1.28"

_TERRAFORM_BLOCKED_REASON = (
    "the `terraform` binary is not installed and cannot be obtained here "
    "(releases.hashicorp.com is unreachable through this sandbox's egress proxy, curl returns "
    "000), so `terraform fmt -check` and `terraform validate` cannot run. This is reported as "
    "ran=False, NOT as a passing validation."
)
_HELM_BLOCKED_REASON = (
    "the `helm` binary is not installed and cannot be obtained here (get.helm.sh is unreachable, "
    "curl returns 000), so `helm lint` and `helm template` cannot run. This is reported as "
    "ran=False, NOT as a passing validation."
)


# ---------------------------------------------------------------------
# Terraform
# ---------------------------------------------------------------------

def terraform_cli_available(run_shell) -> bool:
    return bool(run_shell(["terraform", "version"], timeout=10).get("ok"))


def validate_terraform_hcl(project_root: str, relative_path: str) -> ValidationResult:
    """Real, in-process HCL2 structural parse. Runs everywhere; explicitly
    weaker than `terraform validate` and labelled as such."""
    target = Path(project_root, relative_path)
    try:
        import hcl2
    except ImportError:
        return ValidationResult(
            validator="hcl2-structural", ran=False, passed=False, target=relative_path,
            detail="python-hcl2 not installed; structural parse could not run",
        )
    try:
        hcl2.load(io.StringIO(target.read_text()))
    except OSError as e:
        return ValidationResult(validator="hcl2-structural", ran=False, passed=False,
                                 target=relative_path, detail=f"could not read file: {e}")
    except Exception as e:  # noqa: BLE001 - any parse failure is a real validation failure
        return ValidationResult(
            validator="hcl2-structural", ran=True, passed=False, target=relative_path,
            detail=f"HCL2 parse failed: {type(e).__name__}: {str(e)[:200]}",
        )
    return ValidationResult(
        validator="hcl2-structural", ran=True, passed=True, target=relative_path,
        detail="file parses as valid HCL2 (structural only - this is NOT `terraform validate` "
               "and does not check provider schemas, variable types, or references)",
    )


def validate_terraform_change(project_root: str, relative_path: str,
                               run_shell) -> list[ValidationResult]:
    """Part 2's required chain: `terraform fmt` -> `terraform validate`.
    Both are attempted for real; both report ran=False here because the
    binary is BLOCKED, and the HCL2 structural parse runs alongside them
    as the strongest check this environment actually supports."""
    results = [validate_terraform_hcl(project_root, relative_path)]
    if not terraform_cli_available(run_shell):
        results.append(ValidationResult(validator="terraform fmt -check", ran=False, passed=False,
                                         target=relative_path, detail=_TERRAFORM_BLOCKED_REASON))
        results.append(ValidationResult(validator="terraform validate", ran=False, passed=False,
                                         target=relative_path, detail=_TERRAFORM_BLOCKED_REASON))
        return results

    directory = str(Path(project_root, relative_path).parent)
    fmt = run_shell(["terraform", "fmt", "-check", "-diff"], cwd=directory, timeout=60)
    results.append(ValidationResult(
        validator="terraform fmt -check", ran=True, passed=bool(fmt.get("ok")),
        target=relative_path,
        detail=(fmt.get("stdout") or fmt.get("stderr") or "")[:400] or "formatting is canonical",
    ))
    validate = run_shell(["terraform", "validate", "-no-color"], cwd=directory, timeout=120)
    results.append(ValidationResult(
        validator="terraform validate", ran=True, passed=bool(validate.get("ok")),
        target=relative_path,
        detail=(validate.get("stdout") or validate.get("stderr") or "")[:400],
    ))
    return results


# ---------------------------------------------------------------------
# Kubernetes
# ---------------------------------------------------------------------

def validate_kubernetes_manifest(project_root: str, relative_path: str,
                                  schema_version: str = K8S_SCHEMA_VERSION) -> ValidationResult:
    """Real schema validation against bundled upstream Kubernetes schemas.
    No cluster required (Part 4: "Do not require a live Kubernetes cluster
    for static analysis")."""
    target = Path(project_root, relative_path)
    try:
        import kubernetes_validate
    except ImportError:
        return ValidationResult(
            validator="kubernetes-validate", ran=False, passed=False, target=relative_path,
            detail="kubernetes-validate not installed; schema validation could not run",
        )
    try:
        raw = target.read_text()
    except OSError as e:
        return ValidationResult(validator="kubernetes-validate", ran=False, passed=False,
                                 target=relative_path, detail=f"could not read file: {e}")
    try:
        documents = [d for d in yaml.safe_load_all(raw) if isinstance(d, dict)]
    except yaml.YAMLError as e:
        return ValidationResult(
            validator="kubernetes-validate", ran=True, passed=False, target=relative_path,
            detail=f"YAML parse failed: {type(e).__name__}: {str(e)[:200]}",
        )

    problems: list[str] = []
    validated = 0
    for index, doc in enumerate(documents):
        if not doc.get("kind") or not doc.get("apiVersion"):
            continue
        try:
            kubernetes_validate.validate(doc, schema_version, strict=False)
            validated += 1
        except Exception as e:  # noqa: BLE001 - library raises several distinct error types
            problems.append(f"doc[{index}] {doc.get('kind')}/"
                             f"{(doc.get('metadata') or {}).get('name', '?')}: "
                             f"{type(e).__name__}: {str(e).splitlines()[0][:160]}")
    if not documents or validated == 0 and not problems:
        return ValidationResult(
            validator="kubernetes-validate", ran=False, passed=False, target=relative_path,
            detail="no Kubernetes documents with kind/apiVersion found to validate",
        )
    if problems:
        return ValidationResult(
            validator="kubernetes-validate", ran=True, passed=False, target=relative_path,
            detail=f"{len(problems)} schema violation(s) against Kubernetes {schema_version}: "
                   + "; ".join(problems)[:500],
        )
    return ValidationResult(
        validator="kubernetes-validate", ran=True, passed=True, target=relative_path,
        detail=f"{validated} document(s) valid against the bundled Kubernetes {schema_version} "
               f"schemas (no cluster contacted)",
    )


# ---------------------------------------------------------------------
# Helm
# ---------------------------------------------------------------------

def helm_cli_available(run_shell) -> bool:
    return bool(run_shell(["helm", "version", "--short"], timeout=10).get("ok"))


def validate_helm_chart(project_root: str, chart_path: str, run_shell) -> list[ValidationResult]:
    """Part 4's required `helm lint` + `helm template`. Both are attempted
    for real and both report ran=False here (helm binary BLOCKED). A
    real YAML parse of the chart's own `values.yaml`/`Chart.yaml` runs
    regardless, since those files are plain YAML."""
    results: list[ValidationResult] = []
    chart_dir = Path(project_root, chart_path)

    for filename in ("Chart.yaml", "values.yaml"):
        candidate = chart_dir / filename
        if not candidate.exists():
            continue
        try:
            yaml.safe_load(candidate.read_text())
            results.append(ValidationResult(
                validator=f"yaml-parse:{filename}", ran=True, passed=True,
                target=f"{chart_path}/{filename}", detail="parses as valid YAML",
            ))
        except (yaml.YAMLError, OSError, UnicodeDecodeError) as e:
            results.append(ValidationResult(
                validator=f"yaml-parse:{filename}", ran=True, passed=False,
                target=f"{chart_path}/{filename}",
                detail=f"{type(e).__name__}: {str(e)[:200]}",
            ))

    if not helm_cli_available(run_shell):
        results.append(ValidationResult(validator="helm lint", ran=False, passed=False,
                                         target=chart_path, detail=_HELM_BLOCKED_REASON))
        results.append(ValidationResult(validator="helm template", ran=False, passed=False,
                                         target=chart_path, detail=_HELM_BLOCKED_REASON))
        return results

    lint = run_shell(["helm", "lint", chart_path], cwd=project_root, timeout=60)
    results.append(ValidationResult(
        validator="helm lint", ran=True, passed=bool(lint.get("ok")), target=chart_path,
        detail=(lint.get("stdout") or lint.get("stderr") or "")[:400],
    ))
    template = run_shell(["helm", "template", "release", chart_path], cwd=project_root, timeout=90)
    results.append(ValidationResult(
        validator="helm template", ran=True, passed=bool(template.get("ok")), target=chart_path,
        detail=(f"rendered {len((template.get('stdout') or '').splitlines())} lines"
                if template.get("ok") else (template.get("stderr") or "")[:400]),
    ))
    return results


# ---------------------------------------------------------------------

def summarize(results: list[ValidationResult]) -> tuple[bool, str]:
    """Returns (validated, explanation).

    `validated` is True only if at least one validator RAN and every
    validator that ran passed. A set of results in which nothing ran can
    never be True - that is the whole point of this module (see the module
    docstring)."""
    ran = [r for r in results if r.ran]
    failed = [r for r in ran if not r.passed]
    blocked = [r for r in results if not r.ran]
    if failed:
        return False, ("validation FAILED: "
                        + "; ".join(f"{r.validator} ({r.detail[:120]})" for r in failed))
    if not ran:
        return False, ("no validator was able to run"
                        + (f" ({len(blocked)} blocked: "
                           + ", ".join(r.validator for r in blocked) + ")" if blocked else "")
                        + " - refusing to report this change as validated")
    explanation = f"{len(ran)} validator(s) passed: " + ", ".join(r.validator for r in ran)
    if blocked:
        explanation += (f"; {len(blocked)} could NOT run and were not counted as passing: "
                        + ", ".join(r.validator for r in blocked))
    return True, explanation
