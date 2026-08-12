"""Terraform deep-analysis scanner (Phase 5 Part 2).

Complements — does NOT duplicate — Phase 4's `security/scanners/
checkov_scanner.py`, which already runs checkov's full Terraform policy
set and is left completely untouched. This module covers the Part 2 items
checkov's resource-level checks structurally cannot reach, because they
are properties of the *configuration itself* rather than of a cloud
resource:

  - hardcoded credentials in a `provider` block (checkov's secret checks
    look at resources; a literal `access_key` on the provider is a
    configuration-level problem)
  - unsafe Terraform **state** configuration — a `local` backend (state
    with credentials in plaintext, in the repo), or a remote backend with
    encryption explicitly disabled. Nothing in a resource block expresses
    this.
  - deprecated/unpinned provider and resource usage — an unconstrained
    provider version means a `terraform init` months from now silently
    picks up a different, potentially breaking provider.

Built on `python-hcl2` (already present as a checkov dependency, so no new
install), which is a real HCL2 parser — verified during Phase 5
investigation to correctly parse provider/backend/resource blocks with
line numbers AND to reject malformed HCL with an `UnexpectedToken` rather
than silently returning a partial parse. That rejection behavior is what
makes `infra/validation.py`'s structural check meaningful.

Provider-agnostic: the credential rules key off *argument names*
(`access_key`, `secret_key`, `client_secret`, `password`, `token`,
`private_key`) that appear across AWS/Azure/GCP/OCI/others, not off a
hard-coded provider list.
"""
from __future__ import annotations

import io
from datetime import datetime, timezone
from pathlib import Path

from ...security.models import (
    AvailabilityResult, ScannerAvailability, ScannerDescriptor, SecurityCategory,
    SecurityFinding, SecurityScanRecord, SecuritySeverity,
)

SCANNER_ID = "terraform-deep"
CATEGORY = SecurityCategory.IAC
SUPPORTED = ["*.tf"]
TOOL_NAME = "python-hcl2"
REMEDIATION_SUPPORTED = True

# Argument names that carry a credential in SOME provider. Deliberately
# provider-agnostic (Part 5: "The core platform must remain
# provider-agnostic. Never hard-code credentials.").
_CREDENTIAL_ARGS = {
    "access_key", "secret_key", "session_token", "token", "password", "client_secret",
    "private_key", "api_key", "auth_token", "secret_access_key", "shared_credentials_file",
}

# A value that is an interpolation/reference is NOT a hardcoded secret -
# `var.x`, `local.x`, `data.x`, `${...}` all resolve elsewhere.
_REFERENCE_PREFIXES = ("var.", "local.", "data.", "module.", "${", "path.", "each.")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def check_availability(run_shell) -> AvailabilityResult:
    """Availability is a pure in-process import check - this scanner
    invokes no binary at all, which is why it stays AVAILABLE in an
    environment where the real `terraform` CLI is BLOCKED."""
    try:
        import hcl2  # noqa: F401
    except ImportError:
        return AvailabilityResult(
            ScannerAvailability.UNAVAILABLE,
            "python-hcl2 is not installed (normally present as a checkov dependency; "
            "`pip install --break-system-packages python-hcl2`)",
        )
    return AvailabilityResult(
        ScannerAvailability.AVAILABLE,
        "python-hcl2 available; parses HCL in-process with no `terraform` binary and no network "
        "(the terraform CLI itself is BLOCKED here - see infra/validation.py)",
    )


def describe(run_shell) -> ScannerDescriptor:
    return ScannerDescriptor(
        scanner_id=SCANNER_ID, capability="infra.terraform_deep_scan", category=CATEGORY,
        supported=SUPPORTED, tool=TOOL_NAME,
        findings_schema="SecurityFinding (security/models.py) - Phase 4 model reused, not forked",
        severity_levels=[s.value for s in SecuritySeverity],
        evidence_kind="HCL block type + argument name (never the value)",
        remediation_supported=REMEDIATION_SUPPORTED, availability=check_availability(run_shell),
    )


def _unwrap(value):
    """python-hcl2 wraps scalars in single-element lists; unwrap for
    comparison but keep the original shape otherwise."""
    if isinstance(value, list) and len(value) == 1:
        return value[0]
    return value


def _is_reference(value) -> bool:
    if not isinstance(value, str):
        return False
    return value.startswith(_REFERENCE_PREFIXES) or ("${" in value)


def _scan_providers(blocks: list, rel_path: str, scanned_at: str) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    for block in blocks:
        for provider_name, body in block.items():
            if not isinstance(body, dict):
                continue
            line = body.get("__start_line__")
            for arg, raw_value in body.items():
                if arg.startswith("__") or arg not in _CREDENTIAL_ARGS:
                    continue
                value = _unwrap(raw_value)
                if _is_reference(value):
                    continue
                if not isinstance(value, str) or not value.strip():
                    continue
                findings.append(SecurityFinding(
                    id=f"terraform-deep:TF_PROVIDER_CREDENTIAL:{rel_path}:{provider_name}:{arg}",
                    scanner=SCANNER_ID, category=CATEGORY, severity=SecuritySeverity.CRITICAL,
                    confidence="high", file=rel_path, line=line,
                    resource=f"provider.{provider_name}",
                    description=f"hardcoded credential in provider \"{provider_name}\" "
                                f"(argument `{arg}`)",
                    # The VALUE is never included - only its argument name and
                    # length, matching Phase 4's "never print the secret" rule.
                    evidence=f"provider \"{provider_name}\" sets `{arg}` to a literal "
                              f"{len(value)}-character value instead of a variable reference "
                              f"(value redacted)",
                    remediation=f"replace with a variable reference (e.g. `{arg} = var.{arg}`) "
                                f"resolved from an approved secret store, or drop the argument "
                                f"entirely and let the provider use its standard credential chain",
                    rule_id="TF_PROVIDER_CREDENTIAL", cwe="CWE-798", detected_at=scanned_at,
                ))
            # Unpinned provider version - a config-level, not resource-level, risk.
            if "version" not in body and provider_name:
                pass  # provider version pinning lives in required_providers; see _scan_terraform_block
    return findings


def _scan_terraform_block(blocks: list, rel_path: str, scanned_at: str) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    for block in blocks:
        line = block.get("__start_line__")
        backends = block.get("backend")
        if backends:
            for backend in (backends if isinstance(backends, list) else [backends]):
                for backend_type, backend_body in backend.items():
                    body = backend_body if isinstance(backend_body, dict) else {}
                    if backend_type == "local":
                        findings.append(SecurityFinding(
                            id=f"terraform-deep:TF_STATE_LOCAL_BACKEND:{rel_path}",
                            scanner=SCANNER_ID, category=CATEGORY, severity=SecuritySeverity.HIGH,
                            confidence="high", file=rel_path, line=line,
                            resource="terraform.backend.local",
                            description="Terraform state uses the local backend",
                            evidence="a `local` backend keeps terraform.tfstate on disk (and often "
                                      "in version control); state contains every resource "
                                      "attribute, including generated passwords and keys, in "
                                      "plaintext",
                            remediation="use a remote backend with encryption and access control "
                                        "(and state locking), and ensure terraform.tfstate is "
                                        "gitignored",
                            rule_id="TF_STATE_LOCAL_BACKEND", cwe="CWE-312",
                            detected_at=scanned_at,
                        ))
                    elif "encrypt" in body and _unwrap(body["encrypt"]) is False:
                        findings.append(SecurityFinding(
                            id=f"terraform-deep:TF_STATE_UNENCRYPTED:{rel_path}:{backend_type}",
                            scanner=SCANNER_ID, category=CATEGORY, severity=SecuritySeverity.HIGH,
                            confidence="high", file=rel_path, line=line,
                            resource=f"terraform.backend.{backend_type}",
                            description=f"Terraform `{backend_type}` backend explicitly disables "
                                        f"state encryption",
                            evidence=f"backend \"{backend_type}\" sets encrypt = false; state "
                                      f"contains plaintext resource attributes and secrets",
                            remediation="set encrypt = true on the backend",
                            rule_id="TF_STATE_UNENCRYPTED", cwe="CWE-311", detected_at=scanned_at,
                        ))
                    for arg, raw_value in body.items():
                        if arg in _CREDENTIAL_ARGS and not _is_reference(_unwrap(raw_value)):
                            findings.append(SecurityFinding(
                                id=f"terraform-deep:TF_STATE_CREDENTIAL:{rel_path}:{arg}",
                                scanner=SCANNER_ID, category=CATEGORY,
                                severity=SecuritySeverity.CRITICAL, confidence="high",
                                file=rel_path, line=line,
                                resource=f"terraform.backend.{backend_type}",
                                description=f"hardcoded credential in backend configuration "
                                            f"(`{arg}`)",
                                evidence=f"backend \"{backend_type}\" sets `{arg}` to a literal "
                                          f"value (redacted)",
                                remediation="supply backend credentials via environment/partial "
                                            "backend configuration, never in committed HCL",
                                rule_id="TF_STATE_CREDENTIAL", cwe="CWE-798",
                                detected_at=scanned_at,
                            ))

        required = block.get("required_providers")
        for req in (required if isinstance(required, list) else ([required] if required else [])):
            if not isinstance(req, dict):
                continue
            for provider_name, spec in req.items():
                spec = _unwrap(spec)
                has_version = isinstance(spec, dict) and "version" in spec
                if not has_version:
                    findings.append(SecurityFinding(
                        id=f"terraform-deep:TF_PROVIDER_UNPINNED:{rel_path}:{provider_name}",
                        scanner=SCANNER_ID, category=CATEGORY, severity=SecuritySeverity.MEDIUM,
                        confidence="high", file=rel_path, line=line,
                        resource=f"required_providers.{provider_name}",
                        description=f"provider \"{provider_name}\" has no version constraint",
                        evidence=f"required_providers.{provider_name} omits `version`, so "
                                  f"`terraform init` resolves whatever is newest at that moment - "
                                  f"builds are not reproducible and a breaking or malicious "
                                  f"provider release is picked up silently",
                        remediation=f"add a version constraint, e.g. "
                                    f"`{provider_name} = {{ source = \"...\", version = \"~> 5.0\" }}`",
                        rule_id="TF_PROVIDER_UNPINNED", detected_at=scanned_at,
                    ))
    return findings


def scan(project_root: str, run_shell) -> SecurityScanRecord:
    scanned_at = _now()
    availability = check_availability(run_shell)
    if availability.status != ScannerAvailability.AVAILABLE:
        return SecurityScanRecord(
            scanner=SCANNER_ID, scanner_version="unknown", category=CATEGORY, scanned_at=scanned_at,
            target=project_root, availability=availability.status, exit_code=0, finding_count=0,
            findings=[], note=availability.reason,
        )

    import hcl2

    root = Path(project_root)
    tf_files = sorted(p for p in root.rglob("*.tf") if ".terraform" not in p.parts)
    if not tf_files:
        return SecurityScanRecord(
            scanner=SCANNER_ID, scanner_version=TOOL_NAME, category=CATEGORY, scanned_at=scanned_at,
            target=project_root, availability=ScannerAvailability.NOT_APPLICABLE, exit_code=0,
            finding_count=0, findings=[],
            note="no .tf files found in this repository - nothing to scan",
        )

    findings: list[SecurityFinding] = []
    parse_errors: list[str] = []
    for tf_file in tf_files:
        rel = str(tf_file.relative_to(root))
        try:
            parsed = hcl2.load(io.StringIO(tf_file.read_text()))
        except Exception as e:  # noqa: BLE001 - any parser failure is reported, never swallowed
            # A file this platform cannot parse is reported as a real
            # finding, not skipped: "we couldn't read it" must never look
            # the same as "it was clean".
            parse_errors.append(f"{rel}: {type(e).__name__}: {str(e)[:120]}")
            findings.append(SecurityFinding(
                id=f"terraform-deep:TF_UNPARSEABLE:{rel}",
                scanner=SCANNER_ID, category=CATEGORY, severity=SecuritySeverity.MEDIUM,
                confidence="high", file=rel, line=None, resource=None,
                description="Terraform file could not be parsed as valid HCL2",
                evidence=f"{type(e).__name__}: {str(e)[:200]}",
                remediation="fix the HCL syntax; this file was NOT security-scanned, so its "
                            "contents are unverified rather than clean",
                rule_id="TF_UNPARSEABLE", detected_at=scanned_at,
            ))
            continue
        findings.extend(_scan_providers(parsed.get("provider", []) or [], rel, scanned_at))
        findings.extend(_scan_terraform_block(parsed.get("terraform", []) or [], rel, scanned_at))

    return SecurityScanRecord(
        scanner=SCANNER_ID, scanner_version=TOOL_NAME, category=CATEGORY, scanned_at=scanned_at,
        target=project_root, availability=ScannerAvailability.AVAILABLE, exit_code=0,
        finding_count=len(findings), findings=findings,
        note=f"{len(parse_errors)} unparseable file(s)" if parse_errors else "",
        raw_output_ref=f"{len(tf_files)} .tf file(s) parsed in-process via python-hcl2; "
                       f"resource-level policy coverage comes from the Phase 4 checkov scanner, "
                       f"not this module",
    )
