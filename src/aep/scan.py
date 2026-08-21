"""`aep scan <path>` - capability-routed, read-only project analysis.

One command that answers "what is this repository, and what is actually
wrong with it?" without the caller having to know which analyzers exist or
which ones apply.

The routing rule that makes the output honest: an analyzer is only run when
`capabilities.detect_project()` found real evidence that it applies. What
happens to the rest is reported with a precise, non-interchangeable status:

  PASS        applicable, ran, found nothing
  FAIL        applicable, ran, found something (or errored)
  SKIPPED     NOT APPLICABLE to this repository - no Terraform files, no
              Chart.yaml, no manifests. Nothing is wrong and nothing is
              missing; this analyzer simply has no subject here.
  UNAVAILABLE APPLICABLE, but AEP cannot provide the capability in this
              install (e.g. an external scanner binary is genuinely absent).
              This is a gap in AEP's packaging, not in the repository.
  BLOCKED     APPLICABLE and the analyzer exists, but an external
              precondition prevents it running (registry/network/credentials).

Conflating SKIPPED with UNAVAILABLE was the specific defect this module
exists to fix: a pure React app was being told its Terraform scanning was
"unavailable", which reads as a broken AEP install rather than the truth,
which is that the repository contains no Terraform.

**Read-only by construction.** This module walks and reads files and calls
scanner adapters that do the same. It never writes to, installs into,
commits to, or deploys the target repository. Remediation is a separate,
explicit action - never a side effect of looking.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .capabilities import Capability, ProjectProfile, detect_project


class AnalyzerStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIPPED = "SKIPPED"
    UNAVAILABLE = "UNAVAILABLE"
    BLOCKED = "BLOCKED"


@dataclass
class AnalyzerResult:
    name: str
    status: AnalyzerStatus
    reason: str
    finding_count: int = 0
    findings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "analyzer": self.name,
            "status": self.status.value,
            "reason": self.reason,
            "finding_count": self.finding_count,
            "findings": [
                {"severity": getattr(f.severity, "value", str(f.severity)),
                 "file": f.file, "line": f.line, "rule": f.rule_id,
                 "description": f.description}
                for f in self.findings
            ],
        }


@dataclass
class ScanReport:
    profile: ProjectProfile
    results: list[AnalyzerResult] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return sum(r.finding_count for r in self.results)

    def security_readiness(self) -> str:
        """READY only when every applicable analyzer actually ran clean.

        A SKIPPED analyzer does not count against readiness (it does not
        apply). An UNAVAILABLE or BLOCKED one does - we genuinely do not
        know, and reporting READY on unknown coverage would be a lie.
        """
        if any(r.status is AnalyzerStatus.FAIL for r in self.results):
            return "NOT_READY"
        if any(r.status in (AnalyzerStatus.UNAVAILABLE, AnalyzerStatus.BLOCKED)
                for r in self.results):
            return "INCOMPLETE"
        return "READY"

    def to_dict(self) -> dict:
        return {
            "project": self.profile.to_dict(),
            "analyzers": [r.to_dict() for r in self.results],
            "total_findings": self.total_findings,
            "security_readiness": self.security_readiness(),
        }


def _run_shell(args, cwd=None, timeout=120) -> dict:
    """Resolve-then-run, matching `tools/shell_tool.py`'s behavior.

    Bare names are resolved via `shutil.which` first: on Windows a bare
    name that does not resolve raises rather than returning non-zero, and
    an unresolvable scanner must read as "not installed", not as a crash
    (see BUGFIX.md BUG-0012/BUG-0019).
    """
    resolved = shutil.which(args[0]) or args[0]
    try:
        proc = subprocess.run([resolved] + list(args[1:]), cwd=cwd,
                               capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "exit_code": -1, "stdout": "", "stderr": str(exc), "args": args}
    return {"ok": proc.returncode == 0, "exit_code": proc.returncode,
            "stdout": proc.stdout, "stderr": proc.stderr, "args": args}


def _from_record(name: str, record) -> AnalyzerResult:
    """Translate a SecurityScanRecord into a routed analyzer result."""
    from .security.models import ScannerAvailability

    if record.availability is ScannerAvailability.BLOCKED:
        return AnalyzerResult(name, AnalyzerStatus.BLOCKED,
                              record.note or "blocked by an external precondition")
    if record.availability is not ScannerAvailability.AVAILABLE:
        return AnalyzerResult(name, AnalyzerStatus.UNAVAILABLE,
                              record.note or "scanner not available in this installation")
    if record.finding_count:
        return AnalyzerResult(name, AnalyzerStatus.FAIL,
                              f"{record.finding_count} finding(s)",
                              record.finding_count, list(record.findings))
    return AnalyzerResult(name, AnalyzerStatus.PASS, "no findings")


def scan_project(project_root: str) -> ScanReport:
    """Detect what the repository is, then run only what applies."""
    profile = detect_project(project_root)
    report = ScanReport(profile=profile)

    # ---- Secrets: always applicable. Any repository can leak one. -------
    from .security.scanners import builtin_secret_scanner
    try:
        report.results.append(
            _from_record("Secrets", builtin_secret_scanner.scan(project_root)))
    except Exception as exc:  # noqa: BLE001 - one analyzer must not kill the scan
        report.results.append(AnalyzerResult("Secrets", AnalyzerStatus.FAIL,
                                              f"scanner error: {exc}"))

    # ---- SAST: needs application source. --------------------------------
    app_langs = [c for c in (Capability.PYTHON, Capability.NODE,
                              Capability.GO, Capability.JAVA) if profile.has(c)]
    if not app_langs:
        report.results.append(AnalyzerResult(
            "SAST", AnalyzerStatus.SKIPPED,
            "no application source detected (no Python/Node/Go/Java markers)"))
    else:
        from .security.scanners import semgrep_scanner
        try:
            avail = semgrep_scanner.check_availability(_run_shell)
            from .security.models import ScannerAvailability
            if avail.status is not ScannerAvailability.AVAILABLE:
                report.results.append(AnalyzerResult(
                    "SAST", AnalyzerStatus.UNAVAILABLE,
                    "semgrep is not installed - install the optional extra: "
                    "pip install 'aep-platform[sast]'"))
            else:
                report.results.append(
                    _from_record("SAST", semgrep_scanner.scan(project_root, _run_shell)))
        except Exception as exc:  # noqa: BLE001
            report.results.append(AnalyzerResult("SAST", AnalyzerStatus.UNAVAILABLE,
                                                  f"semgrep unavailable: {exc}"))

    # ---- Dependencies: needs a dependency manifest. ---------------------
    if not app_langs:
        report.results.append(AnalyzerResult(
            "Dependencies", AnalyzerStatus.SKIPPED,
            "no dependency manifest detected (no pyproject/requirements/package.json/go.mod/pom)"))
    else:
        report.results.append(_dependency_result(project_root))

    # ---- IaC: needs Terraform/Kubernetes/Helm. --------------------------
    iac_caps = [c for c in (Capability.TERRAFORM, Capability.KUBERNETES,
                             Capability.HELM) if profile.has(c)]
    if not iac_caps:
        report.results.append(AnalyzerResult(
            "IaC", AnalyzerStatus.SKIPPED,
            "no infrastructure-as-code detected (no *.tf, Chart.yaml, or Kubernetes manifests)"))
    else:
        report.results.append(_iac_result(project_root, iac_caps))

    # ---- Containers: needs a Dockerfile/compose file. -------------------
    if not profile.has(Capability.CONTAINER):
        report.results.append(AnalyzerResult(
            "Containers", AnalyzerStatus.SKIPPED,
            "no container definition detected (no Dockerfile or docker-compose)"))
    else:
        from .security.scanners import trivy_scanner
        try:
            avail = trivy_scanner.check_availability(_run_shell)
            from .security.models import ScannerAvailability
            if avail.status is ScannerAvailability.AVAILABLE:
                report.results.append(
                    _from_record("Containers", trivy_scanner.scan(project_root, _run_shell)))
            else:
                # Applicable, and AEP cannot ship a container scanner that
                # works without registry access - honestly BLOCKED, not
                # "unavailable", and never "go install trivy".
                report.results.append(AnalyzerResult(
                    "Containers", AnalyzerStatus.BLOCKED,
                    "container image scanning requires a registry-capable scanner and "
                    "network access to the image registry; not available in this environment"))
        except Exception as exc:  # noqa: BLE001
            report.results.append(AnalyzerResult("Containers", AnalyzerStatus.BLOCKED,
                                                  f"container scanning blocked: {exc}"))

    return report


def _dependency_result(project_root: str) -> AnalyzerResult:
    """Real dependency/CVE scan via the existing Phase 3 scanners."""
    try:
        from .dependency.manifests import discover_manifests
        from .dependency.scanners import pip_audit_scanner
    except Exception as exc:  # noqa: BLE001
        return AnalyzerResult("Dependencies", AnalyzerStatus.UNAVAILABLE,
                              f"dependency scanning unavailable: {exc}")

    manifests = discover_manifests(project_root)
    if not manifests:
        return AnalyzerResult("Dependencies", AnalyzerStatus.SKIPPED,
                              "no resolvable dependency manifest found")
    if not pip_audit_scanner.is_available(_run_shell):
        return AnalyzerResult(
            "Dependencies", AnalyzerStatus.UNAVAILABLE,
            "pip-audit is not installed - install the optional extra: "
            "pip install 'aep-platform[dependency-scanning]'")

    total = 0
    for manifest in manifests:
        try:
            record = pip_audit_scanner.scan(manifest, project_root, _run_shell)
            total += record.finding_count
        except Exception as exc:  # noqa: BLE001
            return AnalyzerResult("Dependencies", AnalyzerStatus.FAIL,
                                  f"dependency scan error: {exc}")
    if total:
        return AnalyzerResult("Dependencies", AnalyzerStatus.FAIL,
                              f"{total} vulnerable dependency finding(s)", total)
    return AnalyzerResult("Dependencies", AnalyzerStatus.PASS, "no known vulnerable dependencies")


def _iac_result(project_root: str, iac_caps: list) -> AnalyzerResult:
    """Infrastructure analysis via AEP's OWN native scanners.

    Deliberately does not require checkov: `infra/scanners/` already
    contains real, dependency-free Terraform/Kubernetes checks, so IaC
    analysis works out of the box on a plain install.

    A scanner that ERRORS must never be reported as PASS. An earlier
    revision of this function swallowed exceptions and returned "no
    findings", which turned a crashed scanner into a clean bill of health
    on a real Terraform repository - the exact class of fabricated result
    this platform forbids. Errors now surface as UNAVAILABLE.
    """
    try:
        from .infra.scanners import k8s_native_scanner, terraform_deep_scanner
        from .security.models import ScannerAvailability
    except Exception as exc:  # noqa: BLE001
        return AnalyzerResult("IaC", AnalyzerStatus.UNAVAILABLE,
                              f"infrastructure analysis unavailable: {exc}")

    kinds = ", ".join(sorted(c.value for c in iac_caps))
    findings = []
    errors: list[str] = []
    ran_any = False

    for module in (terraform_deep_scanner, k8s_native_scanner):
        name = module.__name__.rsplit(".", 1)[-1]
        try:
            record = module.scan(project_root, _run_shell)
        except Exception as exc:  # noqa: BLE001 - recorded, never silently passed
            errors.append(f"{name}: {type(exc).__name__}: {exc}")
            continue
        if record.availability is ScannerAvailability.AVAILABLE:
            ran_any = True
            findings.extend(record.findings)
        elif record.availability is ScannerAvailability.BLOCKED:
            errors.append(f"{name}: BLOCKED - {record.note or 'external precondition'}")
        else:
            errors.append(f"{name}: {record.availability.value} - {record.note or 'not available'}")

    if findings:
        return AnalyzerResult("IaC", AnalyzerStatus.FAIL,
                              f"{len(findings)} finding(s) across {kinds}",
                              len(findings), findings)
    if not ran_any:
        return AnalyzerResult("IaC", AnalyzerStatus.UNAVAILABLE,
                              "; ".join(errors) or "no infrastructure scanner could run")
    if errors:
        # Something ran clean, but coverage is partial - say so rather than
        # implying the whole surface was checked.
        return AnalyzerResult("IaC", AnalyzerStatus.PASS,
                              f"no findings across {kinds} (partial coverage: {'; '.join(errors)})")
    return AnalyzerResult("IaC", AnalyzerStatus.PASS, f"no findings across {kinds}")


def render_report(report: ScanReport) -> str:
    """Human-readable scan output."""
    profile = report.profile
    lines: list[str] = []
    lines.append("=== AEP SCAN ===")
    lines.append(f"Repository: {profile.root}")
    lines.append("")
    lines.append("Detected:")
    for capability in profile.sorted_capabilities():
        evidence = profile.evidence.get(Capability(capability), [])
        hint = f"  ({', '.join(evidence[:2])})" if evidence else ""
        lines.append(f"  {capability}{hint}")
    lines.append("")

    width = max((len(r.name) for r in report.results), default=12) + 2
    lines.append("SECURITY POSTURE")
    for result in report.results:
        lines.append(f"  {result.name:<{width}}{result.status.value}")
    lines.append("")

    for label, status in (("Analyzed", None), ("Skipped", AnalyzerStatus.SKIPPED),
                           ("Unavailable", AnalyzerStatus.UNAVAILABLE),
                           ("Blocked", AnalyzerStatus.BLOCKED)):
        if status is None:
            ran = [r for r in report.results
                   if r.status in (AnalyzerStatus.PASS, AnalyzerStatus.FAIL)]
            if ran:
                lines.append("Analyzed:")
                for r in ran:
                    lines.append(f"  {r.name} - {r.reason}")
                lines.append("")
            continue
        group = [r for r in report.results if r.status is status]
        if group:
            lines.append(f"{label}:")
            for r in group:
                lines.append(f"  {r.name} - {r.reason}")
            lines.append("")

    findings = [f for r in report.results for f in r.findings]
    if findings:
        lines.append(f"FINDINGS ({len(findings)})")
        for f in findings[:25]:
            severity = getattr(f.severity, "value", str(f.severity))
            location = f"{f.file}:{f.line}" if f.file else "-"
            lines.append(f"  [{severity}] {location} {f.description}")
        if len(findings) > 25:
            lines.append(f"  ... and {len(findings) - 25} more")
        lines.append("")

    lines.append(f"Security readiness: {report.security_readiness()}")
    lines.append("")
    lines.append("Next steps:")
    if report.total_findings:
        lines.append("  - Review the findings above; AEP made NO changes (scan is read-only).")
        lines.append("  - Remediation is a separate, explicit action.")
    else:
        lines.append("  - No findings from the analyzers that apply to this repository.")
    incomplete = [r for r in report.results
                  if r.status in (AnalyzerStatus.UNAVAILABLE, AnalyzerStatus.BLOCKED)]
    for r in incomplete:
        lines.append(f"  - {r.name} did not run: {r.reason}")
    return "\n".join(lines)
