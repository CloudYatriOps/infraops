"""Built-in secret scanner - AEP's self-contained default.

Why this exists: `gitleaks_scanner.py` is a real adapter around a real
binary, but that binary is a Go program AEP cannot ship through a Python
wheel. A normal `pip install aep-platform` therefore had no working secret
detection at all and reported `UNAVAILABLE` - telling the user to go
install gitleaks themselves, which is not an acceptable out-of-the-box
product experience for a capability AEP claims to have.

The platform already contains a real, deterministic secret detector:
`aep.redaction.find_secrets()` (AWS access keys and secret keys, private
key blocks, Slack tokens, GitHub classic/fine-grained PATs,
credential-in-URL, generic API-key assignments, plus an opt-in
high-entropy heuristic). It is the same detector the orchestrator's
security gate and the demo already rely on to block a task graph on a real
secret. This module exposes it through the standard scanner adapter
contract so `aep security-status`/`aep scan` can use it with no external
tool, on every platform, at zero install cost.

This is NOT a reimplementation and NOT a stub: it is the existing engine
behind the existing adapter interface. It is also NOT a claim to be
gitleaks - `gitleaks_scanner.py` remains available and preferred when the
real binary IS present, because gitleaks carries far more rules. The
relationship is: built-in = always works; gitleaks = better, if installed.

Secret-value hygiene is unchanged and non-negotiable (see
`security/models.py`): `find_secrets()` returns an already-redacted
preview, and the raw matched value is never read into a finding field,
evidence string, log line, or any other durable/printed state here.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from ...redaction import find_secrets
from ..models import (
    AvailabilityResult, ScannerAvailability, ScannerDescriptor, SecurityCategory,
    SecurityFinding, SecurityScanRecord, SecuritySeverity,
)

SCANNER_ID = "builtin-secrets"
CATEGORY = SecurityCategory.SECRET
SUPPORTED = ["*"]  # content-based, language independent
TOOL_NAME = "builtin"  # in-process; no binary is invoked
REMEDIATION_SUPPORTED = True

# A live credential committed to source control is always at least HIGH -
# same rule the gitleaks adapter applies, kept identical so severity does
# not silently change depending on which secret scanner ran.
_DEFAULT_SEVERITY = SecuritySeverity.HIGH

_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".terraform", "vendor",
              ".venv", "venv", ".pytest_cache", "dist", "build", ".mypy_cache",
              ".tox", ".gradle", "target"}

# Files larger than this are not content-scanned. A multi-megabyte blob is
# almost never hand-written source, and reading them makes a scan crawl.
_MAX_FILE_BYTES = 2_000_000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def check_availability(run_shell=None) -> AvailabilityResult:
    """Always AVAILABLE - runs in-process, no binary, no network.

    Takes `run_shell` only to match the adapter contract every other
    scanner in this package follows; it is deliberately unused.
    """
    return AvailabilityResult(
        ScannerAvailability.AVAILABLE,
        "built-in detector (aep.redaction.find_secrets) - in-process, no external tool required",
    )


def describe(run_shell=None) -> ScannerDescriptor:
    return ScannerDescriptor(
        scanner_id=SCANNER_ID, capability="security.secret_scan", category=CATEGORY,
        supported=SUPPORTED, tool=TOOL_NAME,
        findings_schema="SecurityFinding (security/models.py)",
        availability=check_availability(run_shell),
        remediation_supported=REMEDIATION_SUPPORTED,
    )


def _iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            yield Path(dirpath) / name


def scan(project_root: str, run_shell=None) -> SecurityScanRecord:
    """Walk `project_root` and report every high-confidence secret match.

    Read-only: opens files for reading and nothing else. Unreadable or
    binary files are skipped rather than failing the scan - a stray
    binary must not stop a repository from being scanned.
    """
    scanned_at = _now()
    root = Path(project_root).resolve()

    if not root.is_dir():
        return SecurityScanRecord(
            scanner=SCANNER_ID, scanner_version="builtin", category=CATEGORY,
            scanned_at=scanned_at, target=str(root),
            availability=ScannerAvailability.UNAVAILABLE,
            exit_code=0, finding_count=0, findings=[],
            note=f"target is not a directory: {root}",
        )

    findings: list[SecurityFinding] = []
    for path in _iter_files(root):
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError, ValueError):
            # Binary or unreadable - not a scan failure.
            continue

        rel = path.relative_to(root).as_posix()
        for line_no, line in enumerate(content.splitlines(), start=1):
            for match in find_secrets(line, high_confidence_only=True):
                findings.append(SecurityFinding(
                    # Deterministic, content-based fingerprint so suppression
                    # and rescan matching keep working across runs.
                    id=f"{SCANNER_ID}:{match.kind}:{rel}:{line_no}",
                    scanner=SCANNER_ID, category=CATEGORY,
                    severity=_DEFAULT_SEVERITY, confidence="high",
                    file=rel, line=line_no, resource=None,
                    description=f"Potential committed secret ({match.kind}) detected in {rel}",
                    # `match.snippet` is already redacted by find_secrets();
                    # the raw value is never placed here.
                    evidence=f"{match.kind}: {match.snippet}",
                    remediation=(
                        "Remove the credential from source control, rotate it at the "
                        "issuing provider (assume it is compromised), and move it to a "
                        "secret manager or environment variable."
                    ),
                    rule_id=match.kind,
                ))

    return SecurityScanRecord(
        scanner=SCANNER_ID, scanner_version="builtin", category=CATEGORY,
        scanned_at=scanned_at, target=str(root),
        availability=ScannerAvailability.AVAILABLE,
        exit_code=0, finding_count=len(findings), findings=findings,
    )
