"""Real npm-audit-backed scanner for Node.js `package.json` manifests.

Also genuinely verified during Phase 3 development: a fixture `package.json`
pinning `minimatch@3.0.4` produced real vulnerability data from
registry.npmjs.org (GHSA-f8q6-p94x-37v3 and related ReDoS advisories,
fixAvailable -> 3.1.5) via this exact command sequence.

`npm audit` needs a lockfile to resolve against. If the manifest's
directory doesn't already have one, `npm install --package-lock-only`
resolves one from the real npm registry without installing any package
code into node_modules (so no third-party install script ever runs) -
only then does the real, unmodified `npm audit --json` run.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ..models import DependencyManifest, Ecosystem, ScanRecord, Severity, VulnerabilityFinding

TOOL_NAME = "npm-audit"
ecosystem = Ecosystem.NODE

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH,
    "moderate": Severity.MODERATE, "low": Severity.LOW,
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_available(run_shell) -> bool:
    result = run_shell(["npm", "--version"], timeout=10)
    return bool(result.get("ok"))


def _version(run_shell) -> str:
    result = run_shell(["npm", "--version"], timeout=10)
    return (result.get("stdout") or "").strip() or "unknown"


def _installed_version(project_root: str, manifest: DependencyManifest, name: str) -> str:
    try:
        pkg_json = json.loads(Path(project_root, manifest.path).read_text())
    except Exception:
        return "unknown"
    return (pkg_json.get("dependencies", {}).get(name)
            or pkg_json.get("devDependencies", {}).get(name) or "unknown")


def scan(manifest: DependencyManifest, project_root: str, run_shell) -> ScanRecord:
    manifest_dir = str(Path(project_root, manifest.path).parent)
    scanned_at = _now()
    tool_version = _version(run_shell)

    lockfile = Path(manifest_dir) / "package-lock.json"
    if not lockfile.exists():
        run_shell(["npm", "install", "--package-lock-only"], cwd=manifest_dir, timeout=180)

    result = run_shell(["npm", "audit", "--json"], cwd=manifest_dir, timeout=60)
    try:
        data = json.loads(result.get("stdout") or "{}")
    except json.JSONDecodeError:
        data = {}

    findings: list[VulnerabilityFinding] = []
    for name, vuln in (data.get("vulnerabilities") or {}).items():
        fix_available = vuln.get("fixAvailable")
        fixed_versions: list[str] = []
        if isinstance(fix_available, dict) and fix_available.get("version"):
            fixed_versions = [fix_available["version"]]
        installed_version = _installed_version(project_root, manifest, name)
        for via in vuln.get("via", []):
            if not isinstance(via, dict):
                continue
            findings.append(VulnerabilityFinding(
                id=str(via.get("source") or via.get("url") or name),
                aliases=[via["url"]] if via.get("url") else [],
                ecosystem=ecosystem, manifest_path=manifest.path, package=name,
                installed_version=installed_version,
                vulnerable_range=via.get("range", "unknown"),
                fixed_versions=fixed_versions,
                severity=_SEVERITY_MAP.get(via.get("severity", ""), Severity.UNKNOWN),
                summary=(via.get("title") or "")[:500],
                source=TOOL_NAME, scanned_at=scanned_at,
            ))

    return ScanRecord(
        scanner=TOOL_NAME, scanner_version=tool_version, scanned_at=scanned_at,
        manifest_path=manifest.path, ecosystem=ecosystem, exit_code=result.get("exit_code", -1),
        finding_count=len(findings), findings=findings,
        raw_output_ref=((result.get("stdout") or "") + "\n" + (result.get("stderr") or ""))[:4000],
    )
