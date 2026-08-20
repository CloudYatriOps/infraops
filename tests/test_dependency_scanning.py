"""Real scanner tests - no mocked scanner output. These shell out to the
actual `pip-audit`/`npm` binaries and hit the actual PyPI/npm registries,
exactly the way DependencyCVEAgent does via the shell tool. Skipped (not
faked) if the underlying binary genuinely isn't available, per
ARCHITECTURE.md's "never fabricate a scan result" discipline - the same
rule dependency/scanners/govulncheck_scanner.py and trivy_scanner.py
document for ecosystems this sandbox can't reach.
"""
from __future__ import annotations

import shutil
import subprocess

import pytest

from aep.dependency.manifests import discover_manifests
from aep.dependency.scanners import npm_audit_scanner, pip_audit_scanner


def _make_run_shell(default_cwd):
    """Mirrors DependencyCVEAgent._run_shell: scanners may omit `cwd` and
    expect it to default to the project root they were invoked against."""
    def run(args, cwd=None, timeout=60):
        # BUG-0012-class fix, test-helper side: on Windows, `npm` is really
        # `npm.cmd`, and `subprocess.run` without `shell=True` raises
        # FileNotFoundError for a bare name it can't launch directly - which
        # crashed pytest COLLECTION (the skipif itself calls this), not just
        # the test body. Resolve the name first; if it doesn't resolve at
        # all, let is_available()/the caller see a clean non-zero failure
        # instead of an uncaught exception.
        resolved = shutil.which(args[0]) or args[0]
        try:
            proc = subprocess.run([resolved] + args[1:], cwd=cwd or default_cwd,
                                   capture_output=True, text=True, timeout=timeout)
        except (FileNotFoundError, OSError) as exc:
            return {"ok": False, "exit_code": -1, "stdout": "", "stderr": str(exc), "args": args}
        return {"ok": proc.returncode == 0, "exit_code": proc.returncode,
                "stdout": proc.stdout, "stderr": proc.stderr, "args": args}
    return run


_real_run_shell = _make_run_shell(".")


@pytest.mark.skipif(not pip_audit_scanner.is_available(_real_run_shell),
                     reason="pip-audit not installed in this environment")
def test_pip_audit_scanner_finds_a_real_known_vulnerability(tmp_path):
    (tmp_path / "requirements.txt").write_text("urllib3==1.26.4\n")
    manifest = discover_manifests(str(tmp_path))[0]

    record = pip_audit_scanner.scan(manifest, str(tmp_path), _make_run_shell(str(tmp_path)))

    assert record.scanner == "pip-audit"
    assert record.finding_count > 0
    packages = {f.package for f in record.findings}
    assert "urllib3" in packages
    ids = {f.id for f in record.findings}
    assert "PYSEC-2021-108" in ids  # the real, published GHSA-q2q7-5pp4-w6pg / CVE-2021-33503
    finding = next(f for f in record.findings if f.id == "PYSEC-2021-108")
    assert finding.fixed_versions == ["1.26.5"]
    assert "GHSA-q2q7-5pp4-w6pg" in finding.aliases


@pytest.mark.skipif(not pip_audit_scanner.is_available(_real_run_shell),
                     reason="pip-audit not installed in this environment")
def test_pip_audit_scanner_reports_clean_for_a_safe_pin(tmp_path):
    (tmp_path / "requirements.txt").write_text("urllib3==2.7.0\n")
    manifest = discover_manifests(str(tmp_path))[0]
    record = pip_audit_scanner.scan(manifest, str(tmp_path), _make_run_shell(str(tmp_path)))
    assert record.finding_count == 0


@pytest.mark.skipif(not npm_audit_scanner.is_available(_real_run_shell),
                     reason="npm not available in this environment")
def test_npm_audit_scanner_finds_a_real_known_vulnerability(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"name": "npmaudit-fixture", "version": "1.0.0", '
        '"dependencies": {"minimatch": "3.0.4"}}\n'
    )
    manifest = discover_manifests(str(tmp_path))[0]

    record = npm_audit_scanner.scan(manifest, str(tmp_path), _make_run_shell(str(tmp_path)))

    assert record.scanner == "npm-audit"
    assert record.finding_count > 0
    assert any(f.package == "minimatch" for f in record.findings)
