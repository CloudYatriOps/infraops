"""Real scanner tests - no mocked scanner output, mirroring
test_dependency_scanning.py's discipline exactly: these shell out to the
actual gitleaks/semgrep/checkov binaries, and are skipped (not faked) if
the binary genuinely isn't available in this environment. `trivy` is
the one category that's expected to be BLOCKED everywhere this platform
has been run so far (see security/scanners/trivy_scanner.py) - that is
asserted directly rather than skipped, since "reports BLOCKED honestly" is
itself the behavior under test.
"""
from __future__ import annotations

import subprocess

import pytest

from aep.security.models import AvailabilityResult, ScannerAvailability
from aep.security.scanners import checkov_scanner, gitleaks_scanner, semgrep_scanner, trivy_scanner


def _make_run_shell(default_cwd):
    def run(args, cwd=None, timeout=90):
        try:
            proc = subprocess.run(args, cwd=cwd or default_cwd, capture_output=True, text=True,
                                   timeout=timeout)
            return {"ok": proc.returncode == 0, "exit_code": proc.returncode,
                    "stdout": proc.stdout, "stderr": proc.stderr, "args": args}
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            return {"ok": False, "exit_code": -1, "stdout": "", "stderr": str(e), "args": args}
    return run


_real_run_shell = _make_run_shell(".")


# ---- gitleaks (secrets) --------------------------------------------------

@pytest.mark.skipif(
    gitleaks_scanner.check_availability(_real_run_shell).status != ScannerAvailability.AVAILABLE,
    reason="gitleaks not installed in this environment",
)
def test_gitleaks_finds_a_real_fake_aws_key(tmp_path):
    (tmp_path / "config.py").write_text('AWS_ACCESS_KEY_ID = "AKIAZZZZ9999QQQQ1111"\n')

    record = gitleaks_scanner.scan(str(tmp_path), _make_run_shell(str(tmp_path)))

    assert record.availability == ScannerAvailability.AVAILABLE
    assert record.finding_count == 1
    finding = record.findings[0]
    assert finding.rule_id == "aws-access-token"
    assert finding.file == "config.py"
    assert finding.line == 1
    assert finding.severity.value == "high"
    # The hard rule: the raw value is NEVER present anywhere in the finding.
    import json
    assert "AKIAZZZZ9999QQQQ1111" not in json.dumps(finding.to_dict())


@pytest.mark.skipif(
    gitleaks_scanner.check_availability(_real_run_shell).status != ScannerAvailability.AVAILABLE,
    reason="gitleaks not installed in this environment",
)
def test_gitleaks_reports_clean_for_a_repo_with_no_secrets(tmp_path):
    (tmp_path / "app.py").write_text("def add(a, b):\n    return a + b\n")
    record = gitleaks_scanner.scan(str(tmp_path), _make_run_shell(str(tmp_path)))
    assert record.finding_count == 0
    assert record.availability == ScannerAvailability.AVAILABLE


# ---- semgrep (SAST) -------------------------------------------------------

@pytest.mark.skipif(
    semgrep_scanner.check_availability(_real_run_shell).status != ScannerAvailability.AVAILABLE,
    reason="semgrep (or its bundled local ruleset) not available in this environment",
)
def test_semgrep_finds_every_bundled_rule_against_a_real_fixture(tmp_path):
    (tmp_path / "vuln.py").write_text(
        "import subprocess, pickle, yaml, hashlib\n\n"
        "def run_cmd(user_input):\n"
        '    subprocess.run("ls -la " + user_input, shell=True)\n\n'
        "def query(cursor, name):\n"
        '    cursor.execute("SELECT * FROM users WHERE name = \'%s\'" % name)\n\n'
        "def load_obj(data):\n"
        "    return pickle.loads(data)\n\n"
        "def load_config(raw):\n"
        "    return yaml.load(raw)\n\n"
        "def weak_hash(pw):\n"
        "    return hashlib.md5(pw.encode()).hexdigest()\n\n"
        "def run_dynamic(code):\n"
        "    eval(code)\n"
    )
    record = semgrep_scanner.scan(str(tmp_path), _make_run_shell(str(tmp_path)))

    assert record.availability == ScannerAvailability.AVAILABLE
    rule_ids = {f.rule_id for f in record.findings}
    assert rule_ids == {
        "dangerous-subprocess-shell-true", "sql-injection-string-format",
        "insecure-deserialization-pickle", "yaml-load-without-safe-loader",
        "eval-or-exec-on-dynamic-input", "weak-hash-for-security-purpose",
    }
    shell_finding = next(f for f in record.findings if f.rule_id == "dangerous-subprocess-shell-true")
    assert shell_finding.severity.value == "high"
    assert shell_finding.cwe == "CWE-78"


@pytest.mark.skipif(
    semgrep_scanner.check_availability(_real_run_shell).status != ScannerAvailability.AVAILABLE,
    reason="semgrep (or its bundled local ruleset) not available in this environment",
)
def test_semgrep_reports_clean_for_safe_code(tmp_path):
    (tmp_path / "safe.py").write_text("def add(a, b):\n    return a + b\n")
    record = semgrep_scanner.scan(str(tmp_path), _make_run_shell(str(tmp_path)))
    assert record.finding_count == 0


# ---- checkov (IaC) --------------------------------------------------------

@pytest.mark.skipif(
    checkov_scanner.check_availability(_real_run_shell).status != ScannerAvailability.AVAILABLE,
    reason="checkov not installed in this environment",
)
def test_checkov_finds_real_terraform_misconfigurations(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "example" {\n'
        '  bucket = "my-bucket"\n'
        '  acl    = "public-read"\n'
        "}\n\n"
        'resource "aws_security_group" "bad_sg" {\n'
        '  name = "bad_sg"\n'
        "  ingress {\n"
        "    from_port   = 22\n"
        "    to_port     = 22\n"
        '    protocol    = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        "  }\n"
        "}\n"
    )
    record = checkov_scanner.scan(str(tmp_path), _make_run_shell(str(tmp_path)))

    assert record.availability == ScannerAvailability.AVAILABLE
    check_ids = {f.rule_id for f in record.findings}
    assert "CKV2_AWS_6" in check_ids  # S3 public access block missing
    assert "CKV_AWS_24" in check_ids  # SG open ingress to port 22
    finding = next(f for f in record.findings if f.rule_id == "CKV2_AWS_6")
    assert finding.file == "main.tf"
    assert finding.resource == "aws_s3_bucket.example"


@pytest.mark.skipif(
    checkov_scanner.check_availability(_real_run_shell).status != ScannerAvailability.AVAILABLE,
    reason="checkov not installed in this environment",
)
def test_checkov_reports_the_s3_finding_resolved_after_the_real_fix(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "example" {\n  bucket = "my-bucket"\n  acl    = "private"\n}\n\n'
        'resource "aws_s3_bucket_public_access_block" "example_block" {\n'
        "  bucket                  = aws_s3_bucket.example.id\n"
        "  block_public_acls       = true\n"
        "  block_public_policy     = true\n"
        "  ignore_public_acls      = true\n"
        "  restrict_public_buckets = true\n"
        "}\n"
    )
    record = checkov_scanner.scan(str(tmp_path), _make_run_shell(str(tmp_path)))
    check_ids = {f.rule_id for f in record.findings}
    assert "CKV2_AWS_6" not in check_ids


# ---- trivy (containers) - CONFIRMED BLOCKED, not skipped -----------------

def test_trivy_is_honestly_reported_blocked_not_faked():
    availability = trivy_scanner.check_availability(_real_run_shell)
    # Both independent paths (native binary, and docker+registry) were
    # exhausted during Phase 4 investigation, in THIS sandbox - asserted
    # directly (not skipped) because "report BLOCKED honestly, don't fake
    # a clean scan" is itself the behavior under test here.
    assert availability.status == ScannerAvailability.BLOCKED
    assert "docker" in availability.reason.lower() or "trivy" in availability.reason.lower()

    # scan() re-checks availability itself (per scanners/base.py's
    # contract) - given BLOCKED, it must return an honest zero-finding
    # record carrying the BLOCKED reason, NEVER a fabricated clean scan
    # (finding_count=0 here means "did not run", not "ran and found
    # nothing", which `availability` on the record disambiguates).
    record = trivy_scanner.scan(".", _real_run_shell)
    assert record.availability == ScannerAvailability.BLOCKED
    assert record.finding_count == 0
    assert record.findings == []
    assert "docker" in record.note.lower() or "trivy" in record.note.lower()


def test_trivy_scan_refuses_to_fabricate_a_result_if_called_while_available(monkeypatch):
    # scan()'s AVAILABLE branch is intentionally unimplemented (SPECIFIED,
    # NOT VERIFIED - matching Phase 3's dependency/scanners/trivy_scanner.py
    # for the exact same reason: no real environment has ever exercised
    # it). Forcing availability=AVAILABLE here (bypassing the real,
    # BLOCKED check) proves that path raises rather than returning a
    # made-up clean/dirty result.
    monkeypatch.setattr(
        trivy_scanner, "check_availability",
        lambda run_shell: AvailabilityResult(ScannerAvailability.AVAILABLE, "forced for this test"),
    )
    with pytest.raises(RuntimeError):
        trivy_scanner.scan(".", _real_run_shell)
