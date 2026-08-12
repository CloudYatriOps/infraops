"""Remediation logic (Phase 4 Part 4/5/6/13). Entirely offline/fast - no
real scanner invocation needed here, since `plan_*_remediation` only takes
a `SecurityFinding` (already normalized) plus file content."""
from __future__ import annotations

import json
import subprocess

from aep.security.models import SecurityCategory, SecurityFinding, SecuritySeverity
from aep.security.remediation import (
    apply_iac_remediation_plan, apply_sast_remediation_plan, apply_secret_remediation_plan,
    assess_credential_likelihood, inspect_git_history_for_secret, plan_iac_remediation,
    plan_sast_remediation, plan_secret_remediation,
)
from aep.security.secret_manager import EnvVarSecretReference


def _finding(**overrides) -> SecurityFinding:
    base = dict(id="f1", scanner="test", category=SecurityCategory.SECRET,
                severity=SecuritySeverity.HIGH, confidence="high", file="config.py", line=1,
                resource=None, description="d", evidence="e", remediation="r", rule_id="aws-access-token")
    base.update(overrides)
    return SecurityFinding(**base)


# ---- credential likelihood (Part 4 step 1) -------------------------------

def test_placeholder_values_are_not_treated_as_real_credentials():
    assessment = assess_credential_likelihood("AKIAABCD1234EFGH5678",
                                                'AWS_ACCESS_KEY_ID = "AKIAABCD1234EFGH5678"  '
                                                '# placeholder, not real')
    assert assessment.likely_real is False


def test_well_known_documentation_example_is_not_treated_as_real():
    assessment = assess_credential_likelihood("AKIAIOSFODNN7EXAMPLE")
    assert assessment.likely_real is False


def test_a_clean_looking_value_is_treated_as_likely_real_and_flagged_for_rotation():
    assessment = assess_credential_likelihood("AKIAZZZZ9999QQQQ1111")
    assert assessment.likely_real is True
    assert "rotation" in assessment.reason


# ---- secret remediation (Part 4) -----------------------------------------

def test_secret_plan_never_contains_the_raw_value_anywhere():
    finding = _finding()
    content = 'AWS_ACCESS_KEY_ID = "AKIAZZZZ9999QQQQ1111"\n'
    plan = plan_secret_remediation(finding, content)
    assert plan is not None
    dumped = json.dumps(vars(plan))
    assert "AKIAZZZZ9999QQQQ1111" not in dumped
    assert plan.var_name == "AWS_ACCESS_KEY_ID"
    assert plan.reference_snippet == 'os.environ["AWS_ACCESS_KEY_ID"]'
    assert plan.rotation_recommended is True


def test_apply_secret_plan_removes_the_literal_and_adds_the_import():
    finding = _finding()
    content = 'AWS_ACCESS_KEY_ID = "AKIAZZZZ9999QQQQ1111"\n'
    plan = plan_secret_remediation(finding, content)
    fixed = apply_secret_remediation_plan(content, plan)
    assert "AKIAZZZZ9999QQQQ1111" not in fixed
    assert "import os" in fixed
    assert 'AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]' in fixed


def test_secret_plan_refuses_unrecognized_shapes_rather_than_guessing():
    finding = _finding(line=1)
    # Not a simple `NAME = "literal"` assignment - e.g. an f-string built
    # from a function call. Must return None (escalate), never guess.
    content = "AWS_ACCESS_KEY_ID = build_key(region, account)\n"
    assert plan_secret_remediation(finding, content) is None


def test_env_var_secret_reference_adapter_never_needs_the_value():
    ref = EnvVarSecretReference()
    name = ref.suggest_env_var_name("config.py", "aws-access-token")
    assert ref.reference_snippet("python", name) == f'os.environ["{name}"]'
    assert ref.reference_snippet("node", name) == f"process.env.{name}"
    assert "never commit" in ref.setup_instructions(name)


def test_git_history_inspection_is_read_only_and_reports_prior_commit_count(tmp_path):
    subprocess.run(["git", "init", "-q", "-b", "main", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "a@a.com"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "a"], check=True)
    (tmp_path / "config.py").write_text("X = 1\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-q", "-m", "one"], check=True)
    (tmp_path / "config.py").write_text("X = 2\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-q", "-m", "two"], check=True)

    def run_shell(args, cwd=None, timeout=15):
        proc = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return {"ok": proc.returncode == 0, "stdout": proc.stdout, "stderr": proc.stderr}

    result = inspect_git_history_for_secret(run_shell, str(tmp_path), "config.py")
    assert result["checked"] is True
    assert "2 prior commit" in result["note"]


# ---- SAST remediation (Part 5) --------------------------------------------

def test_sast_plan_only_matches_the_exact_verified_shape():
    content = 'import subprocess\n\ndef f(x):\n    subprocess.run("ls -la " + x, shell=True)\n'
    # line is 1-indexed; the vulnerable line is line 4 in this content.
    finding = _finding(category=SecurityCategory.SAST, rule_id="dangerous-subprocess-shell-true",
                        file="app.py", line=4)
    plan = plan_sast_remediation(finding, content)
    assert plan is not None
    fixed = apply_sast_remediation_plan(content, plan)
    assert "shell=False" in fixed
    assert "shell=True" not in fixed
    assert "['ls', '-la', x]" in fixed


def test_sast_plan_refuses_an_unrecognized_shape():
    finding = _finding(category=SecurityCategory.SAST, rule_id="dangerous-subprocess-shell-true",
                        file="app.py", line=1)
    # An f-string, not the narrow "literal" + var shape this fixer verifies.
    content = 'subprocess.run(f"ls -la {x}", shell=True)\n'
    assert plan_sast_remediation(finding, content) is None


def test_sast_plan_refuses_findings_from_other_rules():
    finding = _finding(category=SecurityCategory.SAST, rule_id="sql-injection-string-format",
                        file="app.py", line=1)
    content = 'cursor.execute("SELECT * FROM t WHERE x = \'%s\'" % x)\n'
    assert plan_sast_remediation(finding, content) is None


# ---- IaC remediation (Part 6) ----------------------------------------------

def test_iac_plan_fixes_public_s3_acl_and_adds_access_block():
    finding = _finding(category=SecurityCategory.IAC, rule_id="CKV2_AWS_6", file="main.tf",
                        resource="aws_s3_bucket.example")
    content = ('resource "aws_s3_bucket" "example" {\n  bucket = "my-bucket"\n'
               '  acl    = "public-read"\n}\n')
    plan = plan_iac_remediation(finding, content)
    assert plan is not None
    fixed = apply_iac_remediation_plan(content, plan)
    assert 'acl    = "private"' in fixed
    assert "aws_s3_bucket_public_access_block" in fixed
    assert "example_block" in fixed


def test_iac_plan_does_not_touch_the_security_group_finding():
    # Restricting an open ingress CIDR needs operator knowledge this
    # platform doesn't have - must escalate, never guess a "safe" CIDR.
    finding = _finding(category=SecurityCategory.IAC, rule_id="CKV_AWS_24", file="main.tf",
                        resource="aws_security_group.bad_sg")
    content = ('resource "aws_security_group" "bad_sg" {\n'
               '  ingress {\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n')
    assert plan_iac_remediation(finding, content) is None
