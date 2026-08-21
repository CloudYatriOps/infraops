"""Phase 4 Part 12: end-to-end DISCOVER -> CLASSIFY -> REMEDIATE -> TEST ->
RESCAN -> VERIFY, using the REAL gitleaks/semgrep/checkov binaries end to
end through SecurityAgent + the real orchestrator - no mocked scanner
output anywhere in this file. GitHub push/PR/CI is NOT exercised here
(no `owner`/`repo`/`remote_url` is given to `plan_security_scan`, so
`SecurityAgent._scan` never builds those follow-up tasks - see
dependency/planner.py's identical `include_github` gate, reused
unmodified) - Phase 3's test_dependency_github_loop.py already proves
that hand-off works for the security remediation chain's shared
push/PR/monitor_ci task shapes; duplicating a full mocked-GitHub-transport
test here would just re-test the same wiring twice.

Container scanning (the fourth category Part 12 asks for) is reported
honestly BLOCKED (see security/scanners/trivy_scanner.py) rather than
mocked - `test_container_category_is_blocked_not_mocked` below asserts
exactly that, per Part 12's explicit instruction.
"""
from __future__ import annotations

import subprocess

import pytest

from aep.bootstrap import build_orchestrator
from aep.models import ProjectConfig, TaskStatus
from aep.security.discovery import scanner_for_category
from aep.security.models import ScannerAvailability
from aep.security.planner import plan_security_scan


def _probe(args, cwd=None, timeout=10):
    try:
        proc = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return {"ok": proc.returncode == 0}
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return {"ok": False}


def _init_repo(path) -> None:
    subprocess.run(["git", "init", "-q", "-b", "main", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "aep@example.com"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "AEP Bot"], check=True)


def _orch(tmp_path, project):
    return build_orchestrator(db_path=str(tmp_path / "state.db"), project=project,
                               sleep_fn=lambda s: None, db_backend="sqlite")


_gitleaks_available = (scanner_for_category("secret").check_availability(_probe).status
                        == ScannerAvailability.AVAILABLE)
_semgrep_available = (scanner_for_category("sast").check_availability(_probe).status
                       == ScannerAvailability.AVAILABLE)
_checkov_available = (scanner_for_category("iac").check_availability(_probe).status
                       == ScannerAvailability.AVAILABLE)


@pytest.mark.skipif(not _gitleaks_available, reason="gitleaks not installed in this environment")
def test_e2e_secret_discover_remediate_test_rescan_verify(tmp_path):
    repo = tmp_path / "e2e_secret"
    repo.mkdir()
    _init_repo(repo)
    # A clean-looking (non-placeholder) fake AWS key, so
    # assess_credential_likelihood correctly flags it for rotation - a
    # real, non-trivial demonstration, not a softball placeholder value.
    (repo / "config.py").write_text('AWS_ACCESS_KEY_ID = "AKIAQWERTY7788UIOP99"\n')
    (repo / "app.py").write_text("def add(a, b):\n    return a + b\n")
    (repo / "test_app.py").write_text("from app import add\n\ndef test_add():\n"
                                        "    assert add(2, 3) == 5\n")
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "initial"], check=True)

    project = ProjectConfig(id="e2esecret", name="e2esecret", repo_path=str(repo),
                             policy_path="src/aep/config/policy.yaml")
    orch = _orch(tmp_path, project)

    # DISCOVER + CLASSIFY: a real gitleaks scan of the real fixture.
    plan_security_scan(orch, project_id="e2esecret", project_root=str(repo),
                        categories=["secret"])
    orch.run_to_completion("e2esecret", max_iterations=200)

    all_tasks = orch.store.list_tasks("e2esecret")
    scan_task = next(t for t in all_tasks if t.type == "security_scan")
    assert scan_task.status == TaskStatus.SUCCEEDED
    assert any("gitleaks" in e.summary for e in scan_task.evidence)

    remediate_task = next((t for t in all_tasks if t.type == "security_remediate"), None)
    assert remediate_task is not None, "a HIGH secret finding must produce a remediation task"
    assert remediate_task.status == TaskStatus.SUCCEEDED, remediate_task.evidence

    # REMEDIATE: the literal is actually gone from the real file on disk.
    content = (repo / "config.py").read_text()
    assert "AKIAQWERTY7788UIOP99" not in content
    assert "os.environ" in content

    # TEST: the existing test suite still runs (run_tests task, unmodified).
    test_task = next(t for t in all_tasks if t.type == "run_tests")
    assert test_task.status == TaskStatus.SUCCEEDED

    # RESCAN + VERIFY: a SECOND real gitleaks invocation confirms the
    # specific finding is gone - not assumed because the literal "looks"
    # removed.
    rescan_task = next(t for t in all_tasks if t.type == "security_rescan")
    assert rescan_task.status == TaskStatus.SUCCEEDED
    assert any("CONFIRMED resolved" in e.summary for e in rescan_task.evidence)

    # No raw secret value anywhere in the durable task/event evidence.
    for t in all_tasks:
        for e in t.evidence:
            assert "AKIAQWERTY7788UIOP99" not in e.summary


@pytest.mark.skipif(not _semgrep_available, reason="semgrep not available in this environment")
def test_e2e_sast_discover_remediate_test_rescan_verify(tmp_path):
    repo = tmp_path / "e2e_sast"
    repo.mkdir()
    _init_repo(repo)
    (repo / "app.py").write_text(
        'import subprocess\n\n'
        'def list_dir(user_input):\n'
        '    subprocess.run("ls -la " + user_input, shell=True)\n'
        '    return True\n'
    )
    (repo / "test_app.py").write_text(
        "from app import list_dir\n\ndef test_list_dir():\n    assert list_dir('.') is True\n"
    )
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "initial"], check=True)

    project = ProjectConfig(id="e2esast", name="e2esast", repo_path=str(repo),
                             policy_path="src/aep/config/policy.yaml")
    orch = _orch(tmp_path, project)
    plan_security_scan(orch, project_id="e2esast", project_root=str(repo), categories=["sast"])
    orch.run_to_completion("e2esast", max_iterations=200)

    all_tasks = orch.store.list_tasks("e2esast")
    scan_task = next(t for t in all_tasks if t.type == "security_scan")
    assert scan_task.status == TaskStatus.SUCCEEDED
    assert any("semgrep" in e.summary for e in scan_task.evidence)

    remediate_task = next((t for t in all_tasks if t.type == "security_remediate"), None)
    assert remediate_task is not None
    assert remediate_task.status == TaskStatus.SUCCEEDED, remediate_task.evidence

    content = (repo / "app.py").read_text()
    assert "shell=False" in content
    assert "shell=True" not in content

    test_task = next(t for t in all_tasks if t.type == "run_tests")
    assert test_task.status == TaskStatus.SUCCEEDED

    rescan_task = next(t for t in all_tasks if t.type == "security_rescan")
    assert rescan_task.status == TaskStatus.SUCCEEDED
    assert any("CONFIRMED resolved" in e.summary for e in rescan_task.evidence)


@pytest.mark.skipif(not _checkov_available, reason="checkov not installed in this environment")
def test_e2e_iac_discover_remediate_rescan_verify_and_escalates_the_unfixable_finding(tmp_path):
    repo = tmp_path / "e2e_iac"
    repo.mkdir()
    _init_repo(repo)
    (repo / "main.tf").write_text(
        'resource "aws_s3_bucket" "example" {\n  bucket = "my-bucket"\n  acl    = "public-read"\n}\n\n'
        'resource "aws_security_group" "bad_sg" {\n  name = "bad_sg"\n  ingress {\n'
        '    from_port   = 22\n    to_port     = 22\n    protocol    = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
    )
    (repo / "app.py").write_text("def add(a, b):\n    return a + b\n")
    (repo / "test_app.py").write_text("from app import add\n\ndef test_add():\n"
                                        "    assert add(2, 3) == 5\n")
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "initial"], check=True)

    project = ProjectConfig(id="e2eiac", name="e2eiac", repo_path=str(repo),
                             policy_path="src/aep/config/policy.yaml")
    orch = _orch(tmp_path, project)
    plan_security_scan(orch, project_id="e2eiac", project_root=str(repo), categories=["iac"])
    orch.run_to_completion("e2eiac", max_iterations=200)

    all_tasks = orch.store.list_tasks("e2eiac")
    scan_task = next(t for t in all_tasks if t.type == "security_scan")
    assert scan_task.status == TaskStatus.SUCCEEDED
    assert any("checkov" in e.summary for e in scan_task.evidence)

    remediate_task = next((t for t in all_tasks if t.type == "security_remediate"), None)
    assert remediate_task is not None
    assert remediate_task.status == TaskStatus.SUCCEEDED, remediate_task.evidence

    content = (repo / "main.tf").read_text()
    assert 'acl    = "private"' in content
    assert "aws_s3_bucket_public_access_block" in content
    # The open-ingress security group finding is NOT auto-fixed (picking a
    # "safe" CIDR needs an operator) - it must be escalated instead.
    assert any(t.type == "security_escalate" for t in all_tasks)

    rescan_task = next(t for t in all_tasks if t.type == "security_rescan")
    assert rescan_task.status == TaskStatus.SUCCEEDED
    assert any("CONFIRMED resolved" in e.summary for e in rescan_task.evidence)


def test_container_category_is_blocked_not_mocked():
    """Part 12's explicit instruction: where an external tool is
    unavailable, report it honestly and keep the capability BLOCKED
    rather than mocking success. No task/agent path in this platform ever
    invents a container-scanning result."""
    module = scanner_for_category("container")
    availability = module.check_availability(_probe)
    assert availability.status in (ScannerAvailability.BLOCKED, ScannerAvailability.UNAVAILABLE)
    assert availability.reason
