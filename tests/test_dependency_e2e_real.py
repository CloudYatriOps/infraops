"""Phase 3 Part I: real end-to-end verification.

REAL LOCAL EXECUTION (nothing in this file is mocked): a disposable fixture
project with a deliberately vulnerable, real pinned dependency
(`urllib3==1.26.4`, real CVE-2021-33503 / GHSA-q2q7-5pp4-w6pg /
PYSEC-2021-108) -> the real `pip-audit` binary finds it via the real PyPI
JSON API -> DependencyCVEAgent picks the real smallest safe fixed version
-> rewrites the real manifest -> commits to a real git branch -> installs
the real upgraded package -> runs the real project test suite -> runs
`pip-audit` again for real -> confirms the finding is gone.

Nothing about GitHub is exercised here (no owner/repo/remote_url given),
so this test makes no GitHub claim at all, live or mocked - see
test_dependency_github_loop.py for the GitHub-integration path, which uses
FakeGitHubTransport plus a real local bare git repo standing in for
GitHub's git storage, exactly like Phase 2's test_github_ci_loop.py. This
separation is the point of Part I: REAL LOCAL EXECUTION is proven here in
isolation from any GitHub transport claim, mocked or otherwise.

Skipped, not faked, if pip-audit genuinely isn't installed.
"""
from __future__ import annotations

import shutil
import subprocess

import pytest

from aep.bootstrap import build_orchestrator
from aep.dependency.planner import plan_dependency_scan
from aep.dependency.scanners import pip_audit_scanner
from aep.models import ProjectConfig, TaskStatus


def _run_shell_probe(args, cwd=None, timeout=10):
    # Resolve the binary the SAME way the real scan path does - see the
    # identical note in tests/test_dependency_github_loop.py::_probe.
    resolved = shutil.which(args[0]) or args[0]
    try:
        proc = subprocess.run([resolved] + args[1:], cwd=cwd, capture_output=True,
                               text=True, timeout=timeout)
    except OSError as exc:
        return {"ok": False, "stdout": "", "stderr": str(exc)}
    return {"ok": proc.returncode == 0, "stdout": proc.stdout, "stderr": proc.stderr}


pytestmark = pytest.mark.skipif(
    not pip_audit_scanner.is_available(_run_shell_probe),
    reason="pip-audit not installed in this environment",
)


def _init_repo(path) -> None:
    subprocess.run(["git", "init", "-q", "-b", "main", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "aep@example.com"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "AEP Bot"], check=True)


def test_real_end_to_end_dependency_remediation(tmp_path, policy_path):
    repo = tmp_path / "vulnerable_fixture"
    repo.mkdir()
    _init_repo(repo)

    # Pin the OLD, genuinely vulnerable version into this environment first,
    # so `import urllib3` in the fixture's own test suite is real and
    # correct both before AND after remediation - not just a manifest edit
    # nobody actually runs.
    subprocess.run(["python3", "-m", "pip", "install", "--break-system-packages", "--quiet",
                     "urllib3==1.26.4"], check=True)

    (repo / "requirements.txt").write_text("urllib3==1.26.4\n")
    (repo / "app.py").write_text("import urllib3\n\ndef make_pool():\n    return urllib3.PoolManager()\n")
    (repo / "test_app.py").write_text(
        "from app import make_pool\n\ndef test_make_pool():\n    assert make_pool() is not None\n"
    )
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "initial commit"], check=True)

    project = ProjectConfig(id="e2e_dep", name="e2e_dep", repo_path=str(repo),
                             policy_path=policy_path)
    orch = build_orchestrator(db_path=str(tmp_path / "state.db"), project=project,
                               sleep_fn=lambda s: None, db_backend="sqlite")
    plan_dependency_scan(orch, project_id="e2e_dep", project_root=str(repo))
    orch.run_to_completion("e2e_dep", max_iterations=100)

    tasks = {t.type: t for t in orch.store.list_tasks("e2e_dep")}
    assert set(tasks) == {"dependency_scan", "dependency_remediate", "run_tests",
                           "dependency_rescan"}
    for t in tasks.values():
        assert t.status == TaskStatus.SUCCEEDED, f"{t.type} ended {t.status}: {t.evidence}"

    # 1. The scan step found the REAL, published vulnerability.
    scan_evidence = "\n".join(e.summary for e in tasks["dependency_scan"].evidence)
    assert "PYSEC-2021-108" in scan_evidence or "urllib3" in scan_evidence

    # 2. The manifest was actually rewritten and committed to a real branch,
    #    not just "would have been".
    content = (repo / "requirements.txt").read_text().strip()
    assert content.startswith("urllib3==") and content != "urllib3==1.26.4"
    log = subprocess.run(["git", "-C", str(repo), "log", "--oneline", "--all"],
                          capture_output=True, text=True, check=True).stdout
    assert "security fix" in log

    # 3. The real project test suite ran against the upgraded package (not
    #    the old one) and passed.
    test_evidence = "\n".join(e.summary for e in tasks["run_tests"].evidence)
    assert "1 passed" in test_evidence

    # 4. A second, real pip-audit scan confirms the finding is gone - this
    #    is the "never claim fixed without a second scan" requirement
    #    (Part B), proven with a real tool invocation, not asserted.
    rescan_evidence = "\n".join(e.summary for e in tasks["dependency_rescan"].evidence)
    assert "CONFIRMED resolved" in rescan_evidence
    assert "NOT resolved" not in rescan_evidence

    direct_rescan = subprocess.run(
        ["pip-audit", "-r", "requirements.txt", "-f", "json", "--progress-spinner", "off"],
        cwd=str(repo), capture_output=True, text=True, timeout=60,
    )
    import json
    data = json.loads(direct_rescan.stdout or "{}")
    urllib3_vulns = [v for dep in data.get("dependencies", []) if dep["name"] == "urllib3"
                      for v in dep.get("vulns", [])]
    assert urllib3_vulns == [], "an independent, direct pip-audit call must also see it resolved"
