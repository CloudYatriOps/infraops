"""BUG-0024: `demo_readiness.py`'s checks must work identically from a
source checkout and an installed wheel/sdist - see BUGFIX.md BUG-0024.
Unit-level coverage of the package-aware logic itself (the real
installed-wheel acceptance test lives in the release process, not here -
building and installing a wheel per test run is out of scope for the
fast unit suite); `tests/test_cli_demo.py::test_demo_readiness_prints_checklist_not_percentage`
already covers the CLI-level source-checkout path end to end."""
from __future__ import annotations

import os
import subprocess
import sys

from aep.progress import demo_readiness


def test_source_checkout_root_found_when_running_tests():
    # This test file itself only exists in a source checkout, so running
    # it at all proves we're in one - the real repo root must be found.
    root = demo_readiness._source_checkout_root()
    assert root is not None
    assert (root / "pyproject.toml").is_file()
    assert (root / "tests").is_dir()


def test_source_checkout_root_none_without_markers(tmp_path, monkeypatch):
    # No pyproject.toml/tests/ anywhere above a bare tmp dir - simulates
    # what an installed wheel's site-packages location looks like.
    fake_module_path = tmp_path / "site-packages" / "aep" / "progress" / "demo_readiness.py"
    fake_module_path.parent.mkdir(parents=True)
    fake_module_path.write_text("# fake")
    monkeypatch.setattr(demo_readiness, "__file__", str(fake_module_path))
    assert demo_readiness._source_checkout_root() is None


def test_demo_fixture_present_via_importlib_resources():
    check = demo_readiness._check_demo_fixture_present()
    assert check.ok, check.detail


def test_skill_gate_wired_via_import_introspection():
    check = demo_readiness._check_skill_gate_wired()
    assert check.ok, check.detail
    # Never reads orchestrator.py off a guessed path.
    assert "orchestrator.py" not in check.detail


def test_skill_gate_wired_survives_a_genuinely_cold_import():
    """Real bug found and fixed in this pass, not hypothetical: importing
    `aep.orchestrator` as the FIRST touch of its own dependency graph
    (orchestrator -> agents -> agents.ci_diagnose_agent -> github.planner
    -> orchestrator, a real cycle) fails with "cannot import name
    'Orchestrator' from partially initialized module". Every real entry
    point (aep.cli -> aep.bootstrap) coincidentally avoids this because
    bootstrap.py imports `.agents` before `.orchestrator` - but a
    same-process unit test can't reliably reproduce or catch a regression
    of this, because whether it fails depends on which OTHER test ran
    first and incidentally warmed `aep.orchestrator` already. A genuinely
    fresh subprocess is the only way to guarantee the cold path every
    time - reproduced live: `python -c "import aep.orchestrator"` alone
    fails with exactly this error on this codebase."""
    repo_root = demo_readiness._source_checkout_root()
    assert repo_root is not None
    env = {**os.environ, "PYTHONPATH": str(repo_root / "src")}
    proc = subprocess.run(
        [sys.executable, "-c",
         "from aep.progress.demo_readiness import _check_skill_gate_wired\n"
         "r = _check_skill_gate_wired()\n"
         "assert r.ok, r.detail\n"
         "print('OK')\n"],
        env=env, capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "OK" in proc.stdout


def test_e2e_check_reports_installed_package_validated_without_running_pytest(monkeypatch):
    monkeypatch.setattr(demo_readiness, "_source_checkout_root", lambda: None)

    def _fail_if_called(*args, **kwargs):
        raise AssertionError("must not shell out to pytest in installed-package mode")

    monkeypatch.setattr(subprocess, "run", _fail_if_called)
    check = demo_readiness._check_e2e_test_readiness()
    assert check.ok
    assert "INSTALLED_PACKAGE_VALIDATED" in check.detail


def test_e2e_check_runs_real_test_in_source_checkout_mode():
    check = demo_readiness._check_e2e_test_readiness()
    assert check.ok, check.detail
    assert "SOURCE_TEST_AVAILABLE" in check.detail


def test_compute_demo_readiness_all_ok_from_source_checkout():
    checks = demo_readiness.compute_demo_readiness()
    failures = [c for c in checks if not c.ok]
    assert not failures, failures
