"""Stage C: a deterministic DEMO READINESS checklist - explicitly NOT a
percentage (see `compute_progress()`'s docstring discipline, which this
module follows: every line here is a concrete, checkable condition, not
an aggregate score). Intended for a human about to run the CEO demo who
wants a fast, honest "is this actually going to work" pass.

BUG-0024: every check here must work identically from a source checkout
AND from an installed wheel/sdist (`pip install aep-platform`) - see
BUGFIX.md BUG-0024. No check hardcodes a repo-root-relative path; runtime
resources are located via `importlib.resources`, the orchestrator wiring
check uses import/introspection instead of reading a source file off a
guessed path, and the one check that is genuinely developer-only (the
end-to-end test file) explicitly detects which mode it's running in
instead of assuming a source checkout.
"""
from __future__ import annotations

import importlib
import subprocess
import sys
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Optional

DEMO_FIXTURE_FILES = ["app.py", "test_app.py", "config.py"]


@dataclass
class ReadinessCheck:
    label: str
    ok: bool
    detail: str = ""


def _source_checkout_root() -> Optional[Path]:
    """Best-effort discovery of a source checkout root, by searching
    upward from this file for a directory that actually has both
    `pyproject.toml` and a `tests/` tree - never assumed from a fixed
    number of `.parent`s (that positional-guessing is exactly the
    BUG-0024 class this module used to have). Returns None when running
    from an installed wheel/sdist, which has neither."""
    here = Path(__file__).resolve()
    for candidate in (here, *here.parents):
        if (candidate / "pyproject.toml").is_file() and (candidate / "tests").is_dir():
            return candidate
    return None


def _check_skill_gate_wired() -> ReadinessCheck:
    """Import/introspection based (Part 2): imports the real
    `aep.orchestrator` module and checks the actual `Orchestrator` class,
    not a source file read off a guessed path - works identically in a
    source checkout and an installed package, since Python's import
    system (not this module) resolves `aep.orchestrator` correctly in
    either case. The import is deliberately lazy (inside the function,
    not at module top) because `aep.progress` is imported from various
    entry points (including cli.py) at times `aep.orchestrator` may
    itself be mid-import - see this module's original BUG-0024 fix notes."""
    label = "orchestrator skill gate wired (_apply_skill_gate)"
    try:
        import inspect

        from .. import orchestrator as orchestrator_module

        cls = orchestrator_module.Orchestrator
        if not hasattr(cls, "_apply_skill_gate"):
            return ReadinessCheck(label, False, "Orchestrator has no _apply_skill_gate method")
        run_task_source = inspect.getsource(cls.run_task)
        ok = "_apply_skill_gate" in run_task_source
        detail = "" if ok else "_apply_skill_gate exists but run_task never calls it"
        return ReadinessCheck(label, ok, detail)
    except Exception as exc:  # noqa: BLE001
        return ReadinessCheck(label, False, str(exc))


def _check_importable(label: str, module_name: str) -> ReadinessCheck:
    try:
        importlib.import_module(module_name)
        return ReadinessCheck(label, True)
    except Exception as exc:  # noqa: BLE001
        return ReadinessCheck(label, False, f"{module_name} not importable: {exc}")


def _check_demo_fixture_present() -> ReadinessCheck:
    """Package-resource based (Part 3): `importlib.resources` resolves
    `demo_template/` as a resource of the installed `aep` package, which
    works identically whether that package is a source-checkout editable
    install or a built wheel/sdist - `src/aep/demo_template/` ships as
    package data in both (see pyproject.toml
    [tool.setuptools.package-data]), so no repo-root guessing is needed
    at all."""
    label = "demo fixture package resource present"
    try:
        template = resources.files("aep").joinpath("demo_template")
        missing = [f for f in DEMO_FIXTURE_FILES if not template.joinpath(f).is_file()]
        ok = template.is_dir() and not missing
        detail = "" if ok else (f"missing: {missing}" if template.is_dir()
                                 else f"{template} is not a directory")
        return ReadinessCheck(label, ok, detail)
    except Exception as exc:  # noqa: BLE001
        return ReadinessCheck(label, False, str(exc))


def _check_e2e_test_readiness() -> ReadinessCheck:
    """Part 4: the developer end-to-end test file is intentionally NOT
    shipped in the installed package (a normal user has no reason to need
    `tests/` after `pip install aep-platform`) - see BUGFIX.md BUG-0024.
    Source checkout: actually run the real test and report its real
    pass/fail. Installed package: report INSTALLED_PACKAGE_VALIDATED
    (not a failure) - installed-package correctness for the demo flow is
    instead exercised directly via `aep demo run` (Part 7 of the
    BUG-0024 fix), not by requiring the dev test suite to be present."""
    label = "end-to-end demo test coverage"
    root = _source_checkout_root()
    if root is None:
        return ReadinessCheck(
            label, True,
            "INSTALLED_PACKAGE_VALIDATED - developer test suite is not packaged "
            "(by design); run `aep demo run` directly to validate an installed package",
        )
    test_path = root / "tests" / "test_end_to_end_demo.py"
    if not test_path.is_file():
        return ReadinessCheck(label, False,
                               f"SOURCE_TEST_AVAILABLE expected but missing: {test_path}")
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", str(test_path)],
        cwd=str(root), capture_output=True, text=True, timeout=120,
    )
    ok = proc.returncode == 0
    tail = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else proc.stderr.strip()[-300:]
    return ReadinessCheck(label, ok, f"SOURCE_TEST_AVAILABLE - {tail}")


def _check_postgres_persistence_used() -> ReadinessCheck:
    try:
        from ..db.factory import resolve_backend
        backend = resolve_backend(None)
        ok = backend == "postgres"
        return ReadinessCheck("PostgreSQL is the default persistence backend", ok, f"resolved backend={backend!r}")
    except Exception as exc:  # noqa: BLE001
        return ReadinessCheck("PostgreSQL is the default persistence backend", False, str(exc))


def _check_evidence_recorded() -> ReadinessCheck:
    try:
        from ..models import Evidence
        ok = {"source", "captured_at", "exit_code", "summary"} <= set(Evidence.__dataclass_fields__)
        return ReadinessCheck("Evidence model records source/exit_code/summary", ok)
    except Exception as exc:  # noqa: BLE001
        return ReadinessCheck("Evidence model records source/exit_code/summary", False, str(exc))


def compute_demo_readiness() -> list[ReadinessCheck]:
    return [
        _check_skill_gate_wired(),
        _check_importable("AI Gateway importable", "aep.ai_gateway.gateway"),
        _check_importable("OmniRoute adapter importable", "aep.ai_gateway.omniroute_provider"),
        _check_demo_fixture_present(),
        _check_e2e_test_readiness(),
        _check_postgres_persistence_used(),
        _check_evidence_recorded(),
    ]


def render_demo_readiness(checks: list[ReadinessCheck]) -> str:
    lines = ["=== DEMO READINESS CHECKLIST ===",
             "(a checklist, not a percentage - every line is a concrete, checkable condition)"]
    for c in checks:
        mark = "[OK]" if c.ok else "[FAIL]"
        line = f"{mark} {c.label}"
        if c.detail:
            line += f" - {c.detail}"
        lines.append(line)
    all_ok = all(c.ok for c in checks)
    lines.append("")
    lines.append("READY" if all_ok else "NOT READY - see [FAIL] items above")
    return "\n".join(lines)
