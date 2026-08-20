"""Stage C: a deterministic DEMO READINESS checklist - explicitly NOT a
percentage (see `compute_progress()`'s docstring discipline, which this
module follows: every line here is a concrete, checkable condition, not
an aggregate score). Intended for a human about to run the CEO demo who
wants a fast, honest "is this actually going to work" pass.
"""
from __future__ import annotations

import importlib
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent


@dataclass
class ReadinessCheck:
    label: str
    ok: bool
    detail: str = ""


def _check_skill_gate_wired() -> ReadinessCheck:
    # Deliberately checked via source text, not `import aep.orchestrator`:
    # this module lives under `aep.progress`, which is imported from
    # various entry points (including cli.py) at times `aep.orchestrator`
    # may itself be mid-import - importing the class here risks a
    # circular-import failure that has nothing to do with whether the
    # gate is actually wired. A plain source-text check is exactly as
    # deterministic and has zero import-order risk.
    try:
        source = (REPO_ROOT / "src" / "aep" / "orchestrator.py").read_text()
        ok = "_apply_skill_gate" in source and "def run_task" in source
        return ReadinessCheck("orchestrator skill gate wired (_apply_skill_gate)", ok,
                               "" if ok else "orchestrator.py missing _apply_skill_gate/run_task")
    except Exception as exc:  # noqa: BLE001
        return ReadinessCheck("orchestrator skill gate wired (_apply_skill_gate)", False, str(exc))


def _check_importable(label: str, module_name: str) -> ReadinessCheck:
    try:
        importlib.import_module(module_name)
        return ReadinessCheck(label, True)
    except Exception as exc:  # noqa: BLE001
        return ReadinessCheck(label, False, f"{module_name} not importable: {exc}")


def _check_demo_fixture_present() -> ReadinessCheck:
    template = REPO_ROOT / "demo_project_template"
    required = ["app.py", "test_app.py", "config.py"]
    missing = [f for f in required if not (template / f).is_file()]
    ok = template.is_dir() and not missing
    detail = "" if ok else f"missing: {missing}" if template.is_dir() else f"{template} does not exist"
    return ReadinessCheck("demo_project_template/ fixture present", ok, detail)


def _check_e2e_test_passes() -> ReadinessCheck:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "tests/test_end_to_end_demo.py"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120,
    )
    ok = proc.returncode == 0
    detail = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else proc.stderr.strip()[-300:]
    return ReadinessCheck("tests/test_end_to_end_demo.py passes", ok, detail)


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
        _check_e2e_test_passes(),
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
