"""Computes real, from-evidence platform progress (Phase 3 Part C).

Every number here comes from something checkable right now: whether a
capability's referenced test file(s) actually pass (one real, live pytest
run per `compute_progress()` call - not a cached claim from an earlier
session), plus whether an explicit `phase_verified` durable event exists
for a phase that already tests COMPLETE. Nothing is hardcoded - there is
no percentage anywhere in this module or in README.md/ARCHITECTURE.md;
`aep status`/`aep progress` are the only source, and they compute it fresh
every time (Phase 3 Part C/G).

Performance note: every capability/phase/overall count is attributed from
a SINGLE pytest invocation over the de-duplicated union of every test file
referenced anywhere in the roadmap (via `--junitxml` per-testcase
`classname`), not one subprocess per capability. An earlier version of
this module ran pytest once per capability plus once per phase plus once
overall - correct, but with several dependency/CVE and GitHub-loop test
files doing real network I/O, that meant the same ~60-90s integration test
file could execute three or more times in a single `aep status` call.
Caught by this module's own test suite (test_cli_status.py) timing out,
not a unit test - fixed by computing every count from one shared run.

"A phase is NOT COMPLETE merely because code exists" is enforced here by
construction: a capability with no test_paths, or whose tests don't pass,
can never read as COMPLETE - see `_capability_status`.
"""
from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Optional

from .roadmap import CapabilityDef, PhaseDef, Roadmap, load_roadmap

CAPABILITY_COMPLETE = "COMPLETE"
CAPABILITY_IN_PROGRESS = "IN_PROGRESS"
CAPABILITY_PENDING = "PENDING"
CAPABILITY_BLOCKED = "BLOCKED"

PHASE_NOT_STARTED = "NOT_STARTED"
PHASE_IN_PROGRESS = "IN_PROGRESS"
PHASE_BLOCKED = "BLOCKED"
PHASE_COMPLETE = "COMPLETE"
PHASE_VERIFIED = "VERIFIED"

PLATFORM_VERIFICATION_PROJECT = "_platform"


@dataclass
class CapabilityStatus:
    id: str
    description: str
    status: str
    tests_passed: int = 0
    tests_failed: int = 0
    reason: str = ""


@dataclass
class PhaseProgress:
    id: int
    name: str
    description: str
    status: str
    percent: float
    completed: list[str] = field(default_factory=list)
    active: list[str] = field(default_factory=list)
    pending: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    capabilities: list[CapabilityStatus] = field(default_factory=list)
    tests_passed: int = 0
    tests_failed: int = 0

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "description": self.description,
            "status": self.status, "percent": self.percent,
            "completed_capabilities": self.completed, "active_capabilities": self.active,
            "pending_capabilities": self.pending, "blocked_capabilities": self.blocked,
            "tests_passed": self.tests_passed, "tests_failed": self.tests_failed,
            "capabilities": [
                {"id": c.id, "description": c.description, "status": c.status,
                 "tests_passed": c.tests_passed, "tests_failed": c.tests_failed, "reason": c.reason}
                for c in self.capabilities
            ],
        }


@dataclass
class PlatformProgress:
    overall_percent: float
    phases: list[PhaseProgress]
    total_tests_passed: int
    total_tests_failed: int

    def phase(self, phase_id: int) -> Optional[PhaseProgress]:
        return next((p for p in self.phases if p.id == phase_id), None)

    def to_dict(self) -> dict:
        return {
            "overall_percent": self.overall_percent,
            "total_tests_passed": self.total_tests_passed,
            "total_tests_failed": self.total_tests_failed,
            "phases": [p.to_dict() for p in self.phases],
        }


def _run_pytest_per_file(repo_root: str, test_paths: list[str],
                          timeout: int = 900) -> dict[str, tuple[int, int]]:
    """Runs pytest ONCE for the given file list and returns
    {test_path: (passed, failed)} attributed via the junit report's
    per-testcase `classname` (dotted module path -> file path). One real
    subprocess call - this is what makes COMPLETE mean "passes right now",
    not "passed once, trust me", without re-running the same file
    redundantly for every capability/phase/overall total that references
    it."""
    if not test_paths:
        return {}
    with NamedTemporaryFile(suffix=".xml", delete=False) as f:
        junit_path = f.name
    try:
        try:
            subprocess.run(
                ["python3", "-m", "pytest", "-q", "--tb=no", f"--junitxml={junit_path}", *test_paths],
                cwd=repo_root, capture_output=True, text=True, timeout=timeout,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return {t: (0, 0) for t in test_paths}
        try:
            tree = ET.parse(junit_path)
        except ET.ParseError:
            return {t: (0, 0) for t in test_paths}

        results: dict[str, tuple[int, int]] = {t: (0, 0) for t in test_paths}
        # Map "tests.test_foo" (or "tests.sub.test_foo") -> "tests/test_foo.py",
        # matched against the actual requested paths so this stays correct
        # regardless of nesting depth.
        by_suffix = {t.replace("\\", "/"): t for t in test_paths}
        for testcase in tree.getroot().iter("testcase"):
            classname = testcase.get("classname", "")
            candidate = classname.replace(".", "/") + ".py"
            match = next((orig for suffix, orig in by_suffix.items()
                          if candidate == suffix or candidate.endswith("/" + suffix)
                          or suffix.endswith(candidate)), None)
            if match is None:
                continue
            passed, failed = results[match]
            if testcase.find("failure") is not None or testcase.find("error") is not None:
                failed += 1
            else:
                passed += 1
            results[match] = (passed, failed)
        return results
    finally:
        Path(junit_path).unlink(missing_ok=True)


def _capability_status(cap: CapabilityDef, file_results: dict[str, tuple[int, int]]) -> CapabilityStatus:
    if cap.blocked:
        return CapabilityStatus(cap.id, cap.description, CAPABILITY_BLOCKED, 0, 0, cap.blocked_reason)
    if not cap.test_paths:
        return CapabilityStatus(cap.id, cap.description, CAPABILITY_PENDING, 0, 0,
                                 "not yet implemented/verified by a test")
    passed = sum(file_results.get(t, (0, 0))[0] for t in cap.test_paths)
    failed = sum(file_results.get(t, (0, 0))[1] for t in cap.test_paths)
    if passed > 0 and failed == 0:
        return CapabilityStatus(cap.id, cap.description, CAPABILITY_COMPLETE, passed, failed)
    if passed > 0:
        return CapabilityStatus(cap.id, cap.description, CAPABILITY_IN_PROGRESS, passed, failed,
                                 f"{failed} test(s) failing")
    return CapabilityStatus(cap.id, cap.description, CAPABILITY_PENDING, passed, failed,
                             "tests not passing (file missing, or 0 tests collected/passed)")


def _phase_status(total: int, completed: int, active: int, blocked: int) -> str:
    if total == 0:
        return PHASE_NOT_STARTED
    if blocked == total:
        return PHASE_BLOCKED
    if completed == total:
        return PHASE_COMPLETE
    if completed == 0 and active == 0 and blocked == 0:
        return PHASE_NOT_STARTED
    return PHASE_IN_PROGRESS


def _has_verification_event(store, phase_id: int) -> bool:
    try:
        events = store.query_events(project_id=PLATFORM_VERIFICATION_PROJECT)
    except Exception:
        return False
    return any(e.action == "phase_verified" and e.details.get("phase_id") == phase_id
               for e in events)


def compute_progress(repo_root: str, roadmap_path: Optional[str] = None,
                      store=None, roadmap: Optional[Roadmap] = None) -> PlatformProgress:
    roadmap = roadmap or load_roadmap(roadmap_path or str(Path(repo_root, "config", "roadmap.yaml")))

    all_paths = sorted({t for phase in roadmap.phases for cap in phase.capabilities
                         for t in cap.test_paths if Path(repo_root, t).exists()})
    file_results = _run_pytest_per_file(repo_root, all_paths)

    phases: list[PhaseProgress] = []
    for phase in roadmap.phases:
        cap_statuses = [_capability_status(cap, file_results) for cap in phase.capabilities]
        completed = [c.id for c in cap_statuses if c.status == CAPABILITY_COMPLETE]
        active = [c.id for c in cap_statuses if c.status == CAPABILITY_IN_PROGRESS]
        pending = [c.id for c in cap_statuses if c.status == CAPABILITY_PENDING]
        blocked = [c.id for c in cap_statuses if c.status == CAPABILITY_BLOCKED]

        phase_files = {t for cap in phase.capabilities for t in cap.test_paths}
        phase_passed = sum(file_results.get(t, (0, 0))[0] for t in phase_files)
        phase_failed = sum(file_results.get(t, (0, 0))[1] for t in phase_files)

        total = len(phase.capabilities)
        status = _phase_status(total, len(completed), len(active), len(blocked))
        percent = round((len(completed) / total * 100.0), 1) if total else 0.0

        if status == PHASE_COMPLETE and store is not None and _has_verification_event(store, phase.id):
            status = PHASE_VERIFIED

        phases.append(PhaseProgress(
            id=phase.id, name=phase.name, description=phase.description, status=status,
            percent=percent, completed=completed, active=active, pending=pending, blocked=blocked,
            capabilities=cap_statuses, tests_passed=phase_passed, tests_failed=phase_failed,
        ))

    total_passed = sum(p[0] for p in file_results.values())
    total_failed = sum(p[1] for p in file_results.values())
    overall = round(sum(p.percent for p in phases) / len(phases), 1) if phases else 0.0
    return PlatformProgress(overall_percent=overall, phases=phases,
                             total_tests_passed=total_passed, total_tests_failed=total_failed)


def record_phase_verified(store, phase_id: int, verified_by: str = "aep verify") -> None:
    """Durably records that a phase's full verification was explicitly run
    and passed - the only way a phase can read as VERIFIED rather than just
    COMPLETE (Phase 3's phase-status enum distinguishes the two on
    purpose: COMPLETE means "tests pass right now", VERIFIED means "someone
    explicitly ran and recorded full verification"). Uses the *existing*
    Event/StateStore machinery under a reserved project id - no new
    storage primitive."""
    from ..models import Event
    from ..state_store import now_iso
    store.append_event(Event(
        id="", actor=verified_by, action="phase_verified", project_id=PLATFORM_VERIFICATION_PROJECT,
        task_id=None, decision=None, timestamp=now_iso(), details={"phase_id": phase_id},
    ))
