"""Autonomous work loop (Phase 8 Part 5).

DISCOVER -> PRIORITIZE -> PLAN -> POLICY CHECK -> EXECUTE -> VERIFY ->
RECORD EVIDENCE -> RESCHEDULE/FOLLOW UP -> ESCALATE IF REQUIRED.

Every job type here dispatches to a Phase 3-7 read-only discovery/status
path that ALREADY exists (dependency/CVE inventory, security posture,
infrastructure inventory, CI/CD status, operations incident review) - this
module coordinates and records evidence, it never reimplements scanning
logic. `stale_task_recovery` is the one genuinely Phase-8-native job: it
calls the watchdog (`health.py`) plus the durable lease/lock tables.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..models import Event
from ..policy import PolicyEngine
from ..state_store import StateStore
from . import health as health_mod

# Fixed policy action literal - never built from job/project content.
POLICY_ACTION_SCHEDULED_SCAN = "runtime.scheduled_scan"


@dataclass
class WorkLoopResult:
    job_id: str
    job_type: str
    stage: str          # last stage reached
    outcome: str         # REAL | MOCKED | UNAVAILABLE | BLOCKED | ESCALATED | DENIED
    detail: str


def _discover_dependency_cve(repo: str) -> dict:
    from ..dependency.inventory import build_inventory
    import subprocess

    def run_shell(args, cwd=None, timeout=90):
        try:
            proc = subprocess.run(args, cwd=cwd or repo, capture_output=True, text=True, timeout=timeout)
            return {"ok": proc.returncode == 0, "exit_code": proc.returncode,
                    "stdout": proc.stdout, "stderr": proc.stderr, "args": args}
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            return {"ok": False, "exit_code": -1, "stdout": "", "stderr": str(e), "args": args}

    inv = build_inventory(repo, run_shell)
    return {"manifests_found": len(inv.manifests), "scan_records": len(inv.scan_records)}


def _discover_security(repo: str) -> dict:
    from ..security.scan_runner import run_security_scan
    import subprocess

    def run_shell(args, cwd=None, timeout=90):
        try:
            proc = subprocess.run(args, cwd=cwd or repo, capture_output=True, text=True, timeout=timeout)
            return {"ok": proc.returncode == 0, "exit_code": proc.returncode,
                    "stdout": proc.stdout, "stderr": proc.stderr, "args": args}
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            return {"ok": False, "exit_code": -1, "stdout": "", "stderr": str(e), "args": args}

    res = run_security_scan(repo, run_shell)
    return {"findings": len(res.records)}


def _discover_infrastructure(repo: str) -> dict:
    from ..infra.discovery import discover_infrastructure
    inv = discover_infrastructure(repo)
    return {"assets_found": len(inv.assets)}


def _discover_ci(repo: str) -> dict:
    from ..cicd.discovery import discover_pipeline
    pipeline = discover_pipeline(repo)
    return {"workflows_found": len(pipeline.workflows)}


def _discover_operations(store: StateStore, project_id: str) -> dict:
    from ..operations.memory import list_incidents
    records = list_incidents(store, project_id)
    return {"incident_count": len(records)}


def _stale_task_recovery(store: StateStore, heartbeat_timeout_s: float = 60.0,
                          stuck_task_timeout_s: float = 300.0) -> dict:
    workers = store.list_workers()
    leases = store.list_leases()
    report = health_mod.assess(workers, leases, heartbeat_timeout_s, stuck_task_timeout_s)
    for rec in report.recommendations:
        if rec.kind == "requeue_task":
            store.force_release_lease(rec.target)
    return report.to_dict()


# job_type -> callable(job, store, policy, repo) -> (outcome_str, detail_dict)
def _run_job(job: dict, store: StateStore, policy: PolicyEngine, repo: Optional[str]) -> WorkLoopResult:
    job_type = job["job_type"]
    project_id = job["project_id"]

    # POLICY CHECK: every scheduled job goes through the SAME PolicyEngine
    # every other capability uses, with a fixed string literal action -
    # never an f-string built from job_type/project content.
    decision = policy.evaluate(POLICY_ACTION_SCHEDULED_SCAN, {"job_type": job_type})
    if decision.decision.value == "DENY":
        return WorkLoopResult(job["job_id"], job_type, "POLICY_CHECK", "DENIED", decision.reason)

    try:
        if job_type in ("dependency_cve_scan",) and repo:
            detail = _discover_dependency_cve(repo)
            outcome = "REAL"
        elif job_type in ("secret_scan", "sast_scan") and repo:
            detail = _discover_security(repo)
            outcome = "REAL"
        elif job_type in ("iac_scan", "infrastructure_discovery") and repo:
            detail = _discover_infrastructure(repo)
            outcome = "REAL"
        elif job_type == "ci_status_monitor" and repo:
            detail = _discover_ci(repo)
            outcome = "REAL"
        elif job_type == "deployment_verification":
            detail = {"note": "no live deployment target configured in this environment"}
            outcome = "UNAVAILABLE"
        elif job_type in ("operations_health_review", "incident_recurrence_analysis"):
            detail = _discover_operations(store, project_id)
            outcome = "REAL"
        elif job_type == "stale_task_recovery":
            detail = _stale_task_recovery(store)
            outcome = "REAL"
        else:
            detail = {"note": f"no repo configured for job_type={job_type}"}
            outcome = "UNAVAILABLE"
    except Exception as e:  # never fabricate success - a raised exception is BLOCKED, not passing
        detail = {"error": str(e)}
        outcome = "BLOCKED"

    store.append_event(Event(
        id="", actor="runtime.workloop", action=POLICY_ACTION_SCHEDULED_SCAN,
        project_id=project_id, task_id=None, decision=decision.decision.value,
        timestamp="", details={"job_id": job["job_id"], "job_type": job_type,
                               "outcome": outcome, "evidence": detail},
    ))
    return WorkLoopResult(job["job_id"], job_type, "RECORD_EVIDENCE", outcome, str(detail))
