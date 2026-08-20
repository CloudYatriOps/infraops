"""Live runtime status payload builder (Phase 8 Part 9).

Deliberately separate from `progress/calculator.py` (platform DEVELOPMENT
progress, computed from pytest results) and `progress/deployability.py`
(the deployability enum) - this module reports OPERATIONAL state of a
runtime that has actually been started against a given StateStore db, not
"how much of Phase 8 is built". A high development percentage never
implies this reports anything about a live process (Part 10).
"""
from __future__ import annotations

from ..state_store import StateStore, now_iso
from . import health as health_mod


def build_runtime_status_payload(store: StateStore, supervisor_id: str = None,
                                  heartbeat_timeout_s: float = 60.0,
                                  stuck_task_timeout_s: float = 300.0) -> dict:
    workers = store.list_workers(supervisor_id)
    leases = store.list_leases()
    schedules = store.list_schedules()
    locks = store.list_project_locks()
    report = health_mod.assess(workers, leases, heartbeat_timeout_s, stuck_task_timeout_s)

    active = [w for w in workers if w["status"] == "BUSY"]
    idle = [w for w in workers if w["status"] == "IDLE"]
    restart_count = sum(w["restart_count"] for w in workers)

    due_now = [s for s in schedules if s["next_run_at"] <= now_iso()]
    upcoming = sorted(schedules, key=lambda s: s["next_run_at"])[:5]

    running_rows = []
    for lease in leases:
        running_rows.append({
            "project": lease["project_id"], "task": lease["task_id"],
            "worker": lease["worker_id"], "state": "RUNNING",
            "started": lease["acquired_at"],
        })

    return {
        "supervisor": supervisor_id or "(any)",
        "health": report.state,
        "workers": {"total": len(workers), "active": len(active), "idle": len(idle),
                    "restart_count": restart_count},
        "queue_depth": len(due_now),
        "running_tasks": running_rows,
        "completed": None,   # (Phase 8 does not maintain a separate completion
        "failed": None,       #  counter - Event log via `aep events` is authoritative;
        "quarantined": [s["job_id"] for s in schedules
                        if s["consecutive_failures"] >= 5],
        "awaiting_approval": [],
        "stuck_tasks": report.stuck_tasks,
        "project_locks": locks,
        "next_scheduled_jobs": [{"job_id": s["job_id"], "next_run_at": s["next_run_at"]}
                                for s in upcoming],
        "recommendations": [r.__dict__ for r in report.recommendations],
    }


def print_runtime_status_human(payload: dict) -> None:
    print(f"RUNTIME STATUS - supervisor={payload['supervisor']}")
    print("-" * 60)
    print(f"  Health:        {payload['health']}")
    w = payload["workers"]
    print(f"  Workers:       {w['total']} total ({w['active']} active, {w['idle']} idle), "
          f"restarts={w['restart_count']}")
    print(f"  Queue depth:   {payload['queue_depth']}")
    print(f"  Running tasks: {len(payload['running_tasks'])}")
    for row in payload["running_tasks"]:
        print(f"    PROJECT={row['project']:15.15s} TASK={row['task']:20.20s} "
              f"AGENT={row['worker']:15.15s} STATE={row['state']:10.10s} STARTED={row['started']}")
    print(f"  Quarantined jobs: {payload['quarantined']}")
    print(f"  Stuck tasks:      {payload['stuck_tasks']}")
    print("  Next scheduled jobs:")
    for j in payload["next_scheduled_jobs"]:
        print(f"    {j['job_id']:40.40s} next_run_at={j['next_run_at']}")
