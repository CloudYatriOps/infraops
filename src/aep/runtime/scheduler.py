"""Durable recurring-job scheduler (Phase 8 Part 4).

Backed entirely by `StateStore.runtime_schedules` - a scheduler restart
reads existing rows back (`upsert_schedule` is a no-op for a job_id that
already exists), so it never re-fires a job early or duplicates it purely
because the process restarted. Job execution itself goes through the
policy-aware work loop (`workloop.py`), never bypassing it.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable, Optional

from ..state_store import StateStore

# Project-configurable job catalog. Nothing here hardcodes a specific
# project name - `register_default_jobs` takes the project_id/interval
# from the caller (see Part 4: "Do not hardcode any specific project").
JOB_TYPES = (
    "dependency_cve_scan",
    "secret_scan",
    "sast_scan",
    "iac_scan",
    "infrastructure_discovery",
    "ci_status_monitor",
    "deployment_verification",
    "operations_health_review",
    "incident_recurrence_analysis",
    "stale_task_recovery",
)


def register_default_jobs(store: StateStore, project_id: str, interval_seconds: float = 3600.0) -> None:
    """Idempotently register the standard job catalog for one project.
    Safe to call every supervisor startup: `upsert_schedule` only inserts
    a job_id it has never seen before."""
    for job_type in JOB_TYPES:
        job_id = f"{project_id}:{job_type}"
        store.upsert_schedule(job_id, project_id, job_type, interval_seconds)


def jitter(base_seconds: float, fraction: float = 0.1) -> float:
    """Deterministic-shape (bounded, not opaque) jitter to avoid a
    thundering herd of jobs all re-scheduling for the exact same instant."""
    spread = base_seconds * fraction
    return random.uniform(-spread, spread)


def due_jobs(store: StateStore) -> list[dict]:
    return store.due_schedules()


def run_due_jobs(store: StateStore, dispatch: Callable[[dict], bool],
                  max_consecutive_failures: int = 5) -> list[dict]:
    """Runs every currently-due job exactly once via `dispatch`, then
    durably records success/failure and computes the next run time -
    Part 4's "no duplicate execution after restart" + "failure tracking"
    + "jitter/backoff where appropriate" (backoff: a repeatedly-failing
    job's failure count is durable and callers can use it to widen
    intervals/pause, same shape as `failure.py`'s circuit breaker)."""
    results = []
    for job in due_jobs(store):
        try:
            ok = dispatch(job)
        except Exception:
            ok = False
        # Backoff: consecutive_failures widen the effective interval so a
        # persistently broken job doesn't hammer the same scan every cycle.
        failures = job["consecutive_failures"] + (0 if ok else 1)
        backoff_multiplier = 1.0 if ok else min(2 ** min(failures, 4), 16)
        effective_interval = job["interval_seconds"] * backoff_multiplier
        store.record_schedule_run(job["job_id"], ok, effective_interval,
                                  jitter_seconds=jitter(job["interval_seconds"]))
        results.append({"job_id": job["job_id"], "success": ok,
                         "quarantined": failures >= max_consecutive_failures})
    return results
