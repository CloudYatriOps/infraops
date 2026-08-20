"""RuntimeSupervisor + WorkerPool (Phase 8 Part 1/2/11/12).

Runs a CONTROLLED, TIME/CYCLE-BOUNDED loop - never a real infinite
background process claimed as "it ran forever". `run(max_cycles=...)` or
`run(max_seconds=...)` executes the DISCOVER..ESCALATE work loop that many
times/that long and then returns, with full durable state (workers,
leases, schedules, events) left behind in the SAME StateStore file so a
fresh `RuntimeSupervisor` pointed at the same db can resume exactly where
the last one left off - this is how "crash recovery"/"restart recovery"
are demonstrated honestly in this environment (no daemon supervision here,
just a real, inspectable durable state machine).
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from ..policy import PolicyEngine
from ..state_store import StateStore
from . import health as health_mod
from . import scheduler as scheduler_mod
from .workers import Worker
from .workloop import _run_job


@dataclass
class CycleReport:
    cycle: int
    jobs_dispatched: int
    results: list = field(default_factory=list)
    health: str = "HEALTHY"


class RuntimeSupervisor:
    def __init__(self, store: StateStore, policy: PolicyEngine, num_workers: int = 2,
                 lease_ttl_s: float = 30.0, heartbeat_timeout_s: float = 60.0,
                 stuck_task_timeout_s: float = 300.0, supervisor_id: Optional[str] = None):
        self.store = store
        self.policy = policy
        self.supervisor_id = supervisor_id or f"supervisor-{uuid.uuid4().hex[:8]}"
        self.lease_ttl_s = lease_ttl_s
        self.heartbeat_timeout_s = heartbeat_timeout_s
        self.stuck_task_timeout_s = stuck_task_timeout_s
        self.min_workers = 1
        self.max_workers = max(num_workers, 1)
        self.workers: list[Worker] = [
            Worker(self.supervisor_id, store, lease_ttl_s) for _ in range(self.max_workers)
        ]
        self.started_at = None
        self.stopped = False
        self.restart_count = 0

    # ---- Part 1: graceful shutdown / crash-recovery hooks ----------
    def start(self) -> None:
        from ..state_store import now_iso
        self.started_at = now_iso()
        self.stopped = False

    def shutdown(self) -> None:
        for w in self.workers:
            w.shutdown()
        self.stopped = True

    def recover(self) -> health_mod.HealthReport:
        """Startup/crash recovery: reassess health, requeue anything the
        watchdog flags as stuck, and re-register any worker missing from
        the durable registry. Never performs destructive recovery -
        it only releases stale leases so the SAME durable task/queue
        mechanism can naturally re-offer the work."""
        report = self.watchdog()
        for rec in report.recommendations:
            if rec.kind == "requeue_task":
                self.store.force_release_lease(rec.target)
            elif rec.kind == "restart_worker":
                self.store.remove_worker(rec.target)
                self.restart_count += 1
                self.workers.append(Worker(self.supervisor_id, self.store, self.lease_ttl_s))
        return report

    def watchdog(self) -> health_mod.HealthReport:
        workers = self.store.list_workers(self.supervisor_id)
        leases = self.store.list_leases()
        return health_mod.assess(workers, leases, self.heartbeat_timeout_s, self.stuck_task_timeout_s)

    # ---- Part 5: one DISCOVER..ESCALATE cycle -----------------------
    def run_cycle(self, cycle_num: int, repos: Optional[dict] = None) -> CycleReport:
        repos = repos or {}
        due = scheduler_mod.due_jobs(self.store)
        results = []
        idx = 0
        for job in due:
            worker = self.workers[idx % len(self.workers)]
            idx += 1
            repo = repos.get(job["project_id"])
            outcome = worker.run_once(job, lambda j, r=repo: _run_job(j, self.store, self.policy, r))
            if outcome is not None:
                success = outcome.outcome in ("REAL", "MOCKED")
                self.store.record_schedule_run(job["job_id"], success, job["interval_seconds"])
                results.append(outcome.__dict__)
        report = self.watchdog()
        return CycleReport(cycle=cycle_num, jobs_dispatched=len(results), results=results,
                           health=report.state)

    def run(self, max_cycles: int = 1, max_seconds: Optional[float] = None,
            repos: Optional[dict] = None, sleep_s: float = 0.0) -> list[CycleReport]:
        """Controlled, bounded run - the honest stand-in for "24/7" in a
        test/sandbox environment: N cycles or M wall-clock seconds, never
        an unbounded loop."""
        self.start()
        reports = []
        deadline = time.monotonic() + max_seconds if max_seconds is not None else None
        cycle = 0
        while cycle < max_cycles and (deadline is None or time.monotonic() < deadline):
            reports.append(self.run_cycle(cycle, repos=repos))
            cycle += 1
            if sleep_s:
                time.sleep(sleep_s)
        self.shutdown()
        return reports
