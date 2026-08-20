"""Runtime health model / watchdog (Phase 8 Part 8).

States: HEALTHY / DEGRADED / UNHEALTHY / RECOVERING / STOPPING / STOPPED.
The watchdog only ever RECOMMENDS recovery actions (stale-worker restart,
stale-task requeue); it never itself bypasses policy/approval - actual
mutation goes through the same runanble path (workloop/workers) that
respects PolicyEngine.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


class HealthState:
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"
    RECOVERING = "RECOVERING"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"


@dataclass
class Recommendation:
    kind: str      # "restart_worker" | "requeue_task" | "escalate"
    target: str
    reason: str


@dataclass
class HealthReport:
    state: str
    stale_workers: list
    stuck_tasks: list
    recommendations: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "state": self.state,
            "stale_workers": self.stale_workers,
            "stuck_tasks": self.stuck_tasks,
            "recommendations": [r.__dict__ for r in self.recommendations],
        }


def _seconds_since(iso_ts: str) -> float:
    ts = datetime.fromisoformat(iso_ts)
    return (datetime.now(timezone.utc) - ts).total_seconds()


def assess(workers: list[dict], leases: list[dict], heartbeat_timeout_s: float,
           stuck_task_timeout_s: float) -> HealthReport:
    """Pure function: given current worker/lease rows, decide health state
    and recovery recommendations. Never mutates anything itself."""
    stale_workers = [w for w in workers
                      if w["status"] not in ("STOPPED",) and
                      _seconds_since(w["last_heartbeat"]) > heartbeat_timeout_s]
    stuck_tasks = [l for l in leases if _seconds_since(l["acquired_at"]) > stuck_task_timeout_s]

    recs: list[Recommendation] = []
    for w in stale_workers:
        recs.append(Recommendation("restart_worker", w["worker_id"],
                                    f"no heartbeat for >{heartbeat_timeout_s}s"))
    for l in stuck_tasks:
        recs.append(Recommendation("requeue_task", l["task_id"],
                                    f"lease held >{stuck_task_timeout_s}s without completion"))

    if not workers:
        state = HealthState.STOPPED
    elif stale_workers or stuck_tasks:
        ratio = len(stale_workers) / max(len(workers), 1)
        state = HealthState.UNHEALTHY if ratio >= 0.5 else HealthState.DEGRADED
    else:
        state = HealthState.HEALTHY

    return HealthReport(state=state, stale_workers=[w["worker_id"] for w in stale_workers],
                        stuck_tasks=[l["task_id"] for l in stuck_tasks], recommendations=recs)
