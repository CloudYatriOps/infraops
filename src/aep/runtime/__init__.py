"""Phase 8: 24/7 Autonomous Runtime.

This package adds a supervising, continuously-operable runtime ON TOP of
the existing durable task engine (StateStore/Task/Orchestrator) and
PolicyEngine - it does not replace either. See ARCHITECTURE.md
"Section 29. Phase 8 Addendum: 24/7 Autonomous Runtime" for full design,
and `src/aep/progress/deployability.py`/`calculator.py` for why this is a
SEPARATE concept from platform-development progress (Part 10).

Modules:
  priority.py    deterministic, explainable priority scoring (Part 6)
  leases.py      durable task lease helpers on top of StateStore (Part 2)
  locks.py       durable per-project mutating-work lock (Part 3)
  workers.py     Worker lifecycle: heartbeat, lease ownership (Part 1/2)
  scheduler.py   durable recurring-job scheduler (Part 4)
  workloop.py    DISCOVER..ESCALATE control loop coordinating existing
                 agents (Part 5)
  health.py      health model / watchdog (Part 8)
  supervisor.py  RuntimeSupervisor + WorkerPool orchestrating all of the
                 above for a bounded/controlled run (Part 1/2/11/12)
  status.py      live runtime status payload builder for the CLI (Part 9)
"""
