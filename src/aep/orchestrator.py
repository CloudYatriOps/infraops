"""Central orchestrator: intake -> decompose -> schedule -> dispatch ->
retry. Owns no business logic about *how* to fix a bug or run a scan - that
lives in agents. Owns *whether/when* something runs, entirely from durable
state, which is what makes `resume()` a real crash-recovery path rather
than a resume of in-memory intent.
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Optional

import json

from .agents.base import Agent, build_context
from .events import EventLogger
from .failure import NO_AUTO_RETRY, FailureClassifier, classify
from .models import (
    Evidence, FailureClass, PolicyDecisionType, ProjectConfig, Task, TaskStatus,
)
from .policy import PolicyEngine
from .providers.router import ModelRouter
from .skills.loader import SkillResolutionError, resolve_required_skills
from .skills.registry import SkillRegistry
from .state_store import StateStore, now_iso
from .tool_registry import ToolRegistry


def new_task_id() -> str:
    return str(uuid.uuid4())


class Orchestrator:
    def __init__(self, store: StateStore, tool_registry: ToolRegistry,
                 router: ModelRouter, agents: dict[str, Agent],
                 policies: dict[str, PolicyEngine], projects: dict[str, ProjectConfig],
                 failure_classifier: Optional[FailureClassifier] = None,
                 circuit_breaker_threshold: int = 5,
                 sleep_fn=time.sleep,
                 skill_registry: Optional[SkillRegistry] = None):
        self.store = store
        self.tool_registry = tool_registry
        self.router = router
        self.agents = agents
        self.policies = policies
        self.projects = projects
        self.failure_classifier = failure_classifier or FailureClassifier(
            circuit_breaker_threshold=circuit_breaker_threshold,
        )
        self.circuit_breaker_threshold = circuit_breaker_threshold
        self.logger = EventLogger(store)
        self._sleep = sleep_fn
        # Stage C Part 1: the ONE central skill-registry instance the
        # orchestrator's gate resolves against (see `_apply_skill_gate`
        # below and ARCHITECTURE.md §33) - never constructed a second time
        # per-agent. May be None (skill gate becomes a strict no-op) for
        # callers/tests that never pass one, preserving pre-Stage-C
        # behavior exactly.
        self.skill_registry = skill_registry

    # ---- Intake / graph construction --------------------------------
    def submit_graph(self, project_id: str, tasks: list[Task]) -> list[str]:
        """Persist a pre-built task graph. `plan_fix_bug` below is a small
        example planner; a real intent-decomposition planner would build
        the same `list[Task]` shape from a natural-language request."""
        for task in tasks:
            task.project_id = project_id
            if task.status == TaskStatus.PENDING and not task.dependencies:
                task.status = TaskStatus.READY
            self.store.save_task(task)
        self.logger.log(actor="orchestrator", action="graph_submitted",
                         project_id=project_id, details={"task_ids": [t.id for t in tasks]})
        return [t.id for t in tasks]

    def plan_fix_bug(self, project_id: str, project_root: str, target_file: str,
                      bug_description: str, branch_name: Optional[str] = None) -> list[str]:
        """Canonical Phase-1 task graph for 'fix a bug': recon -> code fix
        -> security scan -> tests. This is the "decompose work" step of the
        master prompt's pipeline, made concrete instead of aspirational."""
        recon = Task(id=new_task_id(), type="recon", project_id=project_id,
                     owner_agent="recon", payload={"project_root": project_root})
        code_fix = Task(id=new_task_id(), type="code_fix", project_id=project_id,
                         owner_agent="code_agent", dependencies=[recon.id],
                         payload={"project_root": project_root, "target_file": target_file,
                                  "bug_description": bug_description,
                                  "branch_name": branch_name or f"aep/fix-{uuid.uuid4().hex[:8]}"})
        sec_scan = Task(id=new_task_id(), type="security_scan", project_id=project_id,
                         owner_agent="security_scan_agent", dependencies=[code_fix.id],
                         payload={"project_root": project_root})
        run_tests = Task(id=new_task_id(), type="run_tests", project_id=project_id,
                          owner_agent="testing_agent", dependencies=[sec_scan.id],
                          payload={"project_root": project_root})
        return self.submit_graph(project_id, [recon, code_fix, sec_scan, run_tests])

    # ---- Approval workflow -------------------------------------------
    def approve(self, task_id: str, decided_by: str) -> None:
        task = self.store.get_task(task_id)
        if task is None or task.status != TaskStatus.BLOCKED_ON_APPROVAL:
            raise ValueError(f"task {task_id} is not awaiting approval")
        task.status = TaskStatus.READY
        task.approval_status = "APPROVED"
        self.store.save_task(task)
        self.logger.log(actor=decided_by, action="approval_granted",
                         project_id=task.project_id, task_id=task_id)

    def reject(self, task_id: str, decided_by: str, reason: str = "") -> None:
        task = self.store.get_task(task_id)
        if task is None or task.status != TaskStatus.BLOCKED_ON_APPROVAL:
            raise ValueError(f"task {task_id} is not awaiting approval")
        task.status = TaskStatus.CANCELLED
        task.approval_status = "REJECTED"
        self.store.save_task(task)
        self.logger.log(actor=decided_by, action="approval_rejected",
                         project_id=task.project_id, task_id=task_id, details={"reason": reason})

    # ---- Scheduling loop -----------------------------------------------
    def _dependencies_satisfied(self, task: Task) -> bool:
        for dep_id in task.dependencies:
            dep = self.store.get_task(dep_id)
            if dep is None or dep.status != TaskStatus.SUCCEEDED:
                return False
        return True

    def _promote_ready_tasks(self, project_id: str) -> None:
        for task in self.store.list_tasks(project_id, statuses=[TaskStatus.PENDING]):
            if self._dependencies_satisfied(task):
                task.status = TaskStatus.READY
                self.store.save_task(task)

    def _next_ready_task(self, project_id: str) -> Optional[Task]:
        ready = self.store.list_tasks(project_id, statuses=[TaskStatus.READY])
        ready.sort(key=lambda t: (-t.priority, t.created_at))
        return ready[0] if ready else None

    def _apply_generic_policy_gate(self, task: Task) -> Optional[TaskStatus]:
        """Optional policy_action/policy_context on a task's payload is
        checked centrally, in addition to any policy checks an agent makes
        itself (defense in depth).

        A task a human has already explicitly approved (via `approve()`)
        skips re-evaluation: without this, a REQUIRE_APPROVAL task would be
        re-blocked on its very next scheduling pass, since nothing about the
        task's payload changes between "approved, now READY" and "running" -
        the same policy_action/policy_context would just match the same
        REQUIRE_APPROVAL rule again and undo the approval. Caught by
        Phase 2's force-push-requires-approval test, but it's a Phase 1
        core gap: DENY has no such issue (a denied task is CANCELLED, a
        terminal state that's never scheduled again), only REQUIRE_APPROVAL
        re-enters the scheduler after approve() sets it back to READY.
        """
        if task.approval_status == "APPROVED":
            return None
        action = task.payload.get("policy_action")
        if not action:
            return None
        policy = self.policies[task.project_id]
        decision = policy.evaluate(action, task.payload.get("policy_context", {}))
        self.logger.log(actor="orchestrator", action="policy_evaluated",
                         project_id=task.project_id, task_id=task.id,
                         decision=decision.decision.value,
                         details={"policy_action": action, "reason": decision.reason})
        if decision.decision == PolicyDecisionType.DENY:
            return TaskStatus.CANCELLED
        if decision.decision == PolicyDecisionType.REQUIRE_APPROVAL:
            return TaskStatus.BLOCKED_ON_APPROVAL
        return None

    def _apply_skill_gate(self, task: Task) -> Optional[TaskStatus]:
        """Stage C central skill-enforcement gate (closes the one known
        Stage B gap noted in ARCHITECTURE.md §32): resolves
        `task.type`'s required skills, exactly once, right here, against
        `self.skill_registry` - the single registry instance the
        orchestrator owns. No agent file performs its own skill
        resolution; this is the ONE place it happens (see the
        `resolve_required_skills` grep check in the Stage C verification
        notes).

        A task type with no entry in `TASK_SKILL_RULES` resolves to an
        empty required set and this is a no-op (returns None, task
        proceeds) - Stage B/C are additive and never retroactively gate a
        Phase 1-8 task type that never asked for skill resolution.

        If `self.skill_registry` itself is None, the gate is a strict
        no-op for every task type. This orchestrator instance was simply
        never configured for Stage C skill enforcement (the default from
        `build_orchestrator` unless `skill_registry`/
        `skill_registry_backend` is explicitly passed) - all 638 Phase
        1-8/Stage A/B tests construct orchestrators this way and must keep
        behaving exactly as before. Enforcement only activates once a
        registry is actually wired in, at which point a task type WITH a
        rule that fails to resolve genuinely escalates (see below).
        """
        from .skills.loader import TASK_SKILL_RULES

        if self.skill_registry is None:
            return None

        rule = TASK_SKILL_RULES.get(task.type)
        if not rule or not rule.get("required"):
            return None

        try:
            resolved = resolve_required_skills(task.type, self.skill_registry)
        except SkillResolutionError as exc:
            self.logger.log(actor="orchestrator", action="skill_gate_blocked",
                             project_id=task.project_id, task_id=task.id,
                             details={"task_type": task.type, "reason": str(exc)})
            return TaskStatus.BLOCKED_ON_APPROVAL

        task.evidence.append(Evidence(
            source="skill_registry", captured_at=now_iso(), exit_code=0,
            summary=json.dumps(resolved.evidence_payload()),
        ))
        self.logger.log(actor="orchestrator", action="skill_gate_passed",
                         project_id=task.project_id, task_id=task.id,
                         details={"task_type": task.type,
                                  "required_skills": [f"{v.skill_id}@{v.version}" for v in resolved.required]})
        return None

    def run_task(self, task: Task) -> None:
        if self.store.is_quarantined(task.project_id, task.type):
            task.status = TaskStatus.QUARANTINED
            self.store.save_task(task)
            self.logger.log(actor="orchestrator", action="task_quarantined_type",
                             project_id=task.project_id, task_id=task.id,
                             details={"reason": "task_type circuit-breaker already open"})
            return

        gate_status = self._apply_generic_policy_gate(task)
        if gate_status == TaskStatus.CANCELLED:
            task.status = TaskStatus.CANCELLED
            self.store.save_task(task)
            return
        if gate_status == TaskStatus.BLOCKED_ON_APPROVAL:
            task.status = TaskStatus.BLOCKED_ON_APPROVAL
            self.store.save_task(task)
            return

        skill_gate_status = self._apply_skill_gate(task)
        if skill_gate_status is not None:
            task.status = skill_gate_status
            self.store.save_task(task)
            return

        agent = self.agents[task.owner_agent]
        project = self.projects[task.project_id]
        policy = self.policies[task.project_id]
        ctx = build_context(task, agent, self.tool_registry, self.router, policy, project, self.logger)

        task.status = TaskStatus.RUNNING
        task.attempts += 1
        self.store.save_task(task)
        self.logger.log(actor="orchestrator", action="task_started",
                         project_id=task.project_id, task_id=task.id)

        try:
            result = agent.run(task, ctx)
        except Exception as e:  # noqa: BLE001 - classified immediately below
            failure_class = classify(e)
            self._handle_failure(task, failure_class, str(e))
            return

        if result.success:
            task.status = TaskStatus.SUCCEEDED
            task.evidence.extend(result.evidence)
            task.artifacts.extend(result.artifacts)
            self.store.save_task(task)
            self.store.reset_failure_counter(task.project_id, task.type)
            for follow_up in result.follow_up_tasks:
                follow_up.parent_task_id = task.id
                self.submit_graph(task.project_id, [follow_up])
            self.logger.log(actor=agent.name, action="task_succeeded",
                             project_id=task.project_id, task_id=task.id,
                             details={"message": result.message})
        else:
            task.evidence.extend(result.evidence)
            self._handle_failure(task, result.failure_class or FailureClass.TOOL, result.message)

    def _handle_failure(self, task: Task, failure_class: FailureClass, message: str) -> None:
        decision = self.failure_classifier.decide(failure_class, task.attempts, task.max_attempts)
        self.logger.log(actor="orchestrator", action="task_failed",
                         project_id=task.project_id, task_id=task.id,
                         details={"failure_class": failure_class.value, "message": message,
                                  "will_retry": decision.should_retry})

        if failure_class in NO_AUTO_RETRY:
            task.status = TaskStatus.BLOCKED_ON_APPROVAL
            self.store.save_task(task)
            self.logger.log(actor="orchestrator", action="human_required",
                             project_id=task.project_id, task_id=task.id,
                             details={"failure_class": failure_class.value, "message": message})
            return

        if decision.should_retry:
            # Still within THIS task instance's own retry budget - e.g. a
            # CI-status poll that legitimately needs several TRANSIENT
            # retries before resolving (see MonitorCIAgent). This must NOT
            # count toward the per-type circuit breaker: that breaker exists
            # to catch a task TYPE that keeps failing across many distinct
            # instances/executions (ARCHITECTURE.md §9), not a single
            # instance backing off exactly as designed. Counting every
            # retry here would let a normal polling task trip a
            # project-wide breaker before its own max_attempts is ever
            # reached - a real bug caught by Phase 2's CI-monitor tests.
            if decision.backoff_seconds > 0:
                self._sleep(decision.backoff_seconds)
            task.status = TaskStatus.PENDING
            self.store.save_task(task)
            return

        # This instance's own retry budget is exhausted - now it's
        # meaningful to ask "does this task TYPE keep failing."
        quarantined_type = self.store.record_failure(task.project_id, task.type,
                                                       self.circuit_breaker_threshold)
        if decision.quarantine or quarantined_type:
            task.status = TaskStatus.QUARANTINED
            self.store.save_task(task)
            self.logger.log(actor="orchestrator", action="task_quarantined",
                             project_id=task.project_id, task_id=task.id)
            return

        task.status = TaskStatus.FAILED
        self.store.save_task(task)

    def run_to_completion(self, project_id: str, max_iterations: int = 200) -> None:
        for _ in range(max_iterations):
            self._promote_ready_tasks(project_id)
            task = self._next_ready_task(project_id)
            if task is None:
                # Nothing READY: either the graph is fully resolved, or the
                # remaining PENDING tasks are blocked on a dependency that
                # will never succeed (CANCELLED/QUARANTINED/BLOCKED). Either
                # way there is nothing safe to schedule right now.
                return
            self.run_task(task)

    def resume(self, project_id: str) -> None:
        """Reload durable state and continue. Any task left RUNNING by a
        prior crash is treated as failed-and-retryable rather than
        silently re-marked succeeded."""
        for task in self.store.list_tasks(project_id, statuses=[TaskStatus.RUNNING]):
            task.status = TaskStatus.PENDING
            self.store.save_task(task)
            self.logger.log(actor="orchestrator", action="resumed_interrupted_task",
                             project_id=project_id, task_id=task.id)
        self.run_to_completion(project_id)
