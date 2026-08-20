"""OperationsIntelligenceAgent (Phase 7).

Implements the closed operational loop end to end using the SAME four-mode
shape as `DependencyCVEAgent`/`SecurityAgent`/`InfrastructureIntelligenceAgent`:

  scan       DETECT -> COLLECT EVIDENCE -> CORRELATE -> DIAGNOSE -> PLAN ->
             POLICY CHECK -> schedules remediate/escalate follow-ups
  remediate  APPROVAL IF REQUIRED (checked, not bypassed) -> REMEDIATE ->
             schedules a rescan follow-up
  rescan     VERIFY -> MONITOR FOR RECURRENCE (via RecurrenceTracker) ->
             CLOSE (success) or escalate
  escalate   CLOSE OR ESCALATE: builds the structured Part 10 escalation

Built entirely on the existing orchestrator/task-graph `follow_up_tasks`
mechanism - no independent scheduler. Reuses `PolicyEngine` for every
authorization decision and `StateStore`/`Event` for all durable evidence
(incident memory, deployment history) - no new storage primitive.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from ..models import Evidence, FailureClass, PolicyDecisionType, Task, TaskResult
from ..operations.correlation import IncidentCorrelationEngine
from ..operations.dependency_graph import ServiceDependencyGraph
from ..operations.escalation import build_escalation
from ..operations.memory import IncidentMemoryRecord
from ..operations.models import (
    Diagnosis, Incident, OperationalEvent, RCAConfidence, RemediationCategory, RootCauseCategory,
)
from ..operations.observability import DeploymentHistoryAdapter
from ..operations.planner import build_escalate_task, build_remediation_task, build_rescan_task
from ..operations.rca import RootCauseAnalyzer
from ..operations.recurrence import RecurrenceTracker
from ..operations.remediation import (
    build_action, evaluate_with_policy, is_authorized, restart_action_for, rollback_action_for,
)
from .base import Agent, AgentContext

_recurrence_trackers: dict[str, RecurrenceTracker] = {}


def _tracker(project_id: str) -> RecurrenceTracker:
    return _recurrence_trackers.setdefault(project_id, RecurrenceTracker())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _action_for(root_cause: RootCauseCategory, environment: str):
    """Deterministic mapping from a root-cause hypothesis to a candidate
    remediation action - matches the Part 6 examples literally (bad
    deployment -> rollback; capacity exhaustion/app defect -> restart;
    everything else has no safe automated action and stays read-only /
    diagnostic-task-only)."""
    if root_cause == RootCauseCategory.BAD_DEPLOYMENT:
        return rollback_action_for(environment)
    if root_cause in (RootCauseCategory.APPLICATION_DEFECT, RootCauseCategory.CAPACITY_EXHAUSTION):
        return restart_action_for(environment)
    return build_action("create_diagnostic_task")


class OperationsIntelligenceAgent:
    name = "operations_intelligence_agent"
    required_capabilities = {
        "filesystem.read", "filesystem.write", "filesystem.list",
        "operations.record_incident", "operations.list_incidents",
        "operations.find_similar_incidents",
        "deployment.list_evidence", "deployment.rollback",
    }

    def run(self, task: Task, ctx: AgentContext) -> TaskResult:
        mode = task.payload.get("mode", "scan")
        if mode == "scan":
            return self._scan(task, ctx)
        if mode == "remediate":
            return self._remediate(task, ctx)
        if mode == "rescan":
            return self._rescan(task, ctx)
        if mode == "escalate":
            return self._escalate(task, ctx)
        raise ValueError(f"unknown operations_intelligence_agent mode: {mode!r}")

    # ---- DETECT + COLLECT + CORRELATE + DIAGNOSE + PLAN + POLICY CHECK --
    def _scan(self, task: Task, ctx: AgentContext) -> TaskResult:
        raw_events = task.payload.get("events", [])
        events = [OperationalEvent.from_dict(e) if isinstance(e, dict) else e for e in raw_events]
        environment = task.payload.get("environment", "development")
        graph_edges = task.payload.get("dependency_graph", {})
        graph = ServiceDependencyGraph(edges=graph_edges)

        evidence = [Evidence(source="operations_detect", captured_at=_now(), exit_code=0,
                              summary=f"{len(events)} operational event(s) received for "
                                      f"correlation")]
        if not events:
            evidence.append(Evidence(source="operations_scan", captured_at=_now(), exit_code=0,
                                      summary="no operational events - nothing to correlate"))
            return TaskResult(success=True, evidence=evidence, message="no operational signal")

        incidents = IncidentCorrelationEngine().correlate(events)
        evidence.append(Evidence(
            source="operations_correlation", captured_at=_now(), exit_code=0,
            summary=f"{len(incidents)} incident(s) correlated from {len(events)} event(s): "
                    f"{[(i.incident_id[:8], i.confidence) for i in incidents]}",
        ))

        follow_ups: list[Task] = []
        for incident in incidents:
            diagnosis = RootCauseAnalyzer().diagnose(incident, events, graph)
            evidence.append(Evidence(
                source="operations_rca", captured_at=_now(), exit_code=0,
                summary=f"incident {incident.incident_id[:8]}: hypothesis="
                        f"{diagnosis.hypothesis.value} confidence={diagnosis.confidence.value}",
            ))

            blast = graph.blast_radius(incident.service) if incident.service else None
            if blast is not None:
                evidence.append(Evidence(
                    source="operations_blast_radius", captured_at=_now(), exit_code=0,
                    summary=f"{incident.service}: upstream={blast.upstream_dependencies} "
                            f"downstream={blast.downstream_services}",
                ))

            similar_result = ctx.tools.call("operations.find_similar_incidents", task_id=task.id,
                                             project_id=task.project_id,
                                             fingerprint=incident.fingerprint)
            similar = similar_result.get("data", []) if similar_result.get("ok") else []
            if similar:
                latest = similar[-1]
                evidence.append(Evidence(
                    source="operations_memory", captured_at=_now(), exit_code=0,
                    summary=f"{len(similar)} similar prior incident(s) found for fingerprint "
                            f"{incident.fingerprint!r} (advisory only - never overrides current "
                            f"evidence/policy): most recent remediation="
                            f"{latest['remediation_used']!r} succeeded={latest['remediation_succeeded']}",
                ))

            if not diagnosis.safe_to_auto_remediate:
                follow_ups.append(build_escalate_task(
                    task.project_id, incident.to_dict(), diagnosis.to_dict(),
                    reason="Insufficient evidence - do not remediate automatically: "
                           f"{diagnosis.recommended_next_diagnostic_action}",
                ))
                continue

            action = _action_for(diagnosis.hypothesis, environment)
            decision = evaluate_with_policy(ctx.policy, action, {"environment": environment})
            evidence.append(Evidence(
                source="operations_policy", captured_at=_now(), exit_code=0,
                summary=f"incident {incident.incident_id[:8]}: action={action.action_id} "
                        f"category={action.category.value} policy_decision="
                        f"{decision.decision.value} ({decision.reason})",
            ))

            if decision.decision == PolicyDecisionType.DENY or action.category == RemediationCategory.DENY:
                follow_ups.append(build_escalate_task(
                    task.project_id, incident.to_dict(), diagnosis.to_dict(),
                    reason=f"policy DENY for {action.policy_action}: {decision.reason}",
                ))
                continue
            if decision.decision == PolicyDecisionType.REQUIRE_APPROVAL:
                follow_ups.append(build_escalate_task(
                    task.project_id, incident.to_dict(), diagnosis.to_dict(),
                    reason=f"human approval required for {action.policy_action} in "
                           f"{environment}: {decision.reason}",
                ))
                continue

            recurrence = _tracker(task.project_id).record_attempt(incident.fingerprint)
            evidence.append(Evidence(
                source="operations_recurrence", captured_at=_now(), exit_code=0,
                summary=recurrence.reason,
            ))
            if not recurrence.should_remediate:
                follow_ups.append(build_escalate_task(
                    task.project_id, incident.to_dict(), diagnosis.to_dict(),
                    reason=recurrence.reason,
                ))
                continue

            follow_ups.append(build_remediation_task(
                task.project_id, incident.to_dict(), diagnosis.to_dict(), action.to_dict(),
                environment,
            ))

        return TaskResult(
            success=True, evidence=evidence,
            message=f"{len(incidents)} incident(s) correlated; "
                    f"{sum(1 for t in follow_ups if t.type == 'operations_remediate')} scheduled "
                    f"for remediation, "
                    f"{sum(1 for t in follow_ups if t.type == 'operations_escalate')} escalated",
            follow_up_tasks=follow_ups,
        )

    # ---- REMEDIATE ---------------------------------------------------
    def _remediate(self, task: Task, ctx: AgentContext) -> TaskResult:
        incident_d = task.payload["incident"]
        diagnosis_d = task.payload["diagnosis"]
        action_d = task.payload["action"]
        environment = task.payload["environment"]
        action = build_action(action_d["action_id"])

        # Re-evaluate policy at execution time too - never trust a decision
        # made in an earlier scan task without re-checking (state may have
        # changed between scheduling and execution).
        decision = evaluate_with_policy(ctx.policy, action, {"environment": environment})
        if not is_authorized(decision):
            return TaskResult(
                success=False, failure_class=FailureClass.SECURITY,
                evidence=[Evidence(source="operations_remediate", captured_at=_now(), exit_code=1,
                                    summary=f"execution-time policy re-check denied "
                                            f"{action.policy_action}: {decision.reason}")],
                message="remediation blocked at execution time by policy",
            )

        evidence = [Evidence(source="operations_remediate", captured_at=_now(), exit_code=0,
                              summary=f"executing {action.action_id} ({action.description}) "
                                      f"in {environment}")]

        deployment_ref = task.payload.get("deployment_ref")
        executed_real = False
        if action.action_id.startswith("rollback") and deployment_ref:
            outcome = ctx.tools.call("deployment.rollback", task_id=task.id,
                                      deployment_ref=deployment_ref)
            executed_real = True
            evidence.append(Evidence(
                source="deployment.rollback", captured_at=_now(),
                exit_code=0 if outcome.get("ok") else 1,
                summary=f"real rollback via deployment provider: "
                        f"{outcome.get('data', {}).get('detail', '')}",
            ))
            success = bool(outcome.get("ok"))
        else:
            # Part 14 / honesty discipline: there is no real workload/job
            # runtime reachable in this environment for restart/retry/
            # rollback-without-a-deployment-ref, so this is explicitly
            # recorded as MOCKED execution, never claimed as a real effect.
            evidence.append(Evidence(
                source="operations_remediate", captured_at=_now(), exit_code=0,
                summary=f"MOCKED execution of {action.action_id}: no real workload/job runtime "
                        f"is reachable in this environment to actually act on; recorded as a "
                        f"planned action only",
            ))
            success = True

        return TaskResult(
            success=success, evidence=evidence,
            message=f"{'REAL' if executed_real else 'MOCKED'} remediation "
                    f"{'succeeded' if success else 'failed'}: {action.action_id}",
            follow_up_tasks=[build_rescan_task(task.project_id, incident_d, action_d, environment)],
        )

    # ---- VERIFY + MONITOR FOR RECURRENCE ------------------------------
    def _rescan(self, task: Task, ctx: AgentContext) -> TaskResult:
        incident_d = task.payload["incident"]
        action_d = task.payload["action"]
        incident = Incident(**{**incident_d})
        fingerprint = incident.fingerprint

        def _record_incident(succeeded: bool) -> None:
            ctx.tools.call("operations.record_incident", task_id=task.id,
                            project_id=task.project_id,
                            record=IncidentMemoryRecord(
                                fingerprint=fingerprint, incident_id=incident.incident_id,
                                root_cause="n/a", confidence="n/a",
                                remediation_used=action_d["action_id"],
                                remediation_succeeded=succeeded,
                                environment=incident.environment).to_dict())

        def _list_evidence():
            from ..deployment.models import DeploymentRecord
            result = ctx.tools.call("deployment.list_evidence", task_id=task.id,
                                     project_id=task.project_id)
            return [DeploymentRecord.from_dict(r) for r in result.get("data", [])]

        adapter = DeploymentHistoryAdapter(_list_evidence)
        health = adapter.service_health()
        evidence = [Evidence(source="operations_verify", captured_at=_now(),
                              exit_code=0 if health.status.value == "REAL" else 1,
                              summary=f"service_health surface status={health.status.value} "
                                      f"detail={health.detail}")]

        if health.status.value != "REAL" or not health.data:
            evidence.append(Evidence(
                source="operations_verify", captured_at=_now(), exit_code=1,
                summary="no deployment evidence available to confirm recovery - status is "
                        "UNVERIFIED, never silently treated as SUCCESS",
            ))
            _record_incident(False)
            return TaskResult(success=False, evidence=evidence, failure_class=FailureClass.HEALTH,
                               message="UNVERIFIED: remediation executed but recovery could not "
                                       "be confirmed with available evidence")

        healthy = bool(health.data[0].get("healthy"))
        _record_incident(healthy)
        if healthy:
            _tracker(task.project_id).reset(fingerprint)
            evidence.append(Evidence(source="operations_verify", captured_at=_now(), exit_code=0,
                                      summary="recovery CONFIRMED by real deployment evidence - "
                                              "closing incident"))
            return TaskResult(success=True, evidence=evidence,
                               message="incident CLOSED: recovery verified")

        evidence.append(Evidence(source="operations_verify", captured_at=_now(), exit_code=1,
                                  summary="deployment evidence shows the service is still not "
                                          "healthy after remediation"))
        return TaskResult(
            success=False, evidence=evidence, failure_class=FailureClass.HEALTH,
            message="remediation did not recover the service",
            follow_up_tasks=[build_escalate_task(
                task.project_id, incident_d, {"hypothesis": "UNKNOWN", "confidence": "UNKNOWN"},
                reason="remediation executed but verification shows the service still unhealthy",
                attempted=[action_d["action_id"]],
            )],
        )

    # ---- CLOSE OR ESCALATE ---------------------------------------------
    def _escalate(self, task: Task, ctx: AgentContext) -> TaskResult:
        incident_d = task.payload["incident"]
        diagnosis_d = task.payload.get("diagnosis", {"hypothesis": "UNKNOWN", "confidence": "UNKNOWN"})
        reason = task.payload.get("reason", "")
        attempted = task.payload.get("attempted", [])
        incident = Incident(**incident_d)
        diagnosis = Diagnosis(
            hypothesis=RootCauseCategory(diagnosis_d.get("hypothesis", "UNKNOWN")),
            confidence=RCAConfidence(diagnosis_d.get("confidence", "UNKNOWN")),
            supporting_evidence=diagnosis_d.get("supporting_evidence", []),
            contradicting_evidence=diagnosis_d.get("contradicting_evidence", []),
            missing_evidence=diagnosis_d.get("missing_evidence", []),
            recommended_next_diagnostic_action=diagnosis_d.get(
                "recommended_next_diagnostic_action", ""),
        )
        escalation = build_escalation(
            incident, diagnosis, attempted=attempted, changed=[],
            failed=attempted, required_action=reason or "human review required",
            recommended_step=diagnosis.recommended_next_diagnostic_action
            or "review incident evidence and decide on manual remediation",
        )
        return TaskResult(
            success=False, failure_class=FailureClass.HUMAN_REQUIRED,
            evidence=[Evidence(source="operations_escalation", captured_at=_now(), exit_code=1,
                                summary=escalation.to_text())],
            message=f"human escalation required for incident {incident.incident_id}: {reason}",
        )
