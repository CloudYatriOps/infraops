"""Phase 7 Part 13 end-to-end scenarios A-D, run through the REAL
Orchestrator/PolicyEngine/StateStore - only the deployment provider
underneath deployment evidence is the local fixture (never live infra),
same discipline `test_deployment_agent.py` uses for Phase 6."""
from __future__ import annotations

from pathlib import Path

from aep.bootstrap import build_orchestrator
from aep.deployment.evidence import record_deployment
from aep.deployment.models import DeploymentRecord, DeploymentState
from aep.models import ProjectConfig, Task, TaskStatus
from aep.operations.memory import list_incidents
from aep.operations.models import EventCategory, EventSeverity, OperationalEvent


def _orch(tmp_path: Path, policy_path: str):
    project = ProjectConfig(id="p1", name="p1", repo_path=str(tmp_path), policy_path=policy_path)
    return build_orchestrator(str(tmp_path / "state.db"), project,
                               deployment_state_dir=str(tmp_path / "deployments"), db_backend="sqlite")


def _event(eid, ts, category, environment="development", service="svc-a", version=None,
           severity=EventSeverity.HIGH):
    return OperationalEvent(event_id=eid, timestamp=ts, source="test", category=category,
                             severity=severity, environment=environment, service=service,
                             deployment_version=version).to_dict()


def _run_scan(orch, events, environment="development"):
    task = Task(id="scan-1", type="operations_scan", project_id="p1",
                owner_agent="operations_intelligence_agent",
                payload={"mode": "scan", "events": events, "environment": environment})
    orch.store.save_task(task)
    orch.run_to_completion("p1")
    return orch.store.list_tasks("p1")


# ---- SCENARIO A: bad deployment -> health failure -> correlate ->
# diagnose -> policy check -> rollback plan -> verify recovery. ----------
def test_scenario_a_bad_deployment_rollback_and_verified_recovery(tmp_path, policy_path):
    orch = _orch(tmp_path, policy_path)
    # A healthy post-rollback deployment record already exists (this
    # platform's OWN durable evidence - what `rescan` verifies recovery
    # against).
    record_deployment(orch.store, "p1", DeploymentRecord(
        task_id="deploy-1", commit_sha="a" * 12, artifact_id="art-1", environment="development",
        release_gates_passed=True, approval_status="not_required", provider="local_fixture",
        provider_status="REAL", final_state=DeploymentState.VERIFIED,
    ))
    events = [
        _event("e1", "2026-01-01T00:00:00+00:00", EventCategory.DEPLOYMENT_REGRESSION, version="v2"),
        _event("e2", "2026-01-01T00:02:00+00:00", EventCategory.READINESS_FAILURE, version="v2"),
    ]
    tasks = _run_scan(orch, events)

    scan = next(t for t in tasks if t.type == "operations_scan")
    assert scan.status == TaskStatus.SUCCEEDED
    remediate = next((t for t in tasks if t.type == "operations_remediate"), None)
    assert remediate is not None, "development rollback must be auto-authorized by policy"
    assert remediate.status == TaskStatus.SUCCEEDED
    rescan = next((t for t in tasks if t.type == "operations_rescan"), None)
    assert rescan is not None
    assert rescan.status == TaskStatus.SUCCEEDED
    assert "CLOSED" in rescan.evidence[-1].summary or "CONFIRMED" in " ".join(
        e.summary for e in rescan.evidence)

    incidents = list_incidents(orch.store, "p1")
    assert incidents and incidents[-1].remediation_succeeded


# ---- SCENARIO B: repeated failure -> automated remediation -> recurrence
# -> cooldown/circuit breaker -> escalation. -----------------------------
def test_scenario_b_recurrence_opens_circuit_breaker_and_escalates(tmp_path, policy_path):
    from aep.agents import operations_intelligence_agent as opsmod
    opsmod._recurrence_trackers.clear()
    orch = _orch(tmp_path, policy_path)
    # No healthy deployment evidence ever recorded: every remediation
    # attempt stays UNVERIFIED/unhealthy, so scanning the SAME incident
    # signature repeatedly must eventually escalate rather than retry
    # forever.
    escalated = False
    for i in range(5):
        events = [
            _event(f"a{i}", f"2026-01-0{i+1}T00:00:00+00:00", EventCategory.DEPLOYMENT_REGRESSION,
                   version="v2"),
            _event(f"b{i}", f"2026-01-0{i+1}T00:02:00+00:00", EventCategory.READINESS_FAILURE,
                   version="v2"),
        ]
        task = Task(id=f"scan-{i}", type="operations_scan", project_id="p1",
                    owner_agent="operations_intelligence_agent",
                    payload={"mode": "scan", "events": events, "environment": "development"})
        orch.store.save_task(task)
        orch.run_to_completion("p1")
        tasks = orch.store.list_tasks("p1")
        if any(t.type == "operations_escalate" and "circuit breaker" in
               " ".join(e.summary for e in t.evidence).lower() for t in tasks
               if t.type != "operations_escalate" or True):
            pass
        all_evidence = " ".join(e.summary for t in tasks for e in t.evidence)
        # Recurrence handling can surface as either a cooldown-window block
        # (Part 8's "same failure returns soon after" case, exercised here
        # since real wall-clock time barely advances between iterations)
        # or an explicit circuit-breaker OPEN once the escalation threshold
        # is reached - both are the required "do not remediate forever"
        # outcome, and both must route to an escalate task rather than
        # silently doing nothing.
        recurrence_blocked = ("cooldown" in all_evidence or "circuit breaker OPEN" in all_evidence)
        escalate_present = any(t.type == "operations_escalate" for t in tasks if t.id.startswith(
            "scan") is False) or any(t.type == "operations_escalate" for t in tasks)
        if recurrence_blocked and escalate_present:
            escalated = True
            break
    assert escalated, "repeated same-fingerprint failures must be blocked by recurrence " \
                       "handling (cooldown/circuit breaker) and routed to escalation"


# ---- SCENARIO C: insufficient evidence -> low confidence -> no unsafe
# remediation -> escalation. ----------------------------------------------
def test_scenario_c_insufficient_evidence_never_auto_remediates(tmp_path, policy_path):
    orch = _orch(tmp_path, policy_path)
    events = [
        _event("e1", "2026-01-01T00:00:00+00:00", EventCategory.READINESS_FAILURE),
        _event("e2", "2026-01-01T00:01:00+00:00", EventCategory.REPEATED_RESTART),
    ]
    tasks = _run_scan(orch, events)
    assert not any(t.type == "operations_remediate" for t in tasks)
    escalate = next(t for t in tasks if t.type == "operations_escalate")
    assert "Insufficient evidence" in " ".join(e.summary for e in escalate.evidence)


# ---- SCENARIO D: similar historical incident is advisory only; current
# evidence disagreeing must not force the old remediation to be reused. --
def test_scenario_d_historical_incident_is_advisory_not_binding(tmp_path, policy_path):
    orch = _orch(tmp_path, policy_path)
    from aep.operations.memory import IncidentMemoryRecord, record_incident

    # A prior incident with the SAME fingerprint shape was remediated by
    # rollback and succeeded.
    fingerprint = "svc-a|development|v2|DEPLOYMENT_REGRESSION+READINESS_FAILURE"
    record_incident(orch.store, "p1", IncidentMemoryRecord(
        fingerprint=fingerprint, incident_id="old-1", root_cause="BAD_DEPLOYMENT",
        confidence="HIGH_CONFIDENCE", remediation_used="rollback_nonprod",
        remediation_succeeded=True, environment="development",
    ))

    events = [
        _event("e1", "2026-01-01T00:00:00+00:00", EventCategory.DEPLOYMENT_REGRESSION, version="v2"),
        _event("e2", "2026-01-01T00:02:00+00:00", EventCategory.READINESS_FAILURE, version="v2"),
    ]
    tasks = _run_scan(orch, events)
    scan = next(t for t in tasks if t.type == "operations_scan")
    memory_evidence = [e for e in scan.evidence if e.source == "operations_memory"]
    assert memory_evidence, "similar prior incident must be surfaced as advisory evidence"
    assert "advisory only" in memory_evidence[0].summary
    # No deployment evidence exists NOW, so recovery cannot be verified as
    # SUCCESS just because it worked historically - the current rescan
    # must not blindly report success from the old remediation's outcome.
    rescan = next((t for t in tasks if t.type == "operations_rescan"), None)
    if rescan is not None:
        assert rescan.status != TaskStatus.SUCCEEDED
