"""Threat-modeling the Phase 8 runtime itself, plus explicit autonomous-
safety proofs (Part 13/14): the autonomous runtime must be MORE
restricted operationally than an interactive operator, never less.

Lint-style structural assertions (same convention as
tests/test_operations_threat_model.py / tests/test_infra_threat_model.py)
plus executable tests proving policy cannot be bypassed by autonomous
mode.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from aep.models import PolicyDecisionType
from aep.policy import PolicyEngine
from aep.runtime.workloop import _run_job
from aep.state_store import StateStore

SRC = Path(__file__).resolve().parent.parent / "src" / "aep"
RUNTIME_DIR = SRC / "runtime"
_MODULES = sorted(RUNTIME_DIR.rglob("*.py"))


def _sources() -> dict[str, str]:
    return {str(p.relative_to(SRC)): p.read_text() for p in _MODULES}


def test_no_runtime_module_calls_an_ai_provider():
    for name, source in _sources().items():
        assert "router.generate" not in source, name
        assert ".generate(" not in source, name


def test_policy_action_passed_to_evaluate_is_always_a_fixed_literal():
    """Every `policy.evaluate(...)` call in runtime/ must pass a literal
    string as the action argument, never an f-string/format/concat built
    from job/project content - the exact discipline every prior phase's
    threat-model test enforces."""
    pattern = re.compile(r"policy\.evaluate\(\s*([^,]+),")
    for name, source in _sources().items():
        for m in pattern.finditer(source):
            arg = m.group(1).strip()
            assert arg.startswith('"') or arg.startswith("'") or arg.isidentifier(), (
                f"{name}: policy.evaluate() action arg {arg!r} is not a fixed literal/constant"
            )
        assert 'f"runtime.' not in source, name
        assert "f'runtime." not in source, name


def test_no_destructive_shell_argv_in_runtime_package():
    destructive = ["terraform destroy", "kubectl delete", "rm -rf", "DROP TABLE", "git push --force"]
    for name, source in _sources().items():
        for d in destructive:
            assert d not in source, f"{name} contains destructive literal {d!r}"


def test_runtime_scheduled_scan_action_is_never_deny_by_construction_but_destructive_action_is():
    """The two ALLOW-listed runtime.* actions are read-only discovery; the
    one runtime destructive action is DENY - never both permissive."""
    policy = PolicyEngine.from_yaml("config/policy.yaml")
    scan = policy.evaluate("runtime.scheduled_scan")
    destructive = policy.evaluate("runtime.autonomous_destructive_action")
    assert scan.decision == PolicyDecisionType.ALLOW
    assert destructive.decision == PolicyDecisionType.DENY


# ---- Executable autonomous-safety proofs -------------------------------

def test_autonomous_mode_cannot_bypass_protected_branch_deny():
    policy = PolicyEngine.from_yaml("config/policy.yaml")
    decision = policy.evaluate("github.push", {"branch": "main"})
    assert decision.decision == PolicyDecisionType.DENY


def test_autonomous_mode_cannot_bypass_force_push_approval():
    policy = PolicyEngine.from_yaml("config/policy.yaml")
    decision = policy.evaluate("github.push", {"branch": "feature", "force": True})
    assert decision.decision == PolicyDecisionType.REQUIRE_APPROVAL


def test_autonomous_mode_cannot_execute_denied_destructive_infrastructure_action():
    policy = PolicyEngine.from_yaml("config/policy.yaml")
    decision = policy.evaluate("infra.terraform_destroy")
    assert decision.decision == PolicyDecisionType.DENY


def test_autonomous_mode_cannot_bypass_production_deployment_approval():
    policy = PolicyEngine.from_yaml("config/policy.yaml")
    decision = policy.evaluate("deployment.deploy", {"environment": "production"})
    assert decision.decision == PolicyDecisionType.REQUIRE_APPROVAL


def test_workloop_denies_job_and_records_no_evidence_of_success_when_policy_denies(tmp_path, monkeypatch):
    """If a job type's fixed policy action were ever DENYed, the work loop
    must stop at POLICY_CHECK and never fabricate a successful outcome."""
    store = StateStore(str(tmp_path / "r.db"))

    class DenyEverything:
        def evaluate(self, action, context=None):
            from aep.models import PolicyDecision
            return PolicyDecision(action=action, decision=PolicyDecisionType.DENY,
                                   matched_rule="test", reason="test-forced-deny")

    job = {"job_id": "j1", "project_id": "proj", "job_type": "dependency_cve_scan",
           "interval_seconds": 60}
    result = _run_job(job, store, DenyEverything(), repo=".")
    assert result.outcome == "DENIED"
    assert result.stage == "POLICY_CHECK"
    # no fabricated success event was recorded for a denied job
    events = store.query_events(project_id="proj")
    assert events == []


def test_autonomous_mode_repeated_job_failure_is_quarantined(tmp_path):
    """A repeatedly-failing scheduled job is quarantined via the SAME
    circuit-breaker threshold mechanism the rest of the platform uses -
    it is not allowed to retry forever."""
    from aep.runtime import scheduler as scheduler_mod

    store = StateStore(str(tmp_path / "r.db"))
    scheduler_mod.register_default_jobs(store, "proj", interval_seconds=0.001)
    job_id = store.list_schedules()[0]["job_id"]
    results = []
    for _ in range(6):
        with store._cursor() as cur:
            cur.execute("UPDATE runtime_schedules SET next_run_at=? WHERE job_id=?",
                        ("2000-01-01T00:00:00+00:00", job_id))
        results = scheduler_mod.run_due_jobs(store, dispatch=lambda j: False, max_consecutive_failures=5)
    matching = [r for r in results if r["job_id"] == job_id]
    assert matching and matching[0]["quarantined"] is True
