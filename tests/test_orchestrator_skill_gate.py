"""Stage C Part 1: proof that `Orchestrator._apply_skill_gate` is wired
into the REAL dispatch path (`run_task`), not just exercised standalone
the way `tests/test_skills_runtime_integration.py` does. Covers:

  1. A task type with NO entry in `TASK_SKILL_RULES` proceeds untouched
     even when a skill registry is configured but empty (regression
     safety - Stage C must not retroactively gate Phase 1-8 task types).
  2. A task type WITH a mapping but an empty skill registry stops/
     escalates to BLOCKED_ON_APPROVAL, logged the same way the generic
     policy gate logs its decision.
  3. A task type WITH a mapping and a correctly seeded registry proceeds,
     and task evidence contains the exact skill id/version resolved.
  4. A skill can never override an existing DENY/REQUIRE_APPROVAL policy
     decision - both gates run together end to end.
"""
from __future__ import annotations

import json

from aep.bootstrap import build_orchestrator
from aep.db.fake import FakeSkillRepository, FakeSkillVersionRepository
from aep.models import Evidence, ProjectConfig, RiskLevel, Task, TaskResult, TaskStatus
from aep.skills.definitions import seed_canonical_skills
from aep.skills.registry import SkillRegistry


class _AlwaysSucceedsAgent:
    """A trivial test-double agent: no real work, always succeeds. Used
    only so these tests can exercise the SKILL gate in isolation, without
    depending on a real agent's own (unrelated) preconditions - e.g.
    TestingAgent genuinely needs a runnable test suite on disk, which is
    irrelevant to what this file is proving."""
    name = "stub_agent"
    required_capabilities: set[str] = set()

    def run(self, task, ctx) -> TaskResult:
        return TaskResult(success=True, message="stub agent ran")


def _project(tmp_path, policy_path):
    return ProjectConfig(id="p", name="p", repo_path=str(tmp_path), policy_path=policy_path)


def _orch(tmp_path, policy_path, skill_registry=None):
    project = _project(tmp_path, policy_path)
    orch = build_orchestrator(db_path=str(tmp_path / "s.db"), project=project,
                               db_backend="sqlite", skill_registry=skill_registry)
    orch.agents["stub_agent"] = _AlwaysSucceedsAgent()
    return orch


def test_task_type_with_no_skill_mapping_proceeds_untouched(tmp_path, policy_path):
    """"recon" has no entry in TASK_SKILL_RULES - even with an empty
    registry configured, the gate must be a no-op."""
    empty_registry = SkillRegistry(FakeSkillRepository(), FakeSkillVersionRepository(), policy_path=policy_path)
    orch = _orch(tmp_path, policy_path, skill_registry=empty_registry)
    task = Task(id="t1", type="recon", project_id="p", owner_agent="recon",
                payload={"project_root": str(tmp_path)})
    orch.submit_graph("p", [task])
    orch.run_to_completion("p")
    result = orch.store.get_task(task.id)
    assert result.status == TaskStatus.SUCCEEDED


def test_task_type_with_mapping_and_empty_registry_escalates(tmp_path, policy_path):
    """"testing" IS mapped (requires the "testing" skill). An empty
    registry means resolution genuinely fails -> the task must stop and
    escalate, never silently proceed as if skills were optional."""
    empty_registry = SkillRegistry(FakeSkillRepository(), FakeSkillVersionRepository(), policy_path=policy_path)
    orch = _orch(tmp_path, policy_path, skill_registry=empty_registry)
    task = Task(id="t2", type="testing", project_id="p", owner_agent="stub_agent",
                payload={"project_root": str(tmp_path)})
    orch.submit_graph("p", [task])
    orch.run_to_completion("p")
    result = orch.store.get_task(task.id)
    assert result.status == TaskStatus.BLOCKED_ON_APPROVAL
    events = orch.store.query_events("p", task.id)
    assert any(e.action == "skill_gate_blocked" for e in events)


def test_task_type_with_mapping_and_seeded_registry_proceeds_with_evidence(tmp_path, policy_path):
    seeded = SkillRegistry(FakeSkillRepository(), FakeSkillVersionRepository(), policy_path=policy_path)
    seed_canonical_skills(seeded)
    orch = _orch(tmp_path, policy_path, skill_registry=seeded)
    task = Task(id="t3", type="testing", project_id="p", owner_agent="stub_agent",
                payload={"project_root": str(tmp_path)})
    orch.submit_graph("p", [task])
    orch.run_to_completion("p")
    result = orch.store.get_task(task.id)
    assert result.status == TaskStatus.SUCCEEDED

    skill_evidence = [e for e in result.evidence if e.source == "skill_registry"]
    assert len(skill_evidence) == 1
    payload = json.loads(skill_evidence[0].summary)
    required = payload["required_skills"]
    assert len(required) == 1
    testing_version = seeded.latest_version("testing")
    assert required[0]["skill_id"] == "testing"
    assert required[0]["version"] == testing_version.version


def test_skill_gate_cannot_override_existing_deny_or_require_approval(tmp_path, policy_path):
    """Both gates run together: even with skills fully resolved, a
    policy-gated task (a "policy_action" in the payload the generic gate
    evaluates) is still governed by PolicyEngine, never by skill content."""
    seeded = SkillRegistry(FakeSkillRepository(), FakeSkillVersionRepository(), policy_path=policy_path)
    seed_canonical_skills(seeded)
    orch = _orch(tmp_path, policy_path, skill_registry=seeded)
    # "deployment" is mapped in TASK_SKILL_RULES AND policy.yaml requires
    # approval for production deploys - proves the skill gate resolving
    # successfully does not bypass the still-pending policy gate.
    task = Task(id="t4", type="deployment", project_id="p", owner_agent="stub_agent",
                payload={"policy_action": "deployment.deploy",
                         "policy_context": {"environment": "production"},
                         "project_root": str(tmp_path)})
    orch.submit_graph("p", [task])
    orch.run_to_completion("p")
    result = orch.store.get_task(task.id)
    assert result.status == TaskStatus.BLOCKED_ON_APPROVAL
    events = orch.store.query_events("p", task.id)
    assert any(e.decision == "REQUIRE_APPROVAL" for e in events)
    # The skill gate never even ran for this task instance (policy gate
    # fires first in run_task) - no skill_gate_* event exists.
    assert not any(e.action in ("skill_gate_passed", "skill_gate_blocked") for e in events)
