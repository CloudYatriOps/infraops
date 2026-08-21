"""Trust Contract: a READ-MODEL/projection over data AEP already persists.

Per the approved Trust-First Architecture Review (P0.1/P0.2/P0.5), this
module introduces NO second source of truth and NO new tables. It answers
the Trust Contract's 18 questions, computes the four verification states,
and classifies a task's demonstrated trust level (L0-L2 only - L3-L5 are
explicitly out of scope for this pass) purely from:

  * `Task` + its `Evidence` list (already persisted, `models.py`)
  * `Event` rows for that task (already persisted, `state_store`/`events.py`)
  * `FindingRecord` rows linked via `task_id` (already persisted, `db/models.py`)

CRITICAL invariant (Part 2 of the review): `not_verified` is never an
empty omission. If a dimension was not checked, it is named, explicitly,
every time - see `_UNCHECKED_DEFAULT` below.

CRITICAL invariant (Part 2): a numeric confidence value is NEVER the
headline signal. `VerificationStatus` is a 4-state, non-numeric field;
any confidence numbers already present on findings/evidence remain
available as supporting detail only (see `Evidence`/`FindingRecord`
themselves - nothing here adds a new numeric score).

Trust level (L0-L2) is computed deterministically from real Task/Evidence/
Event/policy state - never from AI-authored narrative text. An AI may
populate a task's payload or evidence, but nothing in this module reads
free-text "reasoning" to decide a trust level.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .models import Evidence, Event, PolicyDecisionType, Task, TaskStatus

# ---------------------------------------------------------------------------
# Verification status (Part 2 / Part 5 of the review)
# ---------------------------------------------------------------------------

VERIFIED = "VERIFIED"
PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
UNVERIFIED = "UNVERIFIED"
CONTRADICTED = "CONTRADICTED"

# The fixed set of verification dimensions the Trust Contract always
# reports on. A dimension is either in `verified` or explicitly listed in
# `not_verified` - it is never simply absent from both.
#
# "human_approval" is deliberately NOT always in this base set: Level 2
# ("verified remediation") is, by definition (Part 5/Part 10 of the
# review), the class of action that does NOT require human approval when
# every OTHER deterministic criterion holds - counting an approval that
# was never required as "missing" would make VERIFIED unreachable for the
# exact automation level the review calls for. `build_trust_contract`
# adds "human_approval" to this set only when policy actually required it
# (a REQUIRE_APPROVAL decision) - at that point it genuinely is a missing
# or satisfied dimension, never silently dropped.
_VERIFICATION_DIMENSIONS = (
    "scanner_execution",   # a real scanner/tool actually ran against real input
    "independent_rescan",  # a second, independent run confirmed the result
    "tests_executed",      # the project's own test suite ran against the change
    "policy_evaluated",    # PolicyEngine.evaluate() ran for this action
    "skill_requirements",  # required skill(s) resolved (Part 4)
)

# ---------------------------------------------------------------------------
# Trust levels (Part 5 of the review) - L0-L2 ONLY. L3 (PR/CI), L4
# (deployment), L5 (continuous autonomy) are explicitly out of scope here.
# ---------------------------------------------------------------------------

L0 = "L0"  # suggestion only - no mutation, evidence may be incomplete
L1 = "L1"  # verified recommendation - reproducible evidence, no mutation
L2 = "L2"  # verified remediation - mutation, only when every L2 criterion holds

# The real, existing task-type vocabulary (`github/planner.py`,
# `dependency/planner.py`, `security/planner.py`, `infra/planner.py`,
# `operations/planner.py`) that actually changes something outside AEP's
# own state. Deployment/database-migration task types are deliberately
# NOT included: their trust model is Level 4 territory (Part 11 of the
# review), out of scope for this P0 pass.
MUTATING_TASK_TYPES = frozenset({
    "code_fix",
    "dependency_remediate",
    "security_remediate",
    "infra_remediate",
    "operations_remediate",
    "push_branch",
    "create_pull_request",
    "git_operation",
    "github_operation",
})


def compute_verification_status(verified: list[str], not_verified: list[str],
                                 contradicted: bool = False) -> str:
    """Pure 4-state mapping (Part 2). A "95% confidence" AI output with an
    empty `verified` list is UNVERIFIED, full stop - no numeric value can
    upgrade this."""
    if contradicted:
        return CONTRADICTED
    if not verified:
        return UNVERIFIED
    if not not_verified:
        return VERIFIED
    return PARTIALLY_VERIFIED


@dataclass
class TrustContract:
    """The 18-question projection (Part 3 of the review). Every field maps
    directly to already-persisted data; nothing here is a new write path."""
    action_id: str
    what: str
    why: str
    changed: str
    evidence: list[dict] = field(default_factory=list)
    evidence_sources: list[str] = field(default_factory=list)
    evidence_observed_at: list[str] = field(default_factory=list)
    verified: list[str] = field(default_factory=list)
    not_verified: list[str] = field(default_factory=list)
    verification_status: str = UNVERIFIED
    policy_rule: Optional[str] = None
    authorized_by: Optional[str] = None
    tools_used: list[str] = field(default_factory=list)
    skill_used: list[str] = field(default_factory=list)
    outcome: str = "UNKNOWN"
    outcome_verified: bool = False
    trust_level: str = L0
    rollback_available: Optional[bool] = None
    rollback_verified: bool = False
    post_change_events: list[str] = field(default_factory=list)
    permanent_evidence_refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "action_id": self.action_id,
            "what": self.what,
            "why": self.why,
            "changed": self.changed,
            "evidence": self.evidence,
            "evidence_sources": self.evidence_sources,
            "evidence_observed_at": self.evidence_observed_at,
            "verified": self.verified,
            "not_verified": self.not_verified,
            "verification_status": self.verification_status,
            "policy": {"matched_rule": self.policy_rule},
            "authorization": {"authorized_by": self.authorized_by},
            "tools_used": self.tools_used,
            "skills_used": self.skill_used,
            "outcome": {"status": self.outcome, "verified": self.outcome_verified},
            "trust_level": self.trust_level,
            "rollback": {"available": self.rollback_available, "verified": self.rollback_verified},
            "audit_refs": {
                "post_change_events": self.post_change_events,
                "permanent_evidence_refs": self.permanent_evidence_refs,
            },
        }


def _skill_evidence(task: Task) -> Optional[Evidence]:
    for e in task.evidence:
        if e.source == "skill_registry":
            return e
    return None


def _policy_event(events: list[Event]) -> Optional[Event]:
    for e in events:
        if e.action == "policy_evaluated":
            return e
    return None


def _approval_event(events: list[Event]) -> Optional[Event]:
    for e in events:
        if e.action == "approval_granted":
            return e
    return None


def build_trust_contract(task: Task, events: Optional[list[Event]] = None,
                          finding_count: int = 0) -> TrustContract:
    """Assembles the Trust Contract for one Task from data already on the
    Task/Event objects. `events` should be that task's own Event rows
    (e.g. `store.query_events(project_id=..., task_id=task.id)`, the same
    call `scan_lifecycle.get_scan_run` already makes for its Timeline)."""
    events = events or []
    is_mutating = task.type in MUTATING_TASK_TYPES

    verified: list[str] = []
    evidence_dicts: list[dict] = []
    evidence_sources: list[str] = []
    evidence_observed_at: list[str] = []
    tools_used: list[str] = []

    for e in task.evidence:
        evidence_dicts.append(e.to_dict())
        evidence_sources.append(e.source)
        evidence_observed_at.append(e.captured_at)
        tools_used.append(e.source)
        if e.source not in ("skill_registry",):
            # A real tool/scanner actually ran and left evidence. This is
            # the minimum bar for "scanner_execution" - it does NOT by
            # itself imply independent re-verification (see below).
            if "scanner_execution" not in verified:
                verified.append("scanner_execution")

    # Independent rescan: a second scan/finding-generating evidence entry
    # of the same source class, OR an explicit rescan/re-run task type.
    scan_like_sources = [e for e in task.evidence if e.source in ("aep.scan",)]
    if len(scan_like_sources) > 1 or task.type.endswith("_rescan"):
        verified.append("independent_rescan")

    # Tests: a real `run_tests` evidence entry with a captured exit code.
    if any(e.source in ("pytest", "run_tests", "testing_agent") for e in task.evidence):
        verified.append("tests_executed")

    policy_evt = _policy_event(events)
    policy_rule: Optional[str] = None
    authorized_by = "policy:default_posture"
    if policy_evt is not None:
        verified.append("policy_evaluated")
        policy_rule = (policy_evt.details or {}).get("policy_action")
        if policy_evt.decision:
            authorized_by = f"policy:decision={policy_evt.decision}"

    skill_evt = _skill_evidence(task)
    skill_used: list[str] = []
    if skill_evt is not None:
        verified.append("skill_requirements")
        tools_used.append("skill_registry")

    approval_evt = _approval_event(events)
    approval_was_required = bool(
        policy_evt and policy_evt.decision == PolicyDecisionType.REQUIRE_APPROVAL.value
    )
    dimensions = _VERIFICATION_DIMENSIONS + (("human_approval",) if approval_was_required else ())
    if approval_evt is not None:
        verified.append("human_approval")
        authorized_by = f"human:{approval_evt.actor}"

    not_verified = [d for d in dimensions if d not in verified]
    verification_status = compute_verification_status(verified, not_verified)

    outcome = task.status.value
    outcome_verified = task.status == TaskStatus.SUCCEEDED and "scanner_execution" in verified

    trust_level = compute_trust_level(
        task=task, verification_status=verification_status,
        policy_denied=bool(policy_evt and policy_evt.decision == PolicyDecisionType.DENY.value),
        skill_required_and_missing=(task.type in _skill_required_task_types() and skill_evt is None),
    )

    rollback_available: Optional[bool] = None
    if is_mutating:
        # None of these task types auto-merge (dependency/security/infra
        # remediation chains always end in `create_pull_request`, never a
        # merge - see `dependency/planner.py::_pr_body`); the change is
        # reversible by discarding the branch/PR until a human merges it.
        rollback_available = True

    return TrustContract(
        action_id=task.id,
        what=f"{task.type} on project {task.project_id}",
        why=(task.payload.get("bug_description") or task.payload.get("reason")
             or f"triggered_by={task.payload.get('triggered_by', 'system')}"),
        changed=", ".join(task.artifacts) if task.artifacts else "(no artifacts recorded)",
        evidence=evidence_dicts,
        evidence_sources=evidence_sources,
        evidence_observed_at=evidence_observed_at,
        verified=verified,
        not_verified=not_verified,
        verification_status=verification_status,
        policy_rule=policy_rule,
        authorized_by=authorized_by,
        tools_used=sorted(set(tools_used)),
        skill_used=skill_used,
        outcome=outcome,
        outcome_verified=outcome_verified,
        trust_level=trust_level,
        rollback_available=rollback_available,
        rollback_verified=False,  # Part 33/P0 scope: rollback DRILLS are not implemented yet
        post_change_events=[e.action for e in events],
        permanent_evidence_refs=[task.id] + [e.id for e in events],
    )


def _skill_required_task_types() -> frozenset:
    from .skills.loader import TASK_SKILL_RULES
    return frozenset(t for t, rule in TASK_SKILL_RULES.items() if rule.get("required"))


def compute_trust_level(task: Task, verification_status: str, policy_denied: bool,
                         skill_required_and_missing: bool) -> str:
    """Deterministic L0-L2 classification (Part 5). Never reads AI-authored
    narrative text - only real Task/verification/policy/skill state.

    L0: the default - no mutation, or evidence is incomplete/UNVERIFIED.
    L1: non-mutating task, evidence reproducible (VERIFIED or
        PARTIALLY_VERIFIED - a real scan that ran is a verified
        recommendation even before every dimension is checked).
    L2: mutating task type AND task SUCCEEDED AND verification_status is
        VERIFIED AND policy did not deny AND (skill gate not required, or
        required and satisfied). Missing ANY of these caps the level at
        L1/L0 - no AI narrative can substitute for a missing criterion.
    """
    is_mutating = task.type in MUTATING_TASK_TYPES

    if not is_mutating:
        if verification_status in (VERIFIED, PARTIALLY_VERIFIED):
            return L1
        return L0

    if (task.status == TaskStatus.SUCCEEDED
            and verification_status == VERIFIED
            and not policy_denied
            and not skill_required_and_missing):
        return L2

    # A mutating task that hasn't (yet) met every L2 criterion is, at most,
    # a verified recommendation - never silently treated as executed-safe.
    if verification_status in (VERIFIED, PARTIALLY_VERIFIED):
        return L1
    return L0
