"""Deployability calculation (Phase 3 Part D).

Six explicit release states, derived from real phase/test gates - never
"tests pass, therefore production-ready" (the exact anti-pattern Part D
calls out). `live_github_verified`/`live_cve_feed_verified` are passed in
by the caller rather than inferred, because whether an external system was
*actually* exercised live is an operational fact this codebase cannot
observe from its own repo state - see ARCHITECTURE.md's "what is and isn't
real" sections for both Phase 2 (GitHub) and Phase 3 (CVE feeds).
"""
from __future__ import annotations

from dataclasses import dataclass

from .calculator import PHASE_COMPLETE, PHASE_VERIFIED, PlatformProgress

NOT_DEPLOYABLE = "NOT_DEPLOYABLE"
DEVELOPMENT_READY = "DEVELOPMENT_READY"
INTEGRATION_READY = "INTEGRATION_READY"
STAGING_READY = "STAGING_READY"
PRODUCTION_CANDIDATE = "PRODUCTION_CANDIDATE"
PRODUCTION_READY = "PRODUCTION_READY"

_DONE = (PHASE_COMPLETE, PHASE_VERIFIED)

_LATER_PHASES = (
    (4, "Security Intelligence"),
    (5, "Infrastructure Intelligence"),
    (6, "CI/CD & Deployment"),
    (7, "Runtime/Observability"),
    (8, "24/7 Autonomous Operation"),
    # Note: Phase 9 ("Product Foundation & Governance" - PostgreSQL
    # foundation/skill registry/AI gateway/governance, added in Stage A)
    # is deliberately NOT listed here. It is cross-cutting platform
    # plumbing, not a user-facing capability phase like 4-8/10 - it is
    # tracked by `aep progress` like every other phase, but is not a
    # deployability gate the way GitHub/CVE/security/infra/CI/runtime
    # phases are.
    (10, "Multi-Project/Advanced Intelligence"),
)


@dataclass
class DeployabilityResult:
    level: str
    blockers: list[str]

    def to_dict(self) -> dict:
        return {"level": self.level, "blockers": self.blockers}


def compute_deployability(progress: PlatformProgress, live_github_verified: bool = False,
                           live_cve_feed_verified: bool = True) -> DeployabilityResult:
    blockers: list[str] = []
    p1, p2, p3 = progress.phase(1), progress.phase(2), progress.phase(3)

    if progress.total_tests_failed > 0:
        blockers.append(f"{progress.total_tests_failed} test(s) currently failing.")

    if p1 is None or p1.status not in _DONE:
        blockers.append("Phase 1 (Core Platform) is not COMPLETE.")
        return DeployabilityResult(NOT_DEPLOYABLE, blockers)
    if progress.total_tests_failed > 0:
        return DeployabilityResult(NOT_DEPLOYABLE, blockers)

    level = DEVELOPMENT_READY

    if p2 is not None and p2.status in _DONE:
        level = INTEGRATION_READY
    else:
        blockers.append("Phase 2 (GitHub Engineering) is not COMPLETE - required for "
                         "INTEGRATION_READY.")

    if level == INTEGRATION_READY and p3 is not None and p3.status in _DONE:
        level = STAGING_READY
    elif p3 is None or p3.status not in _DONE:
        blockers.append("Phase 3 (Dependency & CVE Intelligence) is not COMPLETE - required for "
                         "STAGING_READY.")

    if not live_github_verified:
        blockers.append("Live GitHub API integration has never been exercised in this sandbox "
                         "(egress proxy blocks api.github.com) - required for PRODUCTION_CANDIDATE.")
    if not live_cve_feed_verified:
        blockers.append("Live CVE/advisory feed integration has not been verified - required for "
                         "PRODUCTION_CANDIDATE.")

    later_incomplete = []
    for phase_num, phase_name in _LATER_PHASES:
        phase_obj = progress.phase(phase_num)
        if phase_obj is None or phase_obj.status not in _DONE:
            # Phase 4 addendum: this used to always read "not started",
            # which was accurate for every phase until Phase 4 itself
            # started reporting real IN_PROGRESS/BLOCKED percentages - the
            # message now reflects the real status instead of a hardcoded
            # word, per this file's own "never invent/misreport a status"
            # rule.
            status_word = phase_obj.status if phase_obj is not None else "NOT_STARTED"
            blockers.append(f"Phase {phase_num} ({phase_name}) is {status_word} "
                             f"({phase_obj.percent if phase_obj is not None else 0.0}%).")
            later_incomplete.append(phase_num)

    if (level == STAGING_READY and live_github_verified and live_cve_feed_verified
            and not any(n in (4, 5, 6) for n in later_incomplete)):
        level = PRODUCTION_CANDIDATE

    p7, p8 = progress.phase(7), progress.phase(8)
    if (level == PRODUCTION_CANDIDATE and p7 is not None and p7.status in _DONE
            and p8 is not None and p8.status in _DONE):
        level = PRODUCTION_READY

    return DeployabilityResult(level=level, blockers=blockers)
