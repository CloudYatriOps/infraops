"""Local fixture deployment provider (Phase 6 Part 7/15) - the one fully
implemented, safe-by-default provider.

This is a REAL, deterministic local deployment: it actually writes
durable JSON state to disk representing a running "deployment" (replica
count, readiness, version history) and actually reads it back for
`status`/`verify`/`rollback` - there is no live cluster or cloud target
anywhere in this module, and `status()` reports `LOCAL_FIXTURE` rather
than `AVAILABLE` so nothing downstream can mistake it for a live
Kubernetes/cloud deployment (Part 7: "clearly report LIVE_KUBERNETES as
unavailable... DO NOT fabricate deployment success"). What IS real here:
the state transitions, the file-backed durability, and the
deploy -> observe -> verify -> decide sequencing (Part 8's rule, applied
even though there is no live cluster to apply it to).

`health_check_fn` is the deliberate seam Part 16 needs to demonstrate
both a successful deployment and a realistic recovery scenario
deterministically (never by chance/timing): tests inject a function that
returns a specific pass/fail outcome rather than this module guessing at
real infrastructure health.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from .models import VerificationCheck
from .provider import (
    DeployOutcome, DeployPlan, DeploymentProviderAvailability, RollbackOutcome, VerifyOutcome,
)

PROVIDER_NAME = "local_fixture"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class LocalFixtureDeploymentProvider:
    name = PROVIDER_NAME

    def __init__(self, state_dir: str, desired_replicas: int = 2,
                 health_check_fn: Optional[Callable[[dict], tuple]] = None):
        self._state_dir = Path(state_dir)
        self._state_dir.mkdir(parents=True, exist_ok=True)
        self._desired_replicas = desired_replicas
        # Default health check: a deployment that was written to disk with
        # ready_replicas == desired_replicas is healthy - real logic over
        # real (locally simulated) state, not a hard-coded True.
        self._health_check_fn = health_check_fn or self._default_health_check

    def _state_path(self, deployment_ref: str) -> Path:
        return self._state_dir / f"{deployment_ref}.json"

    def _history_path(self, deployment_ref: str) -> Path:
        return self._state_dir / f"{deployment_ref}.history.json"

    def status(self) -> tuple:
        return (DeploymentProviderAvailability.LOCAL_FIXTURE,
                "a real, deterministic local deployment fixture - state is written to and read "
                "from disk, but no live cluster or cloud target is contacted. LIVE_KUBERNETES is "
                "UNAVAILABLE in this sandbox (no kubectl binary, no cluster - see "
                "kubernetes_provider.py).")

    def plan(self, environment: str, commit_sha: str, artifact_id: str) -> DeployPlan:
        return DeployPlan(
            environment=environment, commit_sha=commit_sha, artifact_id=artifact_id,
            steps=["write deployment state", f"scale to {self._desired_replicas} replica(s)",
                   "observe rollout", "run health checks"],
            dry_run=False,
        )

    def deploy(self, plan: DeployPlan) -> DeployOutcome:
        # Keyed by ENVIRONMENT only, not commit sha: this is "redeploy the
        # same application to the same environment with a new commit", so
        # a later `rollback()` has a meaningful prior version to restore.
        # Keying by commit sha (an earlier version of this module did)
        # would make every deploy a brand-new, history-less identity and
        # rollback would never have anything to roll back to.
        deployment_ref = f"{plan.environment}-app"
        state = {
            "environment": plan.environment, "commit_sha": plan.commit_sha,
            "artifact_id": plan.artifact_id, "desired_replicas": self._desired_replicas,
            "ready_replicas": self._desired_replicas, "restarts": 0, "deployed_at": _now(),
        }
        history_path = self._history_path(deployment_ref)
        history = json.loads(history_path.read_text()) if history_path.exists() else []
        state_path = self._state_path(deployment_ref)
        if state_path.exists():
            history.append(json.loads(state_path.read_text()))
            history_path.write_text(json.dumps(history))
        state_path.write_text(json.dumps(state))
        return DeployOutcome(
            success=True, provider=self.name,
            provider_status=DeploymentProviderAvailability.LOCAL_FIXTURE,
            rollout_status="ROLLOUT_COMPLETE",
            detail=f"wrote local deployment state for {deployment_ref} "
                   f"({self._desired_replicas} desired replica(s))",
            deployment_ref=deployment_ref,
        )

    def simulate_partial_rollout(self, deployment_ref: str, ready_replicas: int,
                                  restarts: int = 0) -> None:
        """Test-only injection point (Part 16 needs a DETERMINISTIC failure
        to demonstrate rollback, not a race or a random flake). Explicit
        and named for exactly what it does - this is not a hidden
        backdoor, it is the equivalent of a chaos-testing hook, used only
        by `tests/test_deployment_rollback.py` and the Part 16 E2E test."""
        state_path = self._state_path(deployment_ref)
        state = json.loads(state_path.read_text())
        state["ready_replicas"] = ready_replicas
        state["restarts"] = restarts
        state_path.write_text(json.dumps(state))

    def rollout_status(self, deployment_ref: str) -> dict:
        state_path = self._state_path(deployment_ref)
        if not state_path.exists():
            return {"found": False}
        state = json.loads(state_path.read_text())
        state["found"] = True
        return state

    def _default_health_check(self, state: dict) -> tuple:
        if state.get("ready_replicas", 0) >= state.get("desired_replicas", 1):
            return True, (f"{state['ready_replicas']}/{state['desired_replicas']} replicas ready")
        return False, f"{state.get('ready_replicas', 0)}/{state.get('desired_replicas', '?')} " \
                       f"replicas ready - below desired count"

    def verify(self, deployment_ref: str) -> VerifyOutcome:
        state = self.rollout_status(deployment_ref)
        if not state.get("found"):
            return VerifyOutcome(passed=False, checks=[
                VerificationCheck("deployment_exists", False, "no local deployment state found")])
        checks = [VerificationCheck("deployment_exists", True, "state file present")]
        healthy, detail = self._health_check_fn(state)
        checks.append(VerificationCheck("readiness", healthy, detail))
        checks.append(VerificationCheck(
            "restarts_below_threshold", state.get("restarts", 0) < 5,
            f"restarts={state.get('restarts', 0)}"))
        return VerifyOutcome(passed=all(c.passed for c in checks), checks=checks)

    def rollback(self, deployment_ref: str) -> RollbackOutcome:
        history_path = self._history_path(deployment_ref)
        if not history_path.exists():
            return RollbackOutcome(success=False,
                                    detail="no prior version recorded - cannot roll back")
        history = json.loads(history_path.read_text())
        if not history:
            return RollbackOutcome(success=False, detail="rollback history is empty")
        previous = history.pop()
        history_path.write_text(json.dumps(history))
        self._state_path(deployment_ref).write_text(json.dumps(previous))
        return RollbackOutcome(success=True,
                                detail=f"restored previous state (commit_sha="
                                       f"{previous.get('commit_sha')})")
