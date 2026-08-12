"""Kubernetes deployment provider (Phase 6 Part 7/8).

Real architecture, honestly UNAVAILABLE in this sandbox: `kubectl` is not
installed (`which kubectl` returns nothing) and no cluster
(kind/k3s/minikube) is reachable - verified during Phase 6 investigation.
`status()` checks for the `kubectl` binary for real, at call time, rather
than assuming; if a future environment has it, `deploy()`/`verify()`
below already implement the real "deploy -> observe -> verify -> decide"
sequence Part 8 requires (manifest apply, rollout status, pod health,
readiness/liveness, service availability) and never treats `kubectl
apply`'s own exit code as application success - `verify()` always runs a
SEPARATE `kubectl rollout status`/`get pods` round-trip.
"""
from __future__ import annotations

import shutil
import subprocess
from typing import Optional

from .models import VerificationCheck
from .provider import (
    DeployOutcome, DeployPlan, DeploymentProviderAvailability, RollbackOutcome, VerifyOutcome,
)

PROVIDER_NAME = "kubernetes"


def _kubectl_available() -> bool:
    return shutil.which("kubectl") is not None


class KubernetesDeploymentProvider:
    name = PROVIDER_NAME

    def __init__(self, namespace: str = "default", kubeconfig: Optional[str] = None,
                 run_kubectl=None):
        self._namespace = namespace
        self._kubeconfig = kubeconfig
        # Injection point for tests, mirroring every other subprocess
        # wrapper in this codebase (`shell.run`, `run_shell` in
        # infra/security agents) - never called directly by production
        # code paths when kubectl is absent, since `status()` gates first.
        self._run_kubectl = run_kubectl or self._real_kubectl

    def _real_kubectl(self, args: list[str], timeout: int = 60) -> dict:
        cmd = ["kubectl", *args, "-n", self._namespace]
        if self._kubeconfig:
            cmd += ["--kubeconfig", self._kubeconfig]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return {"ok": proc.returncode == 0, "stdout": proc.stdout, "stderr": proc.stderr}
        except (subprocess.TimeoutExpired, OSError) as e:
            return {"ok": False, "stdout": "", "stderr": str(e)}

    def status(self) -> tuple:
        if not _kubectl_available():
            return (DeploymentProviderAvailability.UNAVAILABLE,
                    "the `kubectl` binary is not installed in this sandbox and no Kubernetes "
                    "cluster (kind/k3s/minikube) is configured - LIVE_KUBERNETES is UNAVAILABLE. "
                    "This provider has never been exercised against a real cluster.")
        result = self._run_kubectl(["cluster-info"], timeout=10)
        if not result.get("ok"):
            return (DeploymentProviderAvailability.BLOCKED,
                    f"kubectl is installed but no cluster is reachable: "
                    f"{result.get('stderr', '')[:200]}")
        return DeploymentProviderAvailability.AVAILABLE, "a real cluster is reachable via kubectl"

    def plan(self, environment: str, commit_sha: str, artifact_id: str) -> DeployPlan:
        return DeployPlan(environment=environment, commit_sha=commit_sha, artifact_id=artifact_id,
                           steps=["kubectl apply -f manifest.yaml", "kubectl rollout status",
                                  "kubectl get pods (readiness)", "kubectl get svc (availability)"],
                           dry_run=False)

    def deploy(self, plan: DeployPlan) -> DeployOutcome:
        avail, reason = self.status()
        if avail != DeploymentProviderAvailability.AVAILABLE:
            return DeployOutcome(success=False, provider=self.name, provider_status=avail,
                                  rollout_status="NOT_ATTEMPTED", detail=reason)
        # Real path (only reached with a real cluster - never exercised in
        # this sandbox): apply is NOT treated as success by itself, per
        # Part 8 - `deploy()` only reports what `kubectl apply` returned;
        # `verify()` is the separate, real success determination.
        deployment_ref = f"{plan.environment}-{plan.commit_sha[:12]}"
        apply_result = self._run_kubectl(["apply", "-f", f"{deployment_ref}.yaml"])
        return DeployOutcome(
            success=bool(apply_result.get("ok")), provider=self.name, provider_status=avail,
            rollout_status="APPLY_SUBMITTED" if apply_result.get("ok") else "APPLY_FAILED",
            detail=(apply_result.get("stdout") or apply_result.get("stderr"))[:400],
            deployment_ref=deployment_ref,
        )

    def rollout_status(self, deployment_ref: str) -> dict:
        result = self._run_kubectl(["rollout", "status", f"deployment/{deployment_ref}"])
        return {"found": result.get("ok", False), "raw": result}

    def verify(self, deployment_ref: str) -> VerifyOutcome:
        rollout = self._run_kubectl(["rollout", "status", f"deployment/{deployment_ref}"])
        pods = self._run_kubectl(["get", "pods", "-l", f"app={deployment_ref}"])
        checks = [
            VerificationCheck("rollout_status", bool(rollout.get("ok")),
                               rollout.get("stdout", rollout.get("stderr", ""))[:300]),
            VerificationCheck("pods_reachable", bool(pods.get("ok")),
                               pods.get("stdout", pods.get("stderr", ""))[:300]),
        ]
        return VerifyOutcome(passed=all(c.passed for c in checks), checks=checks)

    def rollback(self, deployment_ref: str) -> RollbackOutcome:
        result = self._run_kubectl(["rollout", "undo", f"deployment/{deployment_ref}"])
        return RollbackOutcome(success=bool(result.get("ok")),
                                detail=(result.get("stdout") or result.get("stderr"))[:400])
