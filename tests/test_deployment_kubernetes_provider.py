"""Kubernetes deployment provider (Phase 6 Part 7/8) - honest UNAVAILABLE
in this sandbox (no kubectl, no cluster), plus the real logic paths
exercised with an injected `run_kubectl` fake for the "cluster present"
branch."""
from __future__ import annotations

from aep.deployment.kubernetes_provider import KubernetesDeploymentProvider
from aep.deployment.provider import DeploymentProviderAvailability


def test_status_is_unavailable_in_this_sandbox():
    """No `kubectl` binary is installed here (verified during Phase 6
    investigation: `which kubectl` returns nothing) - this must never be
    silently reported as AVAILABLE."""
    provider = KubernetesDeploymentProvider()
    avail, reason = provider.status()
    assert avail == DeploymentProviderAvailability.UNAVAILABLE
    assert "never been exercised against a real cluster" in reason


def test_deploy_refuses_when_unavailable_never_fabricates_success():
    provider = KubernetesDeploymentProvider()
    plan = provider.plan("production", "abc123", "artifact-1")
    outcome = provider.deploy(plan)
    assert not outcome.success
    assert outcome.provider_status == DeploymentProviderAvailability.UNAVAILABLE


def test_status_reports_blocked_when_kubectl_binary_present_but_cluster_unreachable(monkeypatch):
    import aep.deployment.kubernetes_provider as mod
    monkeypatch.setattr(mod, "_kubectl_available", lambda: True)
    provider = KubernetesDeploymentProvider(
        run_kubectl=lambda args, timeout=60: {"ok": False, "stdout": "", "stderr": "connection refused"})
    avail, reason = provider.status()
    assert avail == DeploymentProviderAvailability.BLOCKED


def test_apply_is_never_treated_as_application_success_by_itself(monkeypatch):
    """Part 8: 'Never treat kubectl apply success as application success.'
    `deploy()` succeeding must not by itself make `verify()` pass - they
    are separate, real round-trips here."""
    import aep.deployment.kubernetes_provider as mod
    monkeypatch.setattr(mod, "_kubectl_available", lambda: True)
    calls = {"n": 0}

    def fake_kubectl(args, timeout=60):
        calls["n"] += 1
        if args[0] == "apply":
            return {"ok": True, "stdout": "deployment.apps/app configured", "stderr": ""}
        if args[0] == "cluster-info":
            return {"ok": True, "stdout": "Kubernetes control plane is running", "stderr": ""}
        # rollout status / get pods both fail even though apply succeeded
        return {"ok": False, "stdout": "", "stderr": "rollout exceeded its progress deadline"}

    provider = KubernetesDeploymentProvider(run_kubectl=fake_kubectl)
    plan = provider.plan("production", "abc123", "artifact-1")
    outcome = provider.deploy(plan)
    assert outcome.success  # apply itself succeeded
    verify = provider.verify(outcome.deployment_ref)
    assert not verify.passed  # but application-level verification correctly fails
