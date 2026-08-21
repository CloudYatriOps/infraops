"""Kubernetes deployment provider (Phase 6 Part 7/8) - honest UNAVAILABLE
in this sandbox (no kubectl, no cluster), plus the real logic paths
exercised with an injected `run_kubectl` fake for the "cluster present"
branch."""
from __future__ import annotations

import pytest

from aep.deployment.kubernetes_provider import KubernetesDeploymentProvider
from aep.deployment.provider import DeploymentProviderAvailability


def test_status_classifies_the_real_environment_and_never_silently_claims_available():
    """The invariant under test is "never silently AVAILABLE", NOT "this
    machine has no kubectl".

    This previously hardcoded the original sandbox's environment (no
    `kubectl` binary => UNAVAILABLE). On a machine that DOES have kubectl
    installed but no reachable cluster, the provider correctly reports
    BLOCKED - and the test failed for reporting the truth. Assert the
    classification that matches the real environment, using the provider's
    own capability detection rather than a baked-in assumption.
    """
    import aep.deployment.kubernetes_provider as mod

    provider = KubernetesDeploymentProvider()
    avail, reason = provider.status()

    if not mod._kubectl_available():
        assert avail == DeploymentProviderAvailability.UNAVAILABLE
        assert "never been exercised against a real cluster" in reason
    else:
        # kubectl present: only a genuinely reachable cluster may yield
        # AVAILABLE. Anything else must be BLOCKED, never a silent pass.
        assert avail in (DeploymentProviderAvailability.BLOCKED,
                          DeploymentProviderAvailability.AVAILABLE)
        if avail is DeploymentProviderAvailability.BLOCKED:
            assert "no cluster is reachable" in reason
    assert reason, "a status must always carry an explanation, never a bare enum"


def test_deploy_refuses_unless_a_real_cluster_is_reachable_never_fabricates_success():
    provider = KubernetesDeploymentProvider()
    avail, _ = provider.status()
    if avail is DeploymentProviderAvailability.AVAILABLE:
        pytest.skip("a real Kubernetes cluster is reachable here; this test covers "
                     "the refusal path, which by definition does not apply")

    plan = provider.plan("production", "abc123", "artifact-1")
    outcome = provider.deploy(plan)
    assert not outcome.success
    # Whatever the real reason is (no binary => UNAVAILABLE, binary but no
    # cluster => BLOCKED), deploy must surface THAT status, not invent one
    # and not report success.
    assert outcome.provider_status == avail


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
