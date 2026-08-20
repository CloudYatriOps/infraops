from aep.deployment.models import DeploymentRecord, DeploymentState
from aep.operations.observability import (
    AdapterAvailability, DeploymentHistoryAdapter, KNOWN_UNIMPLEMENTED_PROVIDERS,
    build_unimplemented_registry,
)


def test_all_named_future_providers_are_honestly_not_implemented():
    registry = build_unimplemented_registry()
    assert set(registry) == set(KNOWN_UNIMPLEMENTED_PROVIDERS)
    for adapter in registry.values():
        avail = adapter.check_availability()
        assert avail.status == AdapterAvailability.NOT_IMPLEMENTED
        for surface_fn in (adapter.metrics, adapter.logs, adapter.traces, adapter.alerts,
                            adapter.service_health, adapter.deployment_info):
            result = surface_fn()
            assert result.status == AdapterAvailability.NOT_IMPLEMENTED
            assert result.data == []  # never fabricated data for an unimplemented provider


def test_deployment_history_adapter_reports_real_and_never_fabricates_health_with_no_evidence():
    adapter = DeploymentHistoryAdapter(list_evidence_fn=lambda: [])
    assert adapter.check_availability().status == AdapterAvailability.REAL
    health = adapter.service_health()
    assert health.status == AdapterAvailability.REAL
    assert health.data == []  # no evidence -> no fabricated "healthy" claim


def test_deployment_history_adapter_derives_health_from_latest_record():
    record = DeploymentRecord(task_id="t1", commit_sha="abc123", artifact_id="art1",
                               environment="development", release_gates_passed=True,
                               approval_status="not_required", provider="local_fixture",
                               provider_status="REAL", final_state=DeploymentState.VERIFIED)
    adapter = DeploymentHistoryAdapter(list_evidence_fn=lambda: [record])
    health = adapter.service_health()
    assert health.data[0]["healthy"] is True
    info = adapter.deployment_info()
    assert info.data[0]["commit_sha"] == "abc123"


def test_metrics_logs_traces_alerts_are_unavailable_not_fabricated_on_deployment_adapter():
    adapter = DeploymentHistoryAdapter(list_evidence_fn=lambda: [])
    for surface_fn in (adapter.metrics, adapter.logs, adapter.traces, adapter.alerts):
        result = surface_fn()
        assert result.status == AdapterAvailability.UNAVAILABLE
        assert result.data == []
