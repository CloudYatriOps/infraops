"""Cloud adapter contract tests (Phase 5 Part 5/6/12/16).

MOCKED TRANSPORT, labelled explicitly: there are no cloud credentials in
this environment and no cloud endpoint is reachable, so the AWS adapter's
LOGIC is exercised for real against an injected fake client - the same
boundary Phase 2 draws with `FakeGitHubTransport`. No test here claims
live cloud verification, and `CloudDiscoveryResult.is_real` is asserted
False throughout.
"""
from __future__ import annotations

import pytest

from aep.infra.cloud import registry
from aep.infra.cloud.aws_adapter import AWSAdapter
from aep.infra.cloud.base import (
    CloudAdapterStatus, CloudCapability, ReadOnlyViolation, assert_read_only,
    is_read_only_operation,
)


class FakeAWSClient:
    """An injected test double. Every method returns a realistically-shaped
    AWS response so the adapter's normalization is genuinely exercised."""

    def __init__(self, service: str, fail_on: set[str] | None = None):
        self.service = service
        self.fail_on = fail_on or set()
        self.calls: list[str] = []

    def _record(self, name: str):
        self.calls.append(name)
        if name in self.fail_on:
            raise PermissionError(f"AccessDenied: not authorized to call {name}")

    def get_caller_identity(self, **kwargs):
        self._record("get_caller_identity")
        return {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/test"}

    def list_buckets(self, **kwargs):
        self._record("list_buckets")
        return {"Buckets": [{"Name": "prod-data"}, {"Name": "logs"}]}

    def describe_security_groups(self, **kwargs):
        self._record("describe_security_groups")
        return {"SecurityGroups": [{
            "GroupId": "sg-open", "GroupName": "wide-open", "VpcId": "vpc-1",
            "IpPermissions": [{"FromPort": 22, "ToPort": 22,
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        }, {
            "GroupId": "sg-closed", "GroupName": "internal", "VpcId": "vpc-1",
            "IpPermissions": [{"FromPort": 443, "ToPort": 443,
                                "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}],
        }]}

    def describe_db_instances(self, **kwargs):
        self._record("describe_db_instances")
        return {"DBInstances": [{"DBInstanceIdentifier": "prod-db", "PubliclyAccessible": True,
                                  "StorageEncrypted": False, "BackupRetentionPeriod": 0,
                                  "Engine": "postgres"}]}

    def list_secrets(self, **kwargs):
        self._record("list_secrets")
        return {"SecretList": [{"Name": "db-password", "RotationEnabled": False,
                                 "KmsKeyId": None}]}

    def describe_trails(self, **kwargs):
        self._record("describe_trails")
        return {"trailList": [{"Name": "audit", "IsMultiRegionTrail": True,
                                "KmsKeyId": "key-1"}]}

    def get_secret_value(self, **kwargs):  # pragma: no cover - must never be called
        raise AssertionError("the adapter must never call get_secret_value")

    def delete_bucket(self, **kwargs):  # pragma: no cover - must never be called
        raise AssertionError("the adapter must never call a mutating operation")

    def __getattr__(self, name):
        def _default(**kwargs):
            self.calls.append(name)
            return {}
        return _default


def _adapter(fail_on=None):
    clients: dict[str, FakeAWSClient] = {}

    def factory(service: str):
        clients.setdefault(service, FakeAWSClient(service, fail_on))
        return clients[service]

    adapter = AWSAdapter(client_factory=factory)
    return adapter, clients


# ---- read-only enforcement (Part 6) ---------------------------------------

def test_read_only_allowlist_accepts_inspection_verbs():
    for operation in ("describe_instances", "list_buckets", "get_caller_identity",
                       "head_bucket", "search_resources"):
        assert is_read_only_operation(operation)


def test_read_only_allowlist_rejects_every_mutating_verb():
    for operation in ("delete_bucket", "terminate_instances", "put_object", "create_role",
                       "update_policy", "attach_role_policy", "modify_db_instance",
                       "destroy_stack", "apply_terraform"):
        assert not is_read_only_operation(operation)
        with pytest.raises(ReadOnlyViolation):
            assert_read_only(operation)


def test_credential_minting_operations_are_denied_despite_the_get_prefix():
    """`get_session_token` starts like a read but mints credentials."""
    for operation in ("get_session_token", "get_federation_token", "get_secret_value",
                       "get_password_data"):
        assert not is_read_only_operation(operation)


def test_adapter_exposes_no_write_method():
    adapter, _ = _adapter()
    for verb in ("create", "delete", "update", "modify", "apply", "put", "terminate", "destroy"):
        assert not [name for name in dir(adapter)
                    if name.startswith(verb) and not name.startswith("_")]


def test_adapter_never_reads_a_secret_value():
    adapter, clients = _adapter()
    adapter.discover([CloudCapability.SECRETS])
    assert "get_secret_value" not in clients["secretsmanager"].calls


# ---- status labelling (Part 12) -------------------------------------------

def test_injected_transport_is_labelled_mocked_never_real():
    adapter, _ = _adapter()
    status, reason = adapter.status()
    assert status == CloudAdapterStatus.MOCKED
    assert "NOT live cloud verification" in reason
    assert adapter.discover([CloudCapability.STORAGE]).is_real is False


def test_live_status_is_not_available_in_this_environment():
    """This sandbox exports the egress PROXY's credentials as
    AWS_ACCESS_KEY_ID, which boto3 resolves. A presence check would report
    a false AVAILABLE for an account that does not exist - the adapter
    verifies with a real sts round-trip instead."""
    status, reason = AWSAdapter().status()
    assert status != CloudAdapterStatus.AVAILABLE
    assert status in (CloudAdapterStatus.UNAVAILABLE, CloudAdapterStatus.BLOCKED)
    assert reason


# ---- discovery + normalization --------------------------------------------

def test_discovery_covers_all_eleven_part5_capabilities():
    adapter, _ = _adapter()
    assert adapter.supported_capabilities == set(CloudCapability)
    assert len(CloudCapability) == 11


def test_normalizes_public_exposure_to_provider_neutral_attributes():
    adapter, _ = _adapter()
    result = adapter.discover([CloudCapability.NETWORKING])
    open_group = next(r for r in result.resources if r.resource_id.endswith("sg-open"))
    closed_group = next(r for r in result.resources if r.resource_id.endswith("sg-closed"))
    assert open_group.attributes["public"] is True
    assert closed_group.attributes["public"] is False


def test_normalizes_database_encryption_and_backup_attributes():
    adapter, _ = _adapter()
    result = adapter.discover([CloudCapability.DATABASES])
    database = next(r for r in result.resources if "prod-db" in r.resource_id)
    assert database.attributes["public"] is True
    assert database.attributes["encrypted"] is False
    assert database.attributes["backup_retention"] == 0


def test_account_id_is_masked_in_serialized_output():
    adapter, _ = _adapter()
    result = adapter.discover([CloudCapability.ACCOUNT_DISCOVERY])
    assert result.account_id == "123456789012"
    assert result.to_dict()["account_id"] == "****9012"


def test_a_failing_capability_is_recorded_not_silently_empty():
    """An IAM permission gap must not produce a falsely-clean result."""
    adapter, _ = _adapter(fail_on={"describe_db_instances"})
    result = adapter.discover([CloudCapability.DATABASES, CloudCapability.STORAGE])
    assert "databases" in result.capabilities_failed
    assert "AccessDenied" in result.capabilities_failed["databases"]
    # The other capability still worked - one failure degrades one area.
    assert any("prod-data" in r.resource_id for r in result.resources)


# ---- registry (Part 5) -----------------------------------------------------

def test_only_one_provider_is_implemented():
    assert registry.supported_providers() == ["aws"]


def test_unimplemented_providers_report_not_implemented_rather_than_stubbing():
    for provider in ("azure", "gcp", "oci"):
        result = registry.describe_provider(provider)
        assert result.status == CloudAdapterStatus.NOT_IMPLEMENTED
        assert result.resources == []
        assert result.is_real is False
        # An empty result from a stub would be indistinguishable from a
        # real adapter reporting a clean account.
        assert "Phase 5" in result.reason


def test_unknown_provider_is_reported_clearly():
    result = registry.describe_provider("not-a-cloud")
    assert result.status == CloudAdapterStatus.NOT_IMPLEMENTED
    assert "not a provider this platform knows about" in result.reason


def test_discovery_result_is_serializable():
    import json
    adapter, _ = _adapter()
    result = adapter.discover([CloudCapability.STORAGE, CloudCapability.NETWORKING])
    assert json.dumps(result.to_dict())
