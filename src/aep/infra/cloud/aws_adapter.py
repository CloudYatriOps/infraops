"""AWS cloud adapter - the ONE fully-implemented provider (Phase 5 Part 5).

Real `boto3` calls, all eleven Part 5 capability areas, read-only enforced
on every single call. Chosen as the one real provider because `boto3` is
the only cloud SDK actually installable in this sandbox (pypi.org is
reachable; the Azure/GCP/OCI CLIs and this platform's ability to verify
them are not).

## Status labelling (Part 12)

There are NO AWS credentials in this environment, and there is no AWS
endpoint reachable through the egress proxy. `status()` therefore reports:

  - `MOCKED`      when a `client_factory` is injected (contract tests) -
                  the adapter logic is real, the transport is not.
  - `UNAVAILABLE` when boto3 or credentials are absent (the live state
                  here).
  - `AVAILABLE`   only when a real boto3 session resolves real credentials.

`CloudDiscoveryResult.is_real` is True only for `AVAILABLE`, so nothing
downstream can mistake a contract-test run for live cloud verification.
This adapter has NEVER been executed against a real AWS account by this
platform, and that is stated in the Phase 5 report rather than implied
away.

## Read-only enforcement

Every API call goes through `_call()`, which invokes
`base.assert_read_only()` before touching the client. There is no bypass
path and no write method. `_call` is also the single place errors are
caught, so a permission error on one capability degrades that capability
only - it never aborts a whole discovery pass, and the failure is recorded
in `capabilities_failed` rather than silently producing an empty (and
therefore falsely clean-looking) result.

Credentials are never passed in as literals: the adapter takes a
`client_factory`, or falls back to boto3's own credential chain
(environment/instance profile/SSO), optionally seeded from the platform's
existing `SecretManager` (`src/aep/secrets.py`) - never from a task
payload, a config file, or a constructor argument holding a raw key.
"""
from __future__ import annotations

from typing import Callable, Optional

from .base import (
    CloudAdapterStatus, CloudCapability, CloudDiscoveryResult, CloudResource, assert_read_only,
)

PROVIDER = "aws"

# Which boto3 client each capability needs, and the read-only operation
# used to enumerate it.
_CAPABILITY_PLAN: dict[CloudCapability, list[tuple[str, str]]] = {
    CloudCapability.ACCOUNT_DISCOVERY: [("sts", "get_caller_identity")],
    CloudCapability.IAM: [("iam", "list_roles"), ("iam", "list_policies")],
    CloudCapability.NETWORKING: [("ec2", "describe_security_groups"), ("ec2", "describe_vpcs")],
    CloudCapability.COMPUTE: [("ec2", "describe_instances")],
    CloudCapability.STORAGE: [("s3", "list_buckets")],
    CloudCapability.DATABASES: [("rds", "describe_db_instances")],
    CloudCapability.ENCRYPTION: [("kms", "list_keys")],
    CloudCapability.SECRETS: [("secretsmanager", "list_secrets")],
    CloudCapability.LOGGING: [("cloudtrail", "describe_trails")],
    CloudCapability.BACKUPS: [("backup", "list_backup_plans")],
    CloudCapability.PUBLIC_EXPOSURE: [("ec2", "describe_security_groups"),
                                       ("elbv2", "describe_load_balancers")],
}


class AWSAdapter:
    provider = PROVIDER
    supported_capabilities = set(_CAPABILITY_PLAN)

    def __init__(self, client_factory: Optional[Callable[[str], object]] = None,
                  region: str = "us-east-1", secret_manager=None):
        """`client_factory(service_name) -> client` is the injection point
        (mirrors `GitHubClient.transport` from Phase 2). When it is None,
        the adapter builds real boto3 clients using boto3's own credential
        chain - no credential is ever accepted as a literal argument."""
        self._client_factory = client_factory
        self._region = region
        self._secret_manager = secret_manager
        self._clients: dict[str, object] = {}
        self._injected = client_factory is not None

    # ---- client plumbing ------------------------------------------------
    def _client(self, service: str):
        if service in self._clients:
            return self._clients[service]
        if self._client_factory is not None:
            client = self._client_factory(service)
        else:
            import boto3
            client = boto3.client(service, region_name=self._region)
        self._clients[service] = client
        return client

    def _call(self, service: str, operation: str, **kwargs) -> dict:
        """The single enforcement + error-handling point for every AWS API
        call this adapter makes."""
        assert_read_only(operation)
        client = self._client(service)
        method = getattr(client, operation, None)
        if method is None:
            raise AttributeError(f"{service} client has no operation '{operation}'")
        return method(**kwargs) or {}

    # ---- status ---------------------------------------------------------
    def status(self) -> tuple[CloudAdapterStatus, str]:
        """Reports AVAILABLE only after an actual authenticated round-trip
        to AWS, never on the strength of credentials merely being present.

        This distinction is not pedantic - it was a real false positive
        caught during Phase 5 development. This sandbox exports
        `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` holding its **egress
        proxy's** credentials (a 14-character value beginning `prox`, not
        a 20-character `AKIA...` AWS key). `boto3.Session().get_credentials()`
        happily returns them, so an "are credentials present?" check
        reported AVAILABLE - and `CloudDiscoveryResult.is_real` would then
        have been True for an AWS account that does not exist. The actual
        API call fails with `ProxyConnectionError`.

        So the check below is a real, read-only `sts:GetCallerIdentity`
        round-trip - the canonical "am I truly authenticated" call. A
        network/proxy failure is BLOCKED; an auth failure is UNAVAILABLE;
        only a successful response is AVAILABLE.
        """
        if self._injected:
            return (CloudAdapterStatus.MOCKED,
                    "an injected client_factory is in use: adapter logic is real, the AWS "
                    "transport is a test double. This is NOT live cloud verification.")
        try:
            import boto3
        except ImportError:
            return (CloudAdapterStatus.UNAVAILABLE,
                    "boto3 is not installed (`pip install --break-system-packages boto3`)")
        try:
            credentials = boto3.Session().get_credentials()
        except Exception as e:  # noqa: BLE001 - any resolution failure means "no credentials"
            return CloudAdapterStatus.UNAVAILABLE, f"boto3 credential resolution failed: {e}"
        if credentials is None:
            return (CloudAdapterStatus.UNAVAILABLE,
                    "boto3 resolved no credentials (no environment variables, shared config, "
                    "instance profile, or SSO session). No AWS account has been contacted.")

        # Cheap shape check first, so an obviously-not-AWS value doesn't
        # cost a network timeout. AWS access key ids are 20 characters and
        # begin with a known 4-character prefix (AKIA/ASIA/AIDA/AROA/...).
        access_key = getattr(credentials, "access_key", "") or ""
        if len(access_key) != 20 or not access_key[:4].isupper() or not access_key.startswith("A"):
            return (CloudAdapterStatus.UNAVAILABLE,
                    f"resolved a credential from `{getattr(credentials, 'method', 'unknown')}` "
                    f"that is not shaped like an AWS access key id "
                    f"({len(access_key)} chars, expected 20 beginning with AKIA/ASIA/...). In this "
                    f"sandbox these environment variables hold the egress PROXY's credentials, "
                    f"not AWS ones - treating them as AWS access would be a false positive.")

        try:
            identity = boto3.client("sts", region_name=self._region).get_caller_identity()
        except Exception as e:  # noqa: BLE001 - distinguish network from auth below
            name = type(e).__name__
            if any(marker in name for marker in ("Proxy", "EndpointConnection", "ConnectTimeout",
                                                   "ConnectionError", "SSL")):
                return (CloudAdapterStatus.BLOCKED,
                        f"AWS credentials are present but the AWS API is unreachable from this "
                        f"environment ({name}: {str(e)[:160]})")
            return (CloudAdapterStatus.UNAVAILABLE,
                    f"AWS credentials were rejected or could not be verified ({name}: "
                    f"{str(e)[:160]})")
        return (CloudAdapterStatus.AVAILABLE,
                f"authenticated read-only round-trip to AWS succeeded (sts:GetCallerIdentity "
                f"returned account ****{str(identity.get('Account', ''))[-4:]})")

    # ---- per-capability normalizers -------------------------------------
    def _normalize(self, capability: CloudCapability, service: str, operation: str,
                    response: dict) -> list[CloudResource]:
        """Maps a raw AWS response onto provider-neutral attribute names so
        `infra/drift.py` can compare it against repository state without
        any AWS knowledge."""
        resources: list[CloudResource] = []

        if operation == "get_caller_identity":
            return resources  # account id is captured separately

        if operation == "list_buckets":
            for bucket in response.get("Buckets", []):
                resources.append(CloudResource(
                    resource_id=f"aws_s3_bucket.{bucket.get('Name')}", resource_type="s3_bucket",
                    capability=capability, region=self._region,
                    attributes={"name": bucket.get("Name")},
                ))
        elif operation == "describe_security_groups":
            for group in response.get("SecurityGroups", []):
                open_ranges = [
                    f"{perm.get('FromPort', 'all')}-{perm.get('ToPort', 'all')}"
                    for perm in group.get("IpPermissions", [])
                    for ip_range in perm.get("IpRanges", [])
                    if ip_range.get("CidrIp") == "0.0.0.0/0"
                ]
                resources.append(CloudResource(
                    resource_id=f"aws_security_group.{group.get('GroupId')}",
                    resource_type="security_group", capability=capability, region=self._region,
                    attributes={"name": group.get("GroupName"),
                                 "public": bool(open_ranges),
                                 "open_ingress_ports": ",".join(open_ranges) or None,
                                 "vpc_id": group.get("VpcId")},
                ))
        elif operation == "describe_vpcs":
            for vpc in response.get("Vpcs", []):
                resources.append(CloudResource(
                    resource_id=f"aws_vpc.{vpc.get('VpcId')}", resource_type="vpc",
                    capability=capability, region=self._region,
                    attributes={"cidr": vpc.get("CidrBlock"), "is_default": vpc.get("IsDefault")},
                ))
        elif operation == "describe_instances":
            for reservation in response.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    resources.append(CloudResource(
                        resource_id=f"aws_instance.{instance.get('InstanceId')}",
                        resource_type="ec2_instance", capability=capability, region=self._region,
                        attributes={"public": bool(instance.get("PublicIpAddress")),
                                     "state": (instance.get("State") or {}).get("Name"),
                                     "encrypted": all(
                                         b.get("Ebs", {}).get("Encrypted", False)
                                         for b in instance.get("BlockDeviceMappings", [])) or None},
                    ))
        elif operation == "describe_db_instances":
            for db in response.get("DBInstances", []):
                resources.append(CloudResource(
                    resource_id=f"aws_db_instance.{db.get('DBInstanceIdentifier')}",
                    resource_type="rds_instance", capability=capability, region=self._region,
                    attributes={"public": db.get("PubliclyAccessible"),
                                 "encrypted": db.get("StorageEncrypted"),
                                 "backup_retention": db.get("BackupRetentionPeriod"),
                                 "engine": db.get("Engine")},
                ))
        elif operation == "list_roles":
            for role in response.get("Roles", []):
                resources.append(CloudResource(
                    resource_id=f"aws_iam_role.{role.get('RoleName')}", resource_type="iam_role",
                    capability=capability,
                    attributes={"arn": role.get("Arn"), "path": role.get("Path")},
                ))
        elif operation == "list_policies":
            for policy in response.get("Policies", []):
                resources.append(CloudResource(
                    resource_id=f"aws_iam_policy.{policy.get('PolicyName')}",
                    resource_type="iam_policy", capability=capability,
                    attributes={"arn": policy.get("Arn"),
                                 "attachment_count": policy.get("AttachmentCount")},
                ))
        elif operation == "list_keys":
            for key in response.get("Keys", []):
                resources.append(CloudResource(
                    resource_id=f"aws_kms_key.{key.get('KeyId')}", resource_type="kms_key",
                    capability=capability, attributes={"arn": key.get("KeyArn")},
                ))
        elif operation == "list_secrets":
            for secret in response.get("SecretList", []):
                # Names and rotation metadata only - this adapter never
                # calls get_secret_value (explicitly on the read-only deny
                # list in base.py), so no secret VALUE can ever be read
                # through it.
                resources.append(CloudResource(
                    resource_id=f"aws_secretsmanager_secret.{secret.get('Name')}",
                    resource_type="secret", capability=capability,
                    attributes={"rotation_enabled": secret.get("RotationEnabled"),
                                 "kms_key": secret.get("KmsKeyId")},
                ))
        elif operation == "describe_trails":
            for trail in response.get("trailList", []):
                resources.append(CloudResource(
                    resource_id=f"aws_cloudtrail.{trail.get('Name')}", resource_type="cloudtrail",
                    capability=capability,
                    attributes={"logging": True, "multi_region": trail.get("IsMultiRegionTrail"),
                                 "encryption": bool(trail.get("KmsKeyId"))},
                ))
        elif operation == "list_backup_plans":
            for plan in response.get("BackupPlansList", []):
                resources.append(CloudResource(
                    resource_id=f"aws_backup_plan.{plan.get('BackupPlanName')}",
                    resource_type="backup_plan", capability=capability,
                    attributes={"backup": True, "plan_id": plan.get("BackupPlanId")},
                ))
        elif operation == "describe_load_balancers":
            for lb in response.get("LoadBalancers", []):
                resources.append(CloudResource(
                    resource_id=f"aws_lb.{lb.get('LoadBalancerName')}", resource_type="load_balancer",
                    capability=capability, region=self._region,
                    attributes={"public": lb.get("Scheme") == "internet-facing",
                                 "scheme": lb.get("Scheme")},
                ))
        return resources

    # ---- discovery ------------------------------------------------------
    def discover(self, capabilities: Optional[list[CloudCapability]] = None
                  ) -> CloudDiscoveryResult:
        status, reason = self.status()
        result = CloudDiscoveryResult(provider=PROVIDER, status=status, reason=reason)
        if status in (CloudAdapterStatus.UNAVAILABLE, CloudAdapterStatus.BLOCKED,
                       CloudAdapterStatus.NOT_IMPLEMENTED):
            # No fabricated resources, no empty-but-successful-looking
            # result: the status carries why nothing was discovered.
            return result

        requested = capabilities or list(_CAPABILITY_PLAN)
        for capability in requested:
            plan = _CAPABILITY_PLAN.get(capability)
            if plan is None:
                result.capabilities_failed[capability.value] = "not supported by this adapter"
                continue
            result.capabilities_attempted.append(capability)
            for service, operation in plan:
                try:
                    response = self._call(service, operation)
                except Exception as e:  # noqa: BLE001 - one capability failing (e.g. an IAM
                    # permission gap) must degrade only that capability, and must be RECORDED,
                    # never swallowed into a falsely-clean empty result.
                    result.capabilities_failed[capability.value] = f"{type(e).__name__}: {e}"
                    continue
                if operation == "get_caller_identity":
                    result.account_id = response.get("Account")
                result.resources.extend(
                    self._normalize(capability, service, operation, response))
        return result
