"""Infrastructure data model (Phase 5 Part 1/8).

Parallel to `dependency/models.py` (Phase 3) and `security/models.py`
(Phase 4): plain dataclasses used as structured evidence payloads and
function return values, never stored directly by StateStore. Task/Evidence
(`src/aep/models.py`) remain the only durable schema.

Infrastructure findings are NOT a new finding type - Part 8 explicitly
says "normalize infrastructure findings into the existing
SecurityFinding/risk model", so every scanner in `infra/scanners/`
returns the *existing* `security.models.SecurityFinding` /
`SecurityScanRecord`. What this module adds on top is the infrastructure
*context* those findings need to be prioritized correctly - environment,
blast radius, exploitability - via `InfraRiskContext`/`InfraRiskScore` in
`infra/risk.py`, keyed by finding id rather than by forking the model.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional


class AssetKind(str, Enum):
    """What a discovered file/directory actually is. Deliberately broader
    than "terraform + k8s": Part 1 asks for modules, Helm charts,
    Dockerfiles, cloud/environment config, GitOps config, and CI/CD
    infrastructure references."""
    TERRAFORM_ROOT = "terraform_root"        # a directory containing *.tf
    TERRAFORM_MODULE = "terraform_module"    # a nested module directory
    TERRAFORM_STATE_CONFIG = "terraform_state_config"  # backend config
    HELM_CHART = "helm_chart"                # a directory with Chart.yaml
    KUBERNETES_MANIFEST = "kubernetes_manifest"
    KUSTOMIZATION = "kustomization"
    DOCKERFILE = "dockerfile"
    DOCKER_COMPOSE = "docker_compose"
    CLOUD_CONFIG = "cloud_config"            # e.g. serverless.yml, cdk.json
    ENVIRONMENT_CONFIG = "environment_config"  # .env / env-specific tfvars
    GITOPS_CONFIG = "gitops_config"          # ArgoCD/Flux
    CICD_INFRA_REFERENCE = "cicd_infra_reference"  # workflows that touch infra


class Environment(str, Enum):
    """Part 8: "Production resources should have higher risk weighting than
    development resources." Inferred from path/name conventions by
    `infra/discovery.py::infer_environment` - explicitly a heuristic with a
    recorded confidence, never presented as ground truth."""
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"
    UNKNOWN = "unknown"


class BlastRadius(str, Enum):
    """How far a misconfiguration on this asset can reach if exploited."""
    ACCOUNT_WIDE = "account_wide"      # e.g. wildcard IAM, org-level policy
    CLUSTER_WIDE = "cluster_wide"      # e.g. ClusterRole, hostPath, hostNetwork
    NAMESPACE = "namespace"
    WORKLOAD = "workload"              # a single deployment/pod
    UNKNOWN = "unknown"


class Exploitability(str, Enum):
    """Whether reaching this finding requires prior access."""
    INTERNET_REACHABLE = "internet_reachable"   # public LB/NodePort/0.0.0.0/0
    ADJACENT_NETWORK = "adjacent_network"       # in-cluster/in-VPC only
    REQUIRES_LOCAL_ACCESS = "requires_local_access"
    UNKNOWN = "unknown"


@dataclass
class InfraAsset:
    """One discovered infrastructure artifact."""
    path: str                 # relative to project_root
    kind: AssetKind
    environment: Environment
    environment_confidence: str  # "high" | "medium" | "low"
    detail: str = ""
    provider_hints: list[str] = field(default_factory=list)  # e.g. ["aws"], ["kubernetes"]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["kind"] = self.kind.value
        d["environment"] = self.environment.value
        return d


@dataclass
class InfraInventory:
    """Part 1's "normalized infrastructure inventory" - provider-agnostic
    by construction: `provider_hints` records what a file *appears* to
    reference (from `provider "aws"` blocks, `apiVersion:` groups, image
    registries, etc.) without the discovery layer itself knowing or caring
    about any specific cloud."""
    assets: list[InfraAsset] = field(default_factory=list)
    unreadable: list[dict] = field(default_factory=list)  # {path, reason}

    def by_kind(self, kind: AssetKind) -> list[InfraAsset]:
        return [a for a in self.assets if a.kind == kind]

    @property
    def kinds(self) -> set[AssetKind]:
        return {a.kind for a in self.assets}

    @property
    def provider_hints(self) -> set[str]:
        return {h for a in self.assets for h in a.provider_hints}

    def to_dict(self) -> dict:
        return {
            "asset_count": len(self.assets),
            "kinds": sorted(k.value for k in self.kinds),
            "provider_hints": sorted(self.provider_hints),
            "environments": sorted({a.environment.value for a in self.assets}),
            "assets": [a.to_dict() for a in self.assets],
            "unreadable": self.unreadable,
        }


@dataclass
class ValidationResult:
    """Part 10: "Never report infrastructure remediation as successful
    without evidence." Each validator returns one of these; `ran=False`
    means the validator could not run at all (e.g. its binary is BLOCKED)
    and must NEVER be interpreted as "passed" - see
    `infra/validation.py`'s module docstring for why that distinction
    caused a real, concrete near-miss in this phase."""
    validator: str
    ran: bool
    passed: bool
    detail: str
    target: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DriftItem:
    """One difference between desired (repository) and actual (live)
    state - Part 7."""
    resource_id: str
    kind: str  # "drift" | "unmanaged" | "missing"
    desired: Optional[str]
    actual: Optional[str]
    security_relevant: bool
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DriftReport:
    """Part 7: report drift, unmanaged resources, configuration and
    security differences, and produce a remediation PLAN - never an
    automatic reconciliation."""
    source: str  # where "actual" came from, e.g. "aws:read_only" | "fixture"
    compared_at: str
    items: list[DriftItem] = field(default_factory=list)
    remediation_plan: list[str] = field(default_factory=list)
    reconciled: bool = False  # always False in Phase 5, by design

    @property
    def security_relevant_items(self) -> list[DriftItem]:
        return [i for i in self.items if i.security_relevant]

    def to_dict(self) -> dict:
        return {
            "source": self.source, "compared_at": self.compared_at,
            "item_count": len(self.items),
            "security_relevant_count": len(self.security_relevant_items),
            "items": [i.to_dict() for i in self.items],
            "remediation_plan": self.remediation_plan,
            "reconciled": self.reconciled,
        }
