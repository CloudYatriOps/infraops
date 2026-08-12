"""Infrastructure discovery (Phase 5 Part 1/16). Pure filesystem
inspection - fast, offline, no tool dependencies."""
from __future__ import annotations

from pathlib import Path

from aep.infra.discovery import discover_infrastructure, infer_environment
from aep.infra.models import AssetKind, Environment


def _build_repo(root: Path) -> None:
    (root / "envs/prod").mkdir(parents=True)
    (root / "envs/dev").mkdir(parents=True)
    (root / "modules/vpc").mkdir(parents=True)
    (root / "k8s").mkdir()
    (root / "charts/web/templates").mkdir(parents=True)
    (root / ".github/workflows").mkdir(parents=True)

    (root / "envs/prod/main.tf").write_text(
        'terraform {\n  backend "s3" {\n    bucket = "tfstate"\n  }\n}\n'
        'provider "aws" {\n  region = "us-east-1"\n}\n'
        'resource "aws_s3_bucket" "data" {\n  bucket = "prod-data"\n}\n'
    )
    (root / "envs/dev/terraform.tfvars").write_text('env = "dev"\n')
    (root / "modules/vpc/main.tf").write_text(
        'resource "aws_vpc" "v" {\n  cidr_block = "10.0.0.0/16"\n}\n')
    (root / "k8s/deploy.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n")
    (root / "k8s/argo.yaml").write_text(
        "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: web\n")
    (root / "charts/web/Chart.yaml").write_text("apiVersion: v2\nname: web\nversion: 1.0.0\n")
    (root / "charts/web/values.yaml").write_text("replicas: 1\n")
    (root / "charts/web/templates/d.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .Release.Name }}\n")
    (root / "Dockerfile").write_text("FROM python:3.11-slim\nRUN pip install flask\n")
    (root / ".github/workflows/deploy.yml").write_text(
        "name: deploy\njobs:\n  d:\n    steps:\n      - run: terraform apply -auto-approve\n")
    (root / ".github/workflows/test.yml").write_text(
        "name: test\njobs:\n  t:\n    steps:\n      - run: pytest -q\n")


def test_discovers_every_asset_kind(tmp_path):
    _build_repo(tmp_path)
    inventory = discover_infrastructure(str(tmp_path))
    kinds = {a.kind for a in inventory.assets}

    assert AssetKind.TERRAFORM_ROOT in kinds
    assert AssetKind.TERRAFORM_MODULE in kinds
    assert AssetKind.TERRAFORM_STATE_CONFIG in kinds
    assert AssetKind.HELM_CHART in kinds
    assert AssetKind.KUBERNETES_MANIFEST in kinds
    assert AssetKind.GITOPS_CONFIG in kinds
    assert AssetKind.DOCKERFILE in kinds
    assert AssetKind.ENVIRONMENT_CONFIG in kinds
    assert AssetKind.CICD_INFRA_REFERENCE in kinds


def test_terraform_module_is_distinguished_from_root(tmp_path):
    _build_repo(tmp_path)
    inventory = discover_infrastructure(str(tmp_path))
    roots = {a.path for a in inventory.by_kind(AssetKind.TERRAFORM_ROOT)}
    modules = {a.path for a in inventory.by_kind(AssetKind.TERRAFORM_MODULE)}
    assert "envs/prod" in roots
    assert "modules/vpc" in modules
    # A module has no backend of its own and is never planned directly -
    # conflating the two would mean planning/validating the wrong thing.
    assert "modules/vpc" not in roots


def test_environment_is_inferred_with_confidence_and_defaults_to_unknown(tmp_path):
    _build_repo(tmp_path)
    inventory = discover_infrastructure(str(tmp_path))
    prod = next(a for a in inventory.by_kind(AssetKind.TERRAFORM_ROOT) if a.path == "envs/prod")
    assert prod.environment == Environment.PRODUCTION
    assert prod.environment_confidence == "high"

    dockerfile = next(a for a in inventory.by_kind(AssetKind.DOCKERFILE))
    # No environment marker in the path - must NOT be guessed as production.
    assert dockerfile.environment == Environment.UNKNOWN
    assert dockerfile.environment_confidence == "low"


def test_infer_environment_never_defaults_to_production():
    assert infer_environment("some/random/path.tf")[0] == Environment.UNKNOWN
    assert infer_environment("envs/prod/main.tf")[0] == Environment.PRODUCTION
    assert infer_environment("envs/staging/main.tf")[0] == Environment.STAGING
    assert infer_environment("deploy/dev/main.tf")[0] == Environment.DEVELOPMENT


def test_provider_hints_are_aggregated_per_terraform_directory(tmp_path):
    _build_repo(tmp_path)
    inventory = discover_infrastructure(str(tmp_path))
    prod = next(a for a in inventory.by_kind(AssetKind.TERRAFORM_ROOT) if a.path == "envs/prod")
    # The `provider "aws"` block and the resources are in the same file
    # here, but the union is computed per directory precisely because they
    # usually are not.
    assert "aws" in prod.provider_hints
    assert "terraform" in prod.provider_hints


def test_discovery_is_provider_agnostic_and_records_hints_opaquely(tmp_path):
    (tmp_path / "main.tf").write_text(
        'provider "oci" {\n  region = "uk-london-1"\n}\n'
        'resource "oci_core_vcn" "v" {\n  cidr_block = "10.0.0.0/16"\n}\n')
    inventory = discover_infrastructure(str(tmp_path))
    root = next(a for a in inventory.by_kind(AssetKind.TERRAFORM_ROOT))
    # Nothing in discovery knows what "oci" is - it is recorded verbatim.
    assert "oci" in root.provider_hints


def test_helm_templates_are_not_double_counted_as_kubernetes_manifests(tmp_path):
    _build_repo(tmp_path)
    inventory = discover_infrastructure(str(tmp_path))
    manifest_paths = {a.path for a in inventory.by_kind(AssetKind.KUBERNETES_MANIFEST)}
    assert "charts/web/templates/d.yaml" not in manifest_paths
    assert "k8s/deploy.yaml" in manifest_paths


def test_gitops_config_is_classified_more_specifically_than_kubernetes(tmp_path):
    _build_repo(tmp_path)
    inventory = discover_infrastructure(str(tmp_path))
    gitops_paths = {a.path for a in inventory.by_kind(AssetKind.GITOPS_CONFIG)}
    manifest_paths = {a.path for a in inventory.by_kind(AssetKind.KUBERNETES_MANIFEST)}
    assert "k8s/argo.yaml" in gitops_paths
    assert "k8s/argo.yaml" not in manifest_paths


def test_only_infra_touching_ci_workflows_are_inventoried(tmp_path):
    _build_repo(tmp_path)
    inventory = discover_infrastructure(str(tmp_path))
    ci_paths = {a.path for a in inventory.by_kind(AssetKind.CICD_INFRA_REFERENCE)}
    assert ".github/workflows/deploy.yml" in ci_paths
    # A plain test workflow is not infrastructure - inventorying it would
    # be noise, not signal.
    assert ".github/workflows/test.yml" not in ci_paths


def test_unreadable_files_are_recorded_not_silently_skipped(tmp_path):
    (tmp_path / "broken.yaml").write_bytes(b"\xff\xfe\x00binary\x00garbage")
    inventory = discover_infrastructure(str(tmp_path))
    assert any("broken.yaml" in entry["path"] for entry in inventory.unreadable)


def test_vendored_directories_are_skipped(tmp_path):
    (tmp_path / ".terraform/modules").mkdir(parents=True)
    (tmp_path / ".terraform/modules/vendored.tf").write_text('resource "aws_s3_bucket" "v" {}\n')
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "mine" {}\n')
    inventory = discover_infrastructure(str(tmp_path))
    assert all(".terraform" not in a.path for a in inventory.assets)


def test_empty_repository_yields_empty_inventory(tmp_path):
    inventory = discover_infrastructure(str(tmp_path))
    assert inventory.assets == []
    assert inventory.to_dict()["asset_count"] == 0
