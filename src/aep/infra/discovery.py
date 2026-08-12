"""Infrastructure discovery (Phase 5 Part 1).

Pure, read-only filesystem inspection - this module never executes a
binary, never reaches the network, and never mutates anything, which is
what makes Part 6's "discovery MUST default to read-only" true by
construction here rather than by policy alone (policy still gates it too;
see `security.finding`-style rules for `infra.discovery` in
config/policy.yaml).

Provider-agnostic by construction (Part 1: "Do not assume a specific cloud
provider"): this module records *hints* about what a file appears to
reference (a `provider "x"` block, an `apiVersion:` group, a registry
host) as opaque strings, and has no branch anywhere on a specific cloud.
`infra/cloud/` is where provider-specific code lives, and nothing here
imports it.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from .models import AssetKind, Environment, InfraAsset, InfraInventory

# Directories never worth walking into - vendored/generated content would
# otherwise dominate an inventory and slow every scan down.
_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".terraform", "vendor",
              ".venv", "venv", ".pytest_cache", "dist", "build", ".mypy_cache"}

_MAX_PROBE_BYTES = 200_000  # cap per-file read; a manifest bigger than this
                            # is recorded as discovered but not content-probed

_ENV_PATTERNS: list[tuple[re.Pattern, Environment, str]] = [
    (re.compile(r"(^|[/_.-])(prod|production|prd)([/_.-]|$)", re.I), Environment.PRODUCTION, "high"),
    (re.compile(r"(^|[/_.-])(staging|stage|stg|preprod|uat)([/_.-]|$)", re.I),
     Environment.STAGING, "high"),
    (re.compile(r"(^|[/_.-])(dev|development|sandbox|local)([/_.-]|$)", re.I),
     Environment.DEVELOPMENT, "high"),
    (re.compile(r"(^|[/_.-])(test|qa|ci)([/_.-]|$)", re.I), Environment.TEST, "medium"),
]

_K8S_API_GROUPS = re.compile(r"^\s*apiVersion:\s*(\S+)", re.M)
_K8S_KIND = re.compile(r"^\s*kind:\s*(\S+)", re.M)
_TF_PROVIDER = re.compile(r'provider\s+"([A-Za-z0-9_-]+)"')
_TF_BACKEND = re.compile(r'backend\s+"([A-Za-z0-9_-]+)"')
_TF_RESOURCE_PREFIX = re.compile(r'resource\s+"([a-z0-9]+)_')
_DOCKER_FROM = re.compile(r"^\s*FROM\s+(\S+)", re.M | re.I)

# A CI workflow only counts as an "infrastructure reference" if it actually
# mentions an infra tool - otherwise every repo's test workflow would be
# inventoried as infrastructure, which is noise, not signal.
_CICD_INFRA_TOKENS = re.compile(
    r"\b(terraform|tofu|helm|kubectl|kustomize|eksctl|aws\s|az\s|gcloud|oci\s|pulumi|"
    r"cloudformation|ansible|argocd|flux)\b", re.I)

_GITOPS_MARKERS = re.compile(
    r"argoproj\.io|fluxcd\.io|kustomize\.config\.k8s\.io|helm\.toolkit\.fluxcd\.io", re.I)


def infer_environment(path: str) -> tuple[Environment, str]:
    """Heuristic environment inference from path/filename conventions.

    Deliberately returns a confidence alongside the guess and defaults to
    UNKNOWN rather than PRODUCTION: over-guessing "production" would
    silently inflate every risk score (Part 8 weights production higher),
    which is a worse failure than admitting the environment isn't known.
    """
    normalized = path.replace(os.sep, "/")
    for pattern, env, confidence in _ENV_PATTERNS:
        if pattern.search(normalized):
            return env, confidence
    return Environment.UNKNOWN, "low"


def _read_text(path: Path) -> tuple[str, str]:
    """Returns (content, error). Binary/oversized files yield ("", reason)
    rather than raising - a stray binary under an infra directory must not
    abort a whole discovery pass."""
    try:
        if path.stat().st_size > _MAX_PROBE_BYTES:
            return "", f"file exceeds {_MAX_PROBE_BYTES} byte probe limit; discovered but not parsed"
        return path.read_text(), ""
    except (UnicodeDecodeError, ValueError):
        return "", "binary or non-utf8 content"
    except OSError as e:
        return "", f"unreadable: {e}"


def _looks_like_kubernetes(content: str) -> bool:
    return bool(_K8S_API_GROUPS.search(content) and _K8S_KIND.search(content))


def _k8s_provider_hints(content: str) -> list[str]:
    hints = {"kubernetes"}
    for api_version in _K8S_API_GROUPS.findall(content):
        if "/" in api_version:
            group = api_version.split("/", 1)[0]
            # e.g. "rbac.authorization.k8s.io" -> a k8s core group; a
            # vendor CRD group (e.g. "eks.amazonaws.com") is a real
            # provider signal worth keeping, opaquely.
            if not group.endswith("k8s.io"):
                hints.add(group)
    return sorted(hints)


def discover_infrastructure(project_root: str) -> InfraInventory:
    """Walks `project_root` and returns a normalized inventory. Read-only:
    this function opens files for reading and does nothing else."""
    root = Path(project_root).resolve()
    inventory = InfraInventory()
    seen_helm_chart_dirs: set[Path] = set()
    terraform_dirs: dict[Path, list[str]] = {}
    # Provider hints are collected per *directory*, then attached to that
    # directory's TERRAFORM_ROOT/MODULE asset: a root's provider set is the
    # union of what all its .tf files reference, and no single file is
    # authoritative (the `provider` block and the resources using it are
    # very often in different files).
    terraform_provider_hints: dict[Path, set[str]] = {}

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        current = Path(dirpath)

        # ---- Helm charts: a directory is a chart iff it has Chart.yaml ----
        if "Chart.yaml" in filenames:
            seen_helm_chart_dirs.add(current)
            rel = str(current.relative_to(root)) or "."
            env, confidence = infer_environment(rel)
            content, err = _read_text(current / "Chart.yaml")
            name = ""
            if content:
                match = re.search(r"^\s*name:\s*(\S+)", content, re.M)
                name = match.group(1) if match else ""
            inventory.assets.append(InfraAsset(
                path=rel, kind=AssetKind.HELM_CHART, environment=env,
                environment_confidence=confidence,
                detail=f"helm chart{f' ({name})' if name else ''}",
                provider_hints=["helm", "kubernetes"],
            ))
            if err:
                inventory.unreadable.append({"path": f"{rel}/Chart.yaml", "reason": err})

        for filename in filenames:
            full = current / filename
            rel = str(full.relative_to(root))
            env, confidence = infer_environment(rel)
            suffix = full.suffix.lower()

            # ---- Terraform ------------------------------------------------
            if suffix == ".tf":
                terraform_dirs.setdefault(current, []).append(filename)
                content, err = _read_text(full)
                if err:
                    inventory.unreadable.append({"path": rel, "reason": err})
                    continue
                terraform_provider_hints.setdefault(current, set()).update(
                    {*_TF_PROVIDER.findall(content), *_TF_RESOURCE_PREFIX.findall(content)})
                backends = _TF_BACKEND.findall(content)
                if backends:
                    inventory.assets.append(InfraAsset(
                        path=rel, kind=AssetKind.TERRAFORM_STATE_CONFIG, environment=env,
                        environment_confidence=confidence,
                        detail=f"terraform backend: {', '.join(backends)}",
                        provider_hints=sorted(set(backends)),
                    ))
                continue

            if suffix == ".tfvars" or filename.endswith(".tfvars.json"):
                inventory.assets.append(InfraAsset(
                    path=rel, kind=AssetKind.ENVIRONMENT_CONFIG, environment=env,
                    environment_confidence=confidence, detail="terraform variable values",
                    provider_hints=["terraform"],
                ))
                continue

            # ---- Dockerfiles ----------------------------------------------
            if filename == "Dockerfile" or filename.startswith("Dockerfile."):
                content, err = _read_text(full)
                base_images = _DOCKER_FROM.findall(content) if content else []
                inventory.assets.append(InfraAsset(
                    path=rel, kind=AssetKind.DOCKERFILE, environment=env,
                    environment_confidence=confidence,
                    detail=f"base image(s): {', '.join(base_images)}" if base_images else "dockerfile",
                    provider_hints=["container"],
                ))
                if err:
                    inventory.unreadable.append({"path": rel, "reason": err})
                continue

            if filename in ("docker-compose.yml", "docker-compose.yaml", "compose.yaml",
                             "compose.yml"):
                inventory.assets.append(InfraAsset(
                    path=rel, kind=AssetKind.DOCKER_COMPOSE, environment=env,
                    environment_confidence=confidence, detail="docker compose stack",
                    provider_hints=["container"],
                ))
                continue

            # ---- Cloud / serverless config --------------------------------
            if filename in ("serverless.yml", "serverless.yaml", "cdk.json", "samconfig.toml",
                             "pulumi.yaml", "Pulumi.yaml", "template.yaml", "template.yml"):
                inventory.assets.append(InfraAsset(
                    path=rel, kind=AssetKind.CLOUD_CONFIG, environment=env,
                    environment_confidence=confidence, detail=f"cloud config ({filename})",
                    provider_hints=["cloud"],
                ))
                continue

            if suffix in (".yml", ".yaml", ".json"):
                content, err = _read_text(full)
                if err:
                    inventory.unreadable.append({"path": rel, "reason": err})
                    continue

                # Kustomize
                if filename in ("kustomization.yaml", "kustomization.yml"):
                    inventory.assets.append(InfraAsset(
                        path=rel, kind=AssetKind.KUSTOMIZATION, environment=env,
                        environment_confidence=confidence, detail="kustomize overlay/base",
                        provider_hints=["kubernetes", "kustomize"],
                    ))
                    continue

                # GitOps (ArgoCD/Flux) - checked before generic k8s, since
                # an Application/Kustomization CR is *also* valid k8s YAML;
                # the GitOps classification is the more specific, more
                # useful one.
                if _GITOPS_MARKERS.search(content):
                    inventory.assets.append(InfraAsset(
                        path=rel, kind=AssetKind.GITOPS_CONFIG, environment=env,
                        environment_confidence=confidence, detail="GitOps (ArgoCD/Flux) config",
                        provider_hints=["gitops", "kubernetes"],
                    ))
                    continue

                # CI/CD workflows that actually touch infrastructure
                normalized_dir = str(current.relative_to(root)).replace(os.sep, "/")
                in_ci_dir = (".github/workflows" in normalized_dir
                              or normalized_dir.startswith(".gitlab")
                              or normalized_dir.startswith(".circleci"))
                if in_ci_dir or filename in (".gitlab-ci.yml", "azure-pipelines.yml"):
                    if _CICD_INFRA_TOKENS.search(content):
                        tokens = sorted({t.strip().lower()
                                          for t in _CICD_INFRA_TOKENS.findall(content)})
                        inventory.assets.append(InfraAsset(
                            path=rel, kind=AssetKind.CICD_INFRA_REFERENCE, environment=env,
                            environment_confidence=confidence,
                            detail=f"CI/CD references infra tooling: {', '.join(tokens)}",
                            provider_hints=["cicd"],
                        ))
                    continue

                # Helm chart templates are covered by the HELM_CHART asset;
                # cataloguing every template file separately would double
                # count (and templates aren't valid standalone k8s YAML).
                if any(str(current).startswith(str(chart_dir))
                        for chart_dir in seen_helm_chart_dirs):
                    continue

                if _looks_like_kubernetes(content):
                    kinds = sorted(set(_K8S_KIND.findall(content)))
                    inventory.assets.append(InfraAsset(
                        path=rel, kind=AssetKind.KUBERNETES_MANIFEST, environment=env,
                        environment_confidence=confidence,
                        detail=f"kind(s): {', '.join(kinds)}" if kinds else "kubernetes manifest",
                        provider_hints=_k8s_provider_hints(content),
                    ))
                continue

            if filename == ".env" or filename.startswith(".env."):
                inventory.assets.append(InfraAsset(
                    path=rel, kind=AssetKind.ENVIRONMENT_CONFIG, environment=env,
                    environment_confidence=confidence,
                    detail="environment variable file (scan with the secret scanner)",
                    provider_hints=["env"],
                ))

    # ---- Terraform roots vs modules -------------------------------------
    # A .tf directory is a MODULE if any ancestor within the repo also has
    # .tf files or it sits under a directory literally named "modules";
    # otherwise it's a root. This matters because a module has no backend
    # of its own and is never planned/applied directly.
    for tf_dir in sorted(terraform_dirs):
        rel = str(tf_dir.relative_to(root)) or "."
        env, confidence = infer_environment(rel)
        normalized = rel.replace(os.sep, "/")
        parent_has_tf = any(other != tf_dir and tf_dir.is_relative_to(other)
                             for other in terraform_dirs)
        is_module = parent_has_tf or "/modules/" in f"/{normalized}/" or normalized.endswith("/modules")
        inventory.assets.append(InfraAsset(
            path=rel,
            kind=AssetKind.TERRAFORM_MODULE if is_module else AssetKind.TERRAFORM_ROOT,
            environment=env, environment_confidence=confidence,
            detail=f"{len(terraform_dirs[tf_dir])} .tf file(s): "
                   f"{', '.join(sorted(terraform_dirs[tf_dir])[:5])}",
            provider_hints=sorted({"terraform", *terraform_provider_hints.get(tf_dir, set())}),
        ))

    inventory.assets.sort(key=lambda a: (a.kind.value, a.path))
    return inventory
