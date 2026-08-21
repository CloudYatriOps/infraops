"""Deterministic project capability discovery.

Answers one question about an arbitrary repository: *what kind of project
is this, based on evidence actually present on disk?* - so the rest of the
platform can run only the analyzers that apply and honestly say why it
skipped the rest.

Two hard rules, both load-bearing:

1. **Evidence, never names.** A capability is claimed only when a real
   marker file/content pattern is found. The directory being called
   "terraform-infra" proves nothing and is never consulted. Every claimed
   capability carries the concrete evidence paths that produced it, so a
   wrong answer is debuggable rather than mysterious.
2. **Read-only.** This module opens files for reading and does nothing
   else - no writes, no subprocesses, no network. Scanning someone's
   repository must never modify it.

Infrastructure capabilities are derived from the EXISTING
`infra.discovery.discover_infrastructure()` inventory rather than a second
parallel detector - there is one infrastructure-detection implementation
in this codebase and this is a projection of it, not a rival.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from .infra.models import AssetKind


class Capability(str, Enum):
    """What a repository demonstrably contains. Multiple apply at once -
    a repo is very often APPLICATION + PYTHON + TERRAFORM + CI_CD."""

    APPLICATION = "APPLICATION"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    KUBERNETES = "KUBERNETES"
    HELM = "HELM"
    TERRAFORM = "TERRAFORM"
    CONTAINER = "CONTAINER"
    PYTHON = "PYTHON"
    NODE = "NODE"
    GO = "GO"
    JAVA = "JAVA"
    CI_CD = "CI_CD"
    GIT = "GIT"
    UNKNOWN = "UNKNOWN"


# Marker files that prove a language/ecosystem. Matched by exact filename
# at any depth (excluding vendored dirs) - never by directory name.
_LANGUAGE_MARKERS: dict[Capability, tuple[str, ...]] = {
    Capability.PYTHON: ("pyproject.toml", "requirements.txt", "setup.py",
                         "setup.cfg", "Pipfile", "poetry.lock"),
    Capability.NODE: ("package.json",),
    Capability.GO: ("go.mod",),
    Capability.JAVA: ("pom.xml", "build.gradle", "build.gradle.kts"),
}

# CI configuration. Directory-scoped entries are matched as path suffixes
# because the FILES inside them are what matter, not the folder's name.
_CI_FILE_MARKERS = (".gitlab-ci.yml", ".gitlab-ci.yaml", "azure-pipelines.yml",
                     "azure-pipelines.yaml", "Jenkinsfile", ".travis.yml",
                     "bitbucket-pipelines.yml")
_CI_DIR_MARKERS = (".github/workflows", ".circleci")

_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".terraform", "vendor",
              ".venv", "venv", ".pytest_cache", "dist", "build", ".mypy_cache",
              ".tox", ".gradle", "target"}

# Infra asset kind -> capability it proves.
_ASSET_CAPABILITY: dict[AssetKind, Capability] = {
    AssetKind.TERRAFORM_ROOT: Capability.TERRAFORM,
    AssetKind.TERRAFORM_MODULE: Capability.TERRAFORM,
    AssetKind.TERRAFORM_STATE_CONFIG: Capability.TERRAFORM,
    AssetKind.HELM_CHART: Capability.HELM,
    AssetKind.KUBERNETES_MANIFEST: Capability.KUBERNETES,
    AssetKind.KUSTOMIZATION: Capability.KUBERNETES,
    AssetKind.GITOPS_CONFIG: Capability.KUBERNETES,
    AssetKind.DOCKERFILE: Capability.CONTAINER,
    AssetKind.DOCKER_COMPOSE: Capability.CONTAINER,
    AssetKind.CICD_INFRA_REFERENCE: Capability.CI_CD,
}

# Capabilities that, present at all, mean the repo carries infrastructure.
_INFRA_IMPLYING = (Capability.TERRAFORM, Capability.HELM,
                    Capability.KUBERNETES, Capability.CONTAINER)

# Capabilities that mean there is application source to analyze.
_APP_IMPLYING = (Capability.PYTHON, Capability.NODE, Capability.GO,
                  Capability.JAVA)


@dataclass
class ProjectProfile:
    """What a repository is, with the evidence for each claim."""

    root: str
    capabilities: set[Capability] = field(default_factory=set)
    # capability -> the concrete paths that proved it (posix-style,
    # relative to root, capped so a huge repo doesn't produce a huge blob)
    evidence: dict[Capability, list[str]] = field(default_factory=dict)
    unreadable: list[dict] = field(default_factory=list)

    def has(self, capability: Capability) -> bool:
        return capability in self.capabilities

    def sorted_capabilities(self) -> list[str]:
        return sorted(c.value for c in self.capabilities)

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "capabilities": self.sorted_capabilities(),
            "evidence": {c.value: sorted(paths)
                          for c, paths in sorted(self.evidence.items(),
                                                  key=lambda kv: kv[0].value)},
            "unreadable": self.unreadable,
        }


_MAX_EVIDENCE_PER_CAPABILITY = 10


def _record(profile: ProjectProfile, capability: Capability, path: str) -> None:
    profile.capabilities.add(capability)
    paths = profile.evidence.setdefault(capability, [])
    if path not in paths and len(paths) < _MAX_EVIDENCE_PER_CAPABILITY:
        paths.append(path)


def detect_project(project_root: str) -> ProjectProfile:
    """Inspect `project_root` and return what it demonstrably is.

    Read-only. Never raises for an unreadable file - those are recorded in
    `profile.unreadable` so a permission problem is visible rather than
    silently narrowing the result.
    """
    root = Path(project_root).resolve()
    profile = ProjectProfile(root=str(root))

    if not root.is_dir():
        profile.capabilities.add(Capability.UNKNOWN)
        profile.unreadable.append({"path": str(root), "reason": "not a directory"})
        return profile

    if (root / ".git").exists():
        _record(profile, Capability.GIT, ".git")

    # ---- language / ecosystem markers -----------------------------------
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        current = Path(dirpath)
        rel_dir = current.relative_to(root).as_posix()

        for capability, markers in _LANGUAGE_MARKERS.items():
            for marker in markers:
                if marker in filenames:
                    rel = (current / marker).relative_to(root).as_posix()
                    _record(profile, capability, rel)

        for marker in _CI_FILE_MARKERS:
            if marker in filenames:
                _record(profile, Capability.CI_CD,
                        (current / marker).relative_to(root).as_posix())

        for ci_dir in _CI_DIR_MARKERS:
            # Only counts if the directory actually holds files.
            if rel_dir == ci_dir or rel_dir.endswith("/" + ci_dir):
                if filenames:
                    _record(profile, Capability.CI_CD, rel_dir)

    # ---- infrastructure, via the EXISTING inventory ----------------------
    try:
        from .infra.discovery import discover_infrastructure

        inventory = discover_infrastructure(str(root))
    except Exception as exc:  # noqa: BLE001 - degrade honestly, never crash a scan
        profile.unreadable.append(
            {"path": str(root), "reason": f"infrastructure discovery failed: {exc}"})
        inventory = None

    if inventory is not None:
        for asset in inventory.assets:
            capability = _ASSET_CAPABILITY.get(asset.kind)
            if capability is not None:
                _record(profile, capability, asset.path)
        profile.unreadable.extend(inventory.unreadable)

    # ---- derived roll-ups ------------------------------------------------
    for capability in _INFRA_IMPLYING:
        if profile.has(capability):
            profile.capabilities.add(Capability.INFRASTRUCTURE)
            profile.evidence.setdefault(Capability.INFRASTRUCTURE, []).extend(
                p for p in profile.evidence.get(capability, [])
                if p not in profile.evidence.get(Capability.INFRASTRUCTURE, []))
            break

    for capability in _APP_IMPLYING:
        if profile.has(capability):
            profile.capabilities.add(Capability.APPLICATION)
            profile.evidence.setdefault(Capability.APPLICATION, []).extend(
                p for p in profile.evidence.get(capability, [])
                if p not in profile.evidence.get(Capability.APPLICATION, []))
            break

    # GIT alone is not a project type - a bare repo with nothing else in it
    # is genuinely UNKNOWN, and saying so is more useful than implying we
    # recognized something.
    meaningful = profile.capabilities - {Capability.GIT}
    if not meaningful:
        profile.capabilities.add(Capability.UNKNOWN)

    # Cap evidence lists that the roll-ups may have grown past the limit.
    for capability, paths in profile.evidence.items():
        del paths[_MAX_EVIDENCE_PER_CAPABILITY:]

    return profile
