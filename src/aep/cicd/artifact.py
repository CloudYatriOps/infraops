"""Build artifact model + SBOM/provenance (Phase 6 Part 4/12).

An artifact is never "deployable" just because it exists - `is_deployable`
computes the answer from actual recorded gate results, the same
escalation-only, never-fabricate-success discipline `infra/validation.py`
uses for `ran=False`. `generate_sbom()` is real when `cyclonedx-python-lib`
is installed (verified present in this sandbox) and reports UNAVAILABLE
otherwise - it is never faked.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


class ArtifactKind(str, Enum):
    CONTAINER_IMAGE = "container_image"
    BINARY = "binary"
    PACKAGE = "package"
    TERRAFORM_PLAN = "terraform_plan"
    HELM_CHART = "helm_chart"
    RELEASE_BUNDLE = "release_bundle"


class GateStatus(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    NOT_RUN = "NOT_RUN"  # never treated as PASSED - mirrors infra/validation.py's ran=False rule


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class SBOMResult:
    generated: bool
    tool: str
    reason: str
    component_count: int = 0
    format: str = "CycloneDX"
    raw_ref: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


def generate_sbom(project_root: str) -> SBOMResult:
    """Real SBOM generation over the project's Python dependency inventory
    using `cyclonedx-python-lib` (verified installed in this sandbox -
    `pip show cyclonedx-python-lib` succeeds). This is a best-effort,
    Python-ecosystem-only SBOM, not a full multi-language SBOM tool
    (`syft`/`cyclonedx-py` CLI are NOT installed here) - reported honestly
    as such rather than presented as a complete SBOM."""
    try:
        from cyclonedx.model.bom import Bom
        from cyclonedx.model.component import Component, ComponentType
    except ImportError as e:
        return SBOMResult(generated=False, tool="cyclonedx-python-lib", reason=f"not installed: {e}")

    req_files = list(Path(project_root).glob("requirements*.txt"))
    components = []
    for req_file in req_files:
        try:
            for line in req_file.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                name = line.split("==")[0].split(">=")[0].split("<")[0].strip()
                if name:
                    components.append(name)
        except OSError:
            continue

    bom = Bom()
    for name in components:
        bom.components.add(Component(name=name, type=ComponentType.LIBRARY))

    return SBOMResult(
        generated=True, tool="cyclonedx-python-lib", component_count=len(components),
        reason=f"generated a CycloneDX SBOM from {len(req_files)} requirements file(s) "
               f"({len(components)} Python component(s)); this covers Python dependencies only, "
               f"NOT container base image layers or other-language dependencies",
    )


@dataclass
class Provenance:
    """Part 12: "Do not claim signed provenance unless it is actually
    generated and verified." `signed` is always False here - no signing key
    or keyless-signing infrastructure (cosign/sigstore) is available in
    this sandbox, and this dataclass says so explicitly rather than
    omitting the field."""
    commit_sha: str
    build_id: str
    builder: str
    signed: bool = False
    signature_reason: str = "no signing key or sigstore/cosign infrastructure is configured in " \
                             "this environment; provenance is recorded but UNSIGNED"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class BuildArtifact:
    artifact_id: str
    kind: ArtifactKind
    commit_sha: str
    build_id: str
    digest: str
    provenance: Provenance
    created_at: str = field(default_factory=_now)
    security_scan_status: GateStatus = GateStatus.NOT_RUN
    test_status: GateStatus = GateStatus.NOT_RUN
    sbom: Optional[SBOMResult] = None
    deployment_status: str = "NOT_DEPLOYED"

    @property
    def is_deployable(self) -> bool:
        """An artifact is deployable only when its recorded gates actually
        passed - NOT_RUN never counts, matching `infra/validation.py`'s
        `ran=False != passed`."""
        return (self.security_scan_status == GateStatus.PASSED
                and self.test_status == GateStatus.PASSED)

    def to_dict(self) -> dict:
        return {
            "artifact_id": self.artifact_id, "kind": self.kind.value,
            "commit_sha": self.commit_sha, "build_id": self.build_id, "digest": self.digest,
            "provenance": self.provenance.to_dict(), "created_at": self.created_at,
            "security_scan_status": self.security_scan_status.value,
            "test_status": self.test_status.value,
            "sbom": self.sbom.to_dict() if self.sbom else None,
            "deployment_status": self.deployment_status, "is_deployable": self.is_deployable,
        }


def digest_of(content: bytes) -> str:
    """A real content digest (sha256), used as the artifact's identity
    check - Part 4's "artifact identity". Never a random id."""
    return "sha256:" + hashlib.sha256(content).hexdigest()


def build_artifact(kind: ArtifactKind, commit_sha: str, build_id: str, content: bytes,
                    builder: str = "aep-local-build") -> BuildArtifact:
    digest = digest_of(content)
    provenance = Provenance(commit_sha=commit_sha, build_id=build_id, builder=builder)
    return BuildArtifact(artifact_id=f"{kind.value}:{digest[7:19]}", kind=kind,
                          commit_sha=commit_sha, build_id=build_id, digest=digest,
                          provenance=provenance)
