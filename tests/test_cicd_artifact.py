"""Build artifact model + SBOM (Phase 6 Part 4/12)."""
from __future__ import annotations

from pathlib import Path

from aep.cicd.artifact import ArtifactKind, GateStatus, build_artifact, generate_sbom


def test_artifact_identity_is_a_real_content_digest():
    a = build_artifact(ArtifactKind.PACKAGE, commit_sha="abc123", build_id="build-1",
                        content=b"hello world")
    b = build_artifact(ArtifactKind.PACKAGE, commit_sha="abc123", build_id="build-1",
                        content=b"hello world")
    c = build_artifact(ArtifactKind.PACKAGE, commit_sha="abc123", build_id="build-1",
                        content=b"different content")
    assert a.digest == b.digest  # same content -> same digest, never random
    assert a.digest != c.digest
    assert a.digest.startswith("sha256:")


def test_artifact_is_never_deployable_without_both_required_gates():
    a = build_artifact(ArtifactKind.CONTAINER_IMAGE, "sha", "b1", b"x")
    assert not a.is_deployable  # NOT_RUN by default - never treated as passing
    a.test_status = GateStatus.PASSED
    assert not a.is_deployable  # security still NOT_RUN
    a.security_scan_status = GateStatus.PASSED
    assert a.is_deployable


def test_provenance_is_never_claimed_as_signed():
    a = build_artifact(ArtifactKind.HELM_CHART, "sha", "b1", b"chart")
    assert a.provenance.signed is False
    assert "unsigned" in a.provenance.signature_reason.lower() \
        or "UNSIGNED" in a.provenance.signature_reason


def test_sbom_generation_is_real_when_cyclonedx_installed(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\npyyaml>=6.0\n")
    result = generate_sbom(str(tmp_path))
    # cyclonedx-python-lib is verified installed in this sandbox (Phase 6
    # investigation) - if a future environment lacks it, `generated` must
    # be False with a real reason, never fabricated components.
    if result.generated:
        assert result.component_count == 2
    else:
        assert "not installed" in result.reason
