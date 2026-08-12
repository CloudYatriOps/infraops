"""`aep status --security-repo`/`aep security-status` (Phase 4 Part 11).

Follows test_cli_status.py's exact discipline: uses a small, temporary
roadmap fixture rather than this repo's real config/roadmap.yaml, for the
identical self-reference reason documented there (this file IS one of
config/roadmap.yaml's gating tests for a Phase 4 capability). The security
scan itself runs for real (gitleaks/semgrep/checkov against a small real
fixture) - only the ROADMAP is faked, not the scanners.
"""
from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path

import pytest

from aep.cli import _build_security_posture, _build_status_payload
from aep.security.discovery import scanner_for_category
from aep.security.models import ScannerAvailability


def _probe(args, cwd=None, timeout=10):
    try:
        proc = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return {"ok": proc.returncode == 0}
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return {"ok": False}


_gitleaks_available = (scanner_for_category("secret").check_availability(_probe).status
                        == ScannerAvailability.AVAILABLE)


class _Args:
    def __init__(self, project=None, security_repo=None, live_github_verified=False,
                 live_cve_feed_unverified=False, db="aep_state_test.db"):
        self.project = project
        self.security_repo = security_repo
        self.live_github_verified = live_github_verified
        self.live_cve_feed_unverified = live_cve_feed_unverified
        self.db = db
        self.json = True


def _small_roadmap(tmp_path: Path) -> str:
    (tmp_path / "test_a.py").write_text("def test_ok():\n    assert True\n")
    roadmap_path = tmp_path / "roadmap.yaml"
    roadmap_path.write_text(textwrap.dedent("""\
        version: 1
        phases:
          - id: 1
            name: "P1"
            description: "d"
            capabilities:
              - id: cap.a
                description: "done"
                test_paths: ["test_a.py"]
        """))
    return str(roadmap_path)


@pytest.mark.skipif(not _gitleaks_available, reason="gitleaks not installed in this environment")
def test_status_payload_omits_security_posture_by_default(tmp_path):
    roadmap_path = _small_roadmap(tmp_path)
    payload = _build_status_payload(_Args(), repo_root=str(tmp_path), roadmap_path=roadmap_path)
    assert "security_posture" not in payload  # opt-in only - default `aep status` stays fast


@pytest.mark.skipif(not _gitleaks_available, reason="gitleaks not installed in this environment")
def test_status_payload_includes_security_posture_when_requested(tmp_path):
    target_repo = tmp_path / "target"
    target_repo.mkdir()
    (target_repo / "config.py").write_text('AWS_ACCESS_KEY_ID = "AKIAZZZZ9999QQQQ1111"\n')

    roadmap_path = _small_roadmap(tmp_path)
    payload = _build_status_payload(_Args(security_repo=str(target_repo)), repo_root=str(tmp_path),
                                     roadmap_path=roadmap_path)
    assert "security_posture" in payload
    posture = payload["security_posture"]
    assert "categories" in posture
    assert "readiness" in posture
    secrets = next(c for c in posture["categories"] if c["name"] == "Secrets")
    assert secrets["status"] == "1 HIGH"


@pytest.mark.skipif(not _gitleaks_available, reason="gitleaks not installed in this environment")
def test_build_security_posture_is_json_serializable(tmp_path):
    import json

    target_repo = tmp_path / "target2"
    target_repo.mkdir()
    (target_repo / "app.py").write_text("def add(a, b):\n    return a + b\n")
    posture = _build_security_posture(str(target_repo))
    assert json.dumps(posture)


# Deliberately NO test here calls `_build_status_payload()`/`_build_security_posture()`
# against the REAL repo roadmap/repo (see test_cli_status.py's docstring for why).
