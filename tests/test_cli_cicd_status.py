"""`aep status --cicd-repo`/`aep ci-status`/`aep deploy-status` (Phase 6
Part 17). Same "never self-reference the real roadmap" discipline as
tests/test_cli_status.py."""
from __future__ import annotations

import textwrap
from pathlib import Path

from aep.bootstrap import build_orchestrator
from aep.cicd.planner import plan_deployment
from aep.cli import _build_cicd_payload, _build_status_payload, cmd_deploy_status
from aep.models import ProjectConfig


class _Args:
    def __init__(self, cicd_repo=None):
        self.project = None
        self.live_github_verified = False
        self.live_cve_feed_unverified = False
        self.db = "aep_state_test.db"
        self.json = True
        self.cicd_repo = cicd_repo


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


def test_build_cicd_payload_is_json_serializable(tmp_path: Path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("name: CI\non: [push]\njobs:\n  test:\n    steps:\n"
                                       "      - run: pytest\n")
    payload = _build_cicd_payload(str(tmp_path))
    import json
    json.dumps(payload)  # must not raise
    assert payload["pipeline"]["workflow_count"] == 1


def test_status_payload_includes_cicd_when_requested(tmp_path: Path):
    roadmap_path = _small_roadmap(tmp_path)
    payload = _build_status_payload(_Args(cicd_repo=str(tmp_path)), repo_root=str(tmp_path),
                                     roadmap_path=roadmap_path)
    assert "cicd" in payload


def test_status_payload_omits_cicd_when_not_requested(tmp_path: Path):
    roadmap_path = _small_roadmap(tmp_path)
    payload = _build_status_payload(_Args(), repo_root=str(tmp_path), roadmap_path=roadmap_path)
    assert "cicd" not in payload


def test_deploy_status_reports_real_recorded_deployments(tmp_path: Path, policy_path, capsys,
                                                            monkeypatch):
    # `cmd_deploy_status` below reads through `db/factory.py` too, so it
    # must be told explicitly to use the same sqlite backend the
    # orchestrator above was built with (project id "p1" is not a valid
    # UUID, so it cannot go through the Postgres facade).
    monkeypatch.setenv("AEP_DB_BACKEND", "sqlite")
    project = ProjectConfig(id="p1", name="p1", repo_path=str(tmp_path), policy_path=policy_path)
    db_path = str(tmp_path / "s.db")
    orch = build_orchestrator(db_path, project, deployment_state_dir=str(tmp_path / "deploy"), db_backend="sqlite")
    gates = dict(tests_passed=True, cve_scan_clean=True, secrets_clean=True, sast_clean=True,
                 iac_clean=True, ci_pipeline_green=True, artifact_built=True,
                 artifact_provenance_recorded=True, required_approvals_met=True,
                 environment_policy_satisfied=True)
    plan_deployment(orch, "p1", environment="development", commit_sha="abc123def456",
                     artifact_id="art1", gates=gates)
    orch.run_to_completion("p1")

    class _DeployArgs:
        project = "p1"
        db = db_path
        json = False

    cmd_deploy_status(_DeployArgs())
    out = capsys.readouterr().out
    assert "VERIFIED" in out
    assert "art1" in out


# Deliberately NO test here exercises `aep status`/`ci-status` against
# THIS repo's own real config/roadmap.yaml plus `--cicd-repo .` - the same
# self-reference hazard test_cli_status.py documents.
