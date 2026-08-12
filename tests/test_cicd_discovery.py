"""Pipeline discovery (Phase 6 Part 2) - real, in-process YAML parsing of
`.github/workflows/*.yml`, no network."""
from __future__ import annotations

import textwrap
from pathlib import Path

from aep.cicd.discovery import discover_pipeline
from aep.cicd.models import JobKind


def test_discovers_no_workflows_when_none_exist(tmp_path: Path):
    pipeline = discover_pipeline(str(tmp_path))
    assert pipeline.workflows == []
    assert not pipeline.has_build and not pipeline.has_deploy


def test_classifies_build_test_security_deploy_jobs(tmp_path: Path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(textwrap.dedent("""\
        name: CI
        on: [push]
        jobs:
          build:
            steps:
              - run: docker build -t app .
          test:
            needs: [build]
            steps:
              - run: pytest -q
          security:
            steps:
              - run: bandit -r .
          deploy:
            needs: [test, security]
            environment: production
            steps:
              - run: kubectl apply -f manifest.yaml
    """))
    pipeline = discover_pipeline(str(tmp_path))
    assert len(pipeline.workflows) == 1
    workflow = pipeline.workflows[0]
    kinds = {j.name: j.kind for j in workflow.jobs}
    assert kinds["build"] == JobKind.BUILD
    assert kinds["test"] == JobKind.TEST
    assert kinds["security"] == JobKind.SECURITY
    assert kinds["deploy"] == JobKind.DEPLOY
    assert pipeline.has_build and pipeline.has_test and pipeline.has_security and pipeline.has_deploy
    assert workflow.has_approval_gate  # `environment: production` on the deploy job
    assert pipeline.environments == ["production"]


def test_detects_rollback_mechanism(tmp_path: Path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "deploy.yml").write_text(textwrap.dedent("""\
        name: Deploy
        on: [workflow_dispatch]
        jobs:
          rollback:
            steps:
              - name: Rollback on failure
                run: kubectl rollout undo deployment/app
    """))
    pipeline = discover_pipeline(str(tmp_path))
    assert pipeline.has_rollback_mechanism


def test_malformed_workflow_reports_parse_error_not_silently_dropped(tmp_path: Path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "broken.yml").write_text("name: [unterminated\n  jobs: {")
    pipeline = discover_pipeline(str(tmp_path))
    assert len(pipeline.workflows) == 1
    assert pipeline.workflows[0].parse_error is not None


def test_non_mapping_workflow_body_reports_parse_error(tmp_path: Path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "list.yml").write_text("- just\n- a\n- list\n")
    pipeline = discover_pipeline(str(tmp_path))
    assert pipeline.workflows[0].parse_error is not None
