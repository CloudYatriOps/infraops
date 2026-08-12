"""Pipeline discovery (Phase 6 Part 2).

Discovers GitHub Actions workflows by reading `.github/workflows/*.yml`
(and `.yaml`) with `yaml.safe_load` only - never `yaml.load`, never
`eval`/`exec`, and the parsed content is never interpolated into a shell
command anywhere in this module (Part 20's threat model: "repository
workflows are untrusted configuration"). A workflow file is real,
attacker-influenceable input (anyone who can open a PR can add one), so a
malformed or adversarial file degrades to `parse_error` on that one file
rather than crashing discovery or being silently skipped as "no
workflows."
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import JobKind, PipelineModel, WorkflowDefinition, WorkflowJob

_BUILD_HINTS = ("build", "compile", "package", "docker build", "image")
_TEST_HINTS = ("test", "pytest", "jest", "unittest", "coverage")
_SECURITY_HINTS = ("security", "scan", "bandit", "semgrep", "checkov", "gitleaks", "trivy",
                    "codeql", "audit", "sast", "dependency-check")
_ARTIFACT_HINTS = ("artifact", "release", "publish", "upload", "sbom", "helm package")
_DEPLOY_HINTS = ("deploy", "rollout", "kubectl apply", "helm upgrade", "terraform apply",
                  "release-to")
_APPROVAL_HINTS = ("approve", "approval")
_ROLLBACK_HINTS = ("rollback", "revert", "undo")
_LINT_HINTS = ("lint", "flake8", "eslint", "format-check")


def _classify_job(name: str, step_texts: list[str]) -> JobKind:
    """Classified from names/step text only - a heuristic (documented as
    one), not a claim of perfect classification. Order matters: a job that
    both tests and deploys (uncommon but real) is classified DEPLOY first
    because that is the higher-consequence category to flag correctly."""
    haystack = " ".join([name.lower(), *["".join(t.lower()) for t in step_texts]])
    if any(h in haystack for h in _ROLLBACK_HINTS):
        return JobKind.ROLLBACK
    if any(h in haystack for h in _APPROVAL_HINTS):
        return JobKind.APPROVAL
    if any(h in haystack for h in _DEPLOY_HINTS):
        return JobKind.DEPLOY
    if any(h in haystack for h in _SECURITY_HINTS):
        return JobKind.SECURITY
    if any(h in haystack for h in _ARTIFACT_HINTS):
        return JobKind.ARTIFACT
    if any(h in haystack for h in _TEST_HINTS):
        return JobKind.TEST
    if any(h in haystack for h in _LINT_HINTS):
        return JobKind.LINT
    if any(h in haystack for h in _BUILD_HINTS):
        return JobKind.BUILD
    return JobKind.UNKNOWN


def _step_texts(step: Any) -> str:
    if not isinstance(step, dict):
        return ""
    parts = [str(step.get("name", "")), str(step.get("run", "")), str(step.get("uses", ""))]
    return " ".join(parts)


def _parse_workflow(path: Path, relative: str) -> WorkflowDefinition:
    try:
        raw = path.read_text()
    except OSError as e:
        return WorkflowDefinition(path=relative, name=relative, parse_error=f"could not read: {e}")
    try:
        doc = yaml.safe_load(raw)  # safe_load only - never yaml.load/eval/exec on repo content
    except yaml.YAMLError as e:
        return WorkflowDefinition(path=relative, name=relative,
                                   parse_error=f"YAML parse failed: {type(e).__name__}: "
                                               f"{str(e)[:200]}")
    if not isinstance(doc, dict):
        return WorkflowDefinition(path=relative, name=relative,
                                   parse_error="workflow file did not parse to a mapping")

    name = str(doc.get("name") or relative)
    on = doc.get(True, doc.get("on"))  # PyYAML parses bare `on:` key as boolean True in YAML 1.1
    if isinstance(on, str):
        triggers = [on]
    elif isinstance(on, list):
        triggers = [str(t) for t in on]
    elif isinstance(on, dict):
        triggers = [str(k) for k in on.keys()]
    else:
        triggers = []

    jobs: list[WorkflowJob] = []
    raw_jobs = doc.get("jobs")
    if isinstance(raw_jobs, dict):
        for job_id, job_def in raw_jobs.items():
            if not isinstance(job_def, dict):
                continue
            steps = job_def.get("steps") or []
            step_texts = [_step_texts(s) for s in steps if isinstance(s, dict)]
            step_names = [str(s.get("name") or s.get("uses") or s.get("run", "")[:60])
                          for s in steps if isinstance(s, dict)]
            needs = job_def.get("needs") or []
            needs = [needs] if isinstance(needs, str) else list(needs)
            env = job_def.get("environment")
            env_name = env if isinstance(env, str) else (env.get("name") if isinstance(env, dict)
                                                           else None)
            jobs.append(WorkflowJob(
                name=str(job_id), kind=_classify_job(str(job_id), step_texts),
                steps=step_names, needs=needs, environment=env_name,
            ))

    return WorkflowDefinition(path=relative, name=name, triggers=triggers, jobs=jobs)


def discover_pipeline(project_root: str) -> PipelineModel:
    """Real, in-process discovery - no network, no shell, works regardless
    of whether the live GitHub Actions API is reachable."""
    root = Path(project_root)
    workflow_dir = root / ".github" / "workflows"
    workflows: list[WorkflowDefinition] = []
    if workflow_dir.is_dir():
        for entry in sorted(workflow_dir.iterdir()):
            if entry.suffix.lower() not in (".yml", ".yaml") or not entry.is_file():
                continue
            relative = str(entry.relative_to(root))
            workflows.append(_parse_workflow(entry, relative))
    return PipelineModel(workflows=workflows)
