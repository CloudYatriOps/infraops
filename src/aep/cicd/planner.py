"""CI/CD & deployment task chains (Phase 6). Same discipline as
`infra/planner.py`/`dependency/planner.py`/`security/planner.py`: builds
`Task` objects and submits them through the EXISTING
`Orchestrator.submit_graph` - nothing here is a new orchestration
primitive.
"""
from __future__ import annotations

import uuid
from typing import Optional

from ..models import Task


def _new_id() -> str:
    return str(uuid.uuid4())


def plan_ci_inspection(orchestrator, project_id: str, project_root: str) -> list[str]:
    """Static, no-network pipeline discovery only."""
    task = Task(id=_new_id(), type="ci_inspect", project_id=project_id,
                owner_agent="ci_intelligence_agent",
                payload={"mode": "inspect", "project_root": project_root})
    return orchestrator.submit_graph(project_id, [task])


def plan_deployment(orchestrator, project_id: str, environment: str, commit_sha: str,
                     artifact_id: str, gates: dict, infra_required: bool = False,
                     dependencies: Optional[list[str]] = None) -> list[str]:
    """A single `deployment_agent` task carrying pre-computed release-gate
    inputs. Gates are computed by the caller from real scan/test/CI output
    (see `release_gates.evaluate_release_gates`'s docstring) - this planner
    never invents them."""
    task = Task(id=_new_id(), type="deploy", project_id=project_id,
                owner_agent="deployment_agent", dependencies=dependencies or [],
                payload={"mode": "deploy", "environment": environment, "commit_sha": commit_sha,
                         "artifact_id": artifact_id, "gates": gates,
                         "infra_required": infra_required})
    return orchestrator.submit_graph(project_id, [task])
