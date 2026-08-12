"""Discovers what's actually in a project: file inventory, rough language
detection, and whether a CI config is present. Deterministic - no model
call needed for plain inventory, keeping recon fast/cheap and not
dependent on a provider being healthy."""
from __future__ import annotations

from datetime import datetime, timezone

from ..models import Evidence, RiskLevel, Task, TaskResult
from .base import Agent, AgentContext

_LANGUAGE_BY_EXT = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".go": "go", ".tf": "terraform", ".yaml": "yaml", ".yml": "yaml",
}
_CI_MARKERS = (".github/workflows", ".gitlab-ci.yml", "Jenkinsfile", ".circleci")


class ReconAgent:
    name = "recon"
    required_capabilities = {"filesystem.list", "filesystem.read"}

    def run(self, task: Task, ctx: AgentContext) -> TaskResult:
        project_root = task.payload["project_root"]
        listing = ctx.tools.call("filesystem.list", task_id=task.id, project_root=project_root, path=".")
        entries = listing["entries"]

        languages: dict[str, int] = {}
        for entry in entries:
            for ext, lang in _LANGUAGE_BY_EXT.items():
                if entry.endswith(ext):
                    languages[lang] = languages.get(lang, 0) + 1

        has_ci = any(any(marker in e for marker in _CI_MARKERS) for e in entries)

        summary = (f"{len(entries)} files; languages={languages}; "
                   f"ci_config_present={has_ci}")
        evidence = Evidence(
            source="recon", captured_at=datetime.now(timezone.utc).isoformat(),
            exit_code=0, summary=summary,
        )
        return TaskResult(
            success=True,
            evidence=[evidence],
            artifacts=[],
            message=summary,
        )
