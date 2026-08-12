"""Deterministic secret scanner - the first real slice of Phase 3.

Runs before and after CodeAgent's commit. A detected high-confidence secret
is a hard failure (FailureClass.SECURITY -> never auto-retried, see
failure.py), not a WARN, matching ARCHITECTURE.md §11: a secret blocks the
task and surfaces as HUMAN_REQUIRED rather than being silently stripped.
"""
from __future__ import annotations

from datetime import datetime, timezone

from ..models import Evidence, FailureClass, Task, TaskResult
from ..redaction import find_secrets
from .base import Agent, AgentContext


class SecurityScanAgent:
    name = "security_scan_agent"
    required_capabilities = {"filesystem.list", "filesystem.read"}

    def run(self, task: Task, ctx: AgentContext) -> TaskResult:
        project_root = task.payload["project_root"]
        paths = task.payload.get("paths")
        if paths is None:
            listing = ctx.tools.call("filesystem.list", task_id=task.id,
                                      project_root=project_root, path=".")
            paths = [p for p in listing["entries"] if not p.endswith("/")]

        findings: list[str] = []
        for rel_path in paths:
            read = ctx.tools.call("filesystem.read", task_id=task.id,
                                   project_root=project_root, path=rel_path)
            if not read["ok"]:
                continue
            matches = find_secrets(read["content"], high_confidence_only=True)
            for m in matches:
                findings.append(f"{rel_path}: {m.kind} ({m.snippet})")

        evidence = Evidence(
            source="secret-scanner", captured_at=datetime.now(timezone.utc).isoformat(),
            exit_code=0 if not findings else 1,
            summary=f"{len(findings)} finding(s): " + "; ".join(findings) if findings else "clean",
        )
        if findings:
            return TaskResult(
                success=False,
                evidence=[evidence],
                failure_class=FailureClass.SECURITY,
                message=f"blocked: {len(findings)} likely secret(s) detected",
            )
        return TaskResult(success=True, evidence=[evidence], message="no secrets detected")
