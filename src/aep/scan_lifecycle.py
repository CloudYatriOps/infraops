"""Project Analysis Productization: persists `aep scan`'s results so the
UI can offer a real scan lifecycle (Scan Now / history / rerun / report)
instead of a one-shot CLI-only report.

Deliberately reuses existing structures rather than inventing a second
scanner or a second persistence model (see BUGFIX.md / handoff.md for the
review that led here):

  * A "scan run" IS a `Task` (`aep.models.Task`), `type="project_scan"`.
    `tasks.type` has no CHECK constraint, so this needed no migration.
    The task's REAL `TaskStatus` (PENDING/RUNNING/SUCCEEDED/FAILED) is
    never overloaded with product vocabulary - `analysis_state()` below
    derives the richer NEVER_SCANNED/QUEUED/SCANNING/COMPLETED/
    COMPLETED_WITH_FINDINGS/FAILED/CANCELLED label from it plus the
    finding count, keeping "task lifecycle" and "analysis state" as the
    genuinely distinct concepts the product spec calls for.
  * The full `ScanReport.to_dict()` is stored verbatim as ONE `Evidence`
    entry's `summary` on that task - full fidelity, no new table, and
    `aep scan`'s own report shape is the single source of truth for what
    a report looks like.
  * Each finding becomes its own `FindingRecord`, linked via `task_id` to
    the scan-run task - `findings.task_id` already existed and is
    nullable, so this needed no migration either. A NEW `FindingRecord`
    row is written on every scan run (never an UPDATE of a prior run's
    row): scan history must never be silently overwritten, so each run's
    findings are its own immutable record, and "Rerun" comparisons (see
    `compare_scan_runs`) are computed by diffing rows across runs, not by
    mutating a single row's status in place.
  * Scan start/completion are `Event` rows via the existing
    `EventLogger` - the same audit mechanism every other write in this
    API already uses - giving the Timeline for free with no new table.

The one genuinely new piece of schema is migration 0008's
`projects.archived_at`, for safe, non-cascading "Delete Project" - see
that migration file and BUG-0026 for why.

Read-only guarantee: `run_scan` calls the exact same
`aep.scan.scan_project()` the CLI's `aep scan` uses, and does nothing
else to the target repository - no write, no install, no commit.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

from .db.models import FindingRecord
from .db.postgres import ConnectionPool, PostgresFindingRepository
from .events import EventLogger
from .models import Evidence, Task, TaskStatus
from .scan import AnalyzerStatus, ScanReport, scan_project

SCAN_TASK_TYPE = "project_scan"
EVIDENCE_SOURCE = "aep.scan"

# aep.scan's analyzer display names -> the findings.category CHECK values
# (src/aep/migrations_sql/0001_initial_schema.sql) - the only mapping
# needed, since categories/severities otherwise already match verbatim.
_ANALYZER_TO_CATEGORY = {
    "Secrets": "secret",
    "SAST": "sast",
    "Dependencies": "dependency",
    "IaC": "iac",
    "Containers": "container",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _finding_to_dict(f: FindingRecord) -> dict:
    d = asdict(f)
    for key in ("discovered_at", "updated_at"):
        if d.get(key) is not None:
            d[key] = d[key].isoformat() if hasattr(d[key], "isoformat") else str(d[key])
    return d


def analysis_state(task: Optional[Task], finding_count: int = 0) -> str:
    """Maps a scan-run Task's real TaskStatus (+ finding count) to the
    product-level analysis state. Deliberately distinct from `Task.status`
    itself - "Analysis: COMPLETED_WITH_FINDINGS" and "Security: NOT_READY"
    describe different things and must never be conflated (see the
    product spec this module implements)."""
    if task is None:
        return "NEVER_SCANNED"
    if task.status in (TaskStatus.PENDING, TaskStatus.READY):
        return "QUEUED"
    if task.status == TaskStatus.RUNNING:
        return "SCANNING"
    if task.status == TaskStatus.FAILED:
        return "FAILED"
    if task.status in (TaskStatus.CANCELLED, TaskStatus.QUARANTINED):
        return "CANCELLED"
    if task.status == TaskStatus.SUCCEEDED:
        return "COMPLETED_WITH_FINDINGS" if finding_count > 0 else "COMPLETED"
    return "QUEUED"  # RETRY_SCHEDULED/BLOCKED_ON_APPROVAL: not reachable for this task type today


def _persist_findings(pool: ConnectionPool, project_id: str, task_id: str,
                       report: ScanReport) -> list[FindingRecord]:
    repo = PostgresFindingRepository(pool)
    saved = []
    for result in report.results:
        category = _ANALYZER_TO_CATEGORY.get(result.name)
        if category is None:
            continue  # an analyzer with no findings.category mapping never produces findings
        for finding in result.findings:
            record = FindingRecord(
                id=str(uuid.uuid4()),
                project_id=project_id,
                category=category,
                severity=getattr(finding.severity, "value", str(finding.severity)),
                resource=f"{finding.file}:{finding.line}" if finding.file else result.name,
                description=finding.description,
                task_id=task_id,
                evidence={"analyzer": result.name, "rule": finding.rule_id,
                          "file": finding.file, "line": finding.line},
            )
            repo.save(record)
            saved.append(record)
    return saved


def run_scan(pool: ConnectionPool, store, project_id: str, repo_path: str,
             triggered_by: str = "ui") -> dict:
    """Runs one real scan, persists it, and returns the same shape
    `list_scan_runs`/`get_scan_run` produce for it. Synchronous on
    purpose: `scan_project()` is a fast, local, read-only filesystem walk
    (not a long-running job like the roadmap test suite `/system/status`
    runs) - there is no real "long-running task infrastructure" to route
    through for something that completes in low single-digit seconds, and
    fabricating an async queue for it would be inventing complexity the
    actual engine's timing characteristics don't call for."""
    task = Task(id=str(uuid.uuid4()), type=SCAN_TASK_TYPE, project_id=project_id,
                status=TaskStatus.RUNNING, payload={"repo_path": repo_path, "triggered_by": triggered_by})
    store.save_task(task)
    events = EventLogger(store)
    events.log(actor=triggered_by, action="scan.started", project_id=project_id, task_id=task.id,
               details={"repo_path": repo_path})

    try:
        report = scan_project(repo_path)
    except Exception as exc:  # noqa: BLE001 - reported as a real FAILED run, never swallowed
        task.status = TaskStatus.FAILED
        task.evidence.append(Evidence(source=EVIDENCE_SOURCE, captured_at=_now_iso(),
                                       exit_code=1, summary=f"scan raised {type(exc).__name__}: {exc}"))
        store.save_task(task)
        events.log(actor=triggered_by, action="scan.failed", project_id=project_id, task_id=task.id,
                   details={"error": str(exc)})
        return {"task_id": task.id, "status": "FAILED", "analysis_state": "FAILED", "error": str(exc)}

    findings = _persist_findings(pool, project_id, task.id, report)
    report_dict = report.to_dict()
    any_fail = any(r.status == AnalyzerStatus.FAIL for r in report.results)
    task.evidence.append(Evidence(source=EVIDENCE_SOURCE, captured_at=_now_iso(),
                                   exit_code=1 if any_fail else 0, summary=json.dumps(report_dict)))
    task.status = TaskStatus.SUCCEEDED
    store.save_task(task)

    for result in report.results:
        events.log(actor=triggered_by, action=f"scan.{result.name.lower()}_completed",
                   project_id=project_id, task_id=task.id, details={"status": result.status.value})
    events.log(actor=triggered_by, action="scan.report_generated", project_id=project_id, task_id=task.id,
               details={"total_findings": report.total_findings})
    events.log(actor=triggered_by, action="scan.completed", project_id=project_id, task_id=task.id,
               details={"security_readiness": report.security_readiness()})

    return {
        "task_id": task.id, "status": "SUCCEEDED",
        "analysis_state": analysis_state(task, len(findings)),
        "report": report_dict, "finding_count": len(findings),
    }


def _scan_tasks_for_project(store, project_id: str) -> list[Task]:
    tasks = [t for t in store.list_tasks(project_id=project_id) if t.type == SCAN_TASK_TYPE]
    tasks.sort(key=lambda t: t.created_at or "", reverse=True)
    return tasks


def _report_from_task(task: Task) -> Optional[dict]:
    """The persisted report is the last `aep.scan` Evidence entry's
    summary (JSON) - the single source of truth, never reconstructed."""
    for e in reversed(task.evidence):
        if e.source == EVIDENCE_SOURCE:
            try:
                return json.loads(e.summary)
            except (ValueError, TypeError):
                return None
    return None


def _scan_summary(pool: ConnectionPool, task: Task) -> dict:
    findings = PostgresFindingRepository(pool).list(project_id=task.project_id)
    finding_count = sum(1 for f in findings if f.task_id == task.id)
    return {
        "scan_id": task.id, "status": task.status.value,
        "analysis_state": analysis_state(task, finding_count),
        "triggered_by": task.payload.get("triggered_by", "unknown"),
        "started_at": task.created_at, "completed_at": task.updated_at,
        "finding_count": finding_count,
    }


def list_scan_runs(pool: ConnectionPool, store, project_id: str) -> list[dict]:
    return [_scan_summary(pool, t) for t in _scan_tasks_for_project(store, project_id)]


def get_scan_run(pool: ConnectionPool, store, project_id: str, scan_id: str) -> Optional[dict]:
    task = store.get_task(scan_id)
    if task is None or task.project_id != project_id or task.type != SCAN_TASK_TYPE:
        return None
    all_findings = PostgresFindingRepository(pool).list(project_id=project_id)
    scan_findings = [f for f in all_findings if f.task_id == scan_id]
    summary = _scan_summary(pool, task)
    summary["report"] = _report_from_task(task)
    summary["findings"] = [_finding_to_dict(f) for f in scan_findings]
    # Timeline (product spec Part 9): the real Events already logged by
    # `run_scan` for this exact scan run, via the same EventLogger/
    # `events` table every other write in this API uses - no new table,
    # no fabricated per-second progress.
    events = store.query_events(project_id=project_id, task_id=scan_id)
    summary["timeline"] = [
        {"timestamp": e.timestamp, "action": e.action, "details": e.details}
        for e in events
    ]
    return summary


def latest_scan_run(pool: ConnectionPool, store, project_id: str) -> Optional[dict]:
    tasks = _scan_tasks_for_project(store, project_id)
    if not tasks:
        return None
    return get_scan_run(pool, store, project_id, tasks[0].id)


def compare_scan_runs(pool: ConnectionPool, store, project_id: str) -> Optional[dict]:
    """Minimum useful rerun comparison (product spec Part 10): which
    findings are unchanged, newly appeared, or no longer detected between
    the two most recent scan runs. A finding's identity for this
    comparison is (category, resource, description) - the same fields a
    human would use to recognize "the same issue" across two reports. A
    finding that disappears because a SCANNER FAILED (not because the
    issue was fixed) must never read as "resolved" - callers should check
    the newer run's analyzer status before trusting a "resolved" entry
    for that category (see docs/UI-GUIDE.md)."""
    tasks = _scan_tasks_for_project(store, project_id)
    if len(tasks) < 2:
        return None
    newer, older = tasks[0], tasks[1]
    all_findings = PostgresFindingRepository(pool).list(project_id=project_id)

    def _key(f):
        return f"{f.category}|{f.resource}|{f.description}"

    newer_keys = {_key(f) for f in all_findings if f.task_id == newer.id}
    older_keys = {_key(f) for f in all_findings if f.task_id == older.id}
    return {
        "previous_scan_id": older.id, "current_scan_id": newer.id,
        "previous_finding_count": len(older_keys), "current_finding_count": len(newer_keys),
        "unchanged": sorted(newer_keys & older_keys),
        "new_findings": sorted(newer_keys - older_keys),
        "resolved_findings": sorted(older_keys - newer_keys),
    }


def render_markdown_report(project_name: str, repo_path: str, scan_summary: dict) -> str:
    """Executive-readable report (product spec's REPORT section) -
    strictly derived from the persisted scan's own data, never invented
    prose. FACT/FINDING/SKIPPED/BLOCKED/RECOMMENDATION are visually
    distinct sections, never blended into one paragraph."""
    report = scan_summary.get("report") or {}
    analyzers = report.get("analyzers", [])
    lines = [
        "# AEP Project Analysis Report", "",
        f"**Project:** {project_name}", f"**Repository:** {repo_path}",
        f"**Scan status:** {scan_summary.get('status', 'UNKNOWN')}", "",
        "## Detected", "",
        ", ".join(report.get("project", {}).get("capabilities", [])) or "(nothing detected)", "",
        "## Security posture", "",
        "| Check | Status | Reason |", "|---|---|---|",
    ]
    for a in analyzers:
        lines.append(f"| {a['analyzer']} | {a['status']} | {a['reason']} |")
    findings = [f for a in analyzers for f in a.get("findings", [])]
    lines += ["", f"## Findings ({report.get('total_findings', 0)})", ""]
    if not findings:
        lines.append("No findings.")
    for f in findings:
        lines.append(f"- **{f['severity'].upper()}** {f['description']} (`{f['file']}:{f['line']}`)")
    lines += [
        "", "## Recommendation", "",
        "Review the findings above and remediate through a separate, explicit action. "
        "AEP made no changes to this repository during this scan.", "",
        f"*Report generated: {_now_iso()}*",
    ]
    return "\n".join(lines)
