"""Minimal CLI entrypoint.

`tasks`/`events` are per-project read paths over StateStore (the
"dashboard" referenced in ARCHITECTURE.md §18). `status`/`progress` (Phase
3 Part E/F) are platform-wide: they compute real progress/deployability
from `config/roadmap.yaml` plus a live pytest run every time they're
invoked - see src/aep/progress/. Nothing here reads a hardcoded percentage
from a doc; there isn't one.

Note: prior to Phase 3, `aep status --project X` listed that project's
tasks. Phase 3's spec calls for `aep status` to mean platform-wide status
instead (Part E), so that per-project task listing is now `aep tasks`. No
test exercised the old CLI surface (checked before renaming), so nothing
breaks; this is called out explicitly here and in the Phase 3 report.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Optional

from .bootstrap import build_orchestrator
from .models import ProjectConfig, TaskStatus
from .progress.calculator import compute_progress, record_phase_verified
from .progress.deployability import compute_deployability
from .state_store import StateStore

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def cmd_run_fix_bug(args: argparse.Namespace) -> None:
    project = ProjectConfig(id=args.project, name=args.project,
                             repo_path=args.repo, policy_path=args.policy)
    orch = build_orchestrator(args.db, project)
    task_ids = orch.plan_fix_bug(
        project_id=args.project, project_root=args.repo,
        target_file=args.file, bug_description=args.description,
    )
    orch.run_to_completion(args.project)
    for tid in task_ids:
        task = orch.store.get_task(tid)
        print(f"{task.type:16s} {task.status.value:22s} {task.id}")


def cmd_tasks(args: argparse.Namespace) -> None:
    """Per-project task listing (this is what `aep status --project X` did
    before Phase 3 - see this module's docstring)."""
    project = ProjectConfig(id=args.project, name=args.project,
                             repo_path=".", policy_path=args.policy)
    orch = build_orchestrator(args.db, project)
    for task in orch.store.list_tasks(args.project):
        print(f"{task.type:16s} {task.status.value:22s} attempts={task.attempts} {task.id}")


def cmd_events(args: argparse.Namespace) -> None:
    project = ProjectConfig(id=args.project, name=args.project,
                             repo_path=".", policy_path=args.policy)
    orch = build_orchestrator(args.db, project)
    for event in orch.store.query_events(project_id=args.project, task_id=args.task):
        print(json.dumps({
            "timestamp": event.timestamp, "actor": event.actor, "action": event.action,
            "decision": event.decision, "task_id": event.task_id,
        }))


# ---- Platform-wide status/progress (Phase 3 Part E/F) ------------------
def _bar(percent: float, width: int = 20) -> str:
    filled = int(round(max(0.0, min(100.0, percent)) / 100 * width))
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def _task_snapshot(store: StateStore, project_id: str) -> dict:
    tasks = store.list_tasks(project_id)
    by_status: dict[str, int] = {}
    for t in tasks:
        by_status[t.status.value] = by_status.get(t.status.value, 0) + 1
    running = [t for t in tasks if t.status == TaskStatus.RUNNING]
    ready = sorted((t for t in tasks if t.status == TaskStatus.READY),
                   key=lambda t: (-t.priority, t.created_at))
    pending = sorted((t for t in tasks if t.status == TaskStatus.PENDING),
                      key=lambda t: t.created_at)
    current = running[0] if running else (ready[0] if ready else None)
    nxt = ready[1] if running and len(ready) > 0 else (ready[0] if not running and ready else
                                                         (pending[0] if pending else None))
    recent_evidence = []
    for t in sorted(tasks, key=lambda t: t.updated_at, reverse=True)[:5]:
        for e in t.evidence[-2:]:
            recent_evidence.append({"task_type": t.type, "task_id": t.id, "source": e.source,
                                     "captured_at": e.captured_at, "summary": e.summary[:300]})
    return {
        "by_status": by_status,
        "current_task": {"id": current.id, "type": current.type, "status": current.status.value}
                         if current else None,
        "next_task": {"id": nxt.id, "type": nxt.type, "status": nxt.status.value} if nxt else None,
        "recent_evidence": recent_evidence,
    }


def _security_shell(cwd_default: str):
    """CLI-level convenience wrapper around real subprocess calls - the
    SAME trust boundary `progress/calculator.py::_run_pytest_per_file`
    already uses (a direct operator invocation of `aep`, not an
    agent-owned Task running through the capability-scoped ToolRegistry).
    `SecurityAgent` itself never uses this - it always goes through
    `ctx.tools.call("shell.run", ...)`, per ARCHITECTURE.md §16."""
    def run(args, cwd=None, timeout=90):
        try:
            proc = subprocess.run(args, cwd=cwd or cwd_default, capture_output=True, text=True,
                                   timeout=timeout)
            return {"ok": proc.returncode == 0, "exit_code": proc.returncode,
                    "stdout": proc.stdout, "stderr": proc.stderr, "args": args}
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            return {"ok": False, "exit_code": -1, "stdout": "", "stderr": str(e), "args": args}
    return run


def _build_security_posture(security_repo: str, db_path: Optional[str] = None,
                              project_id: Optional[str] = None) -> dict:
    """Part 10/11: a live security-posture computation, run fresh on
    demand - never a cached/stored percentage, same rule
    `progress/calculator.py` follows for test-pass counts. Opt-in only
    (via `--security-repo`) so plain `aep status`/`aep progress` stays
    fast and doesn't require gitleaks/semgrep/checkov to be installed."""
    from .dependency.inventory import build_inventory
    from .security.posture import compute_security_posture
    from .security.scan_runner import run_security_scan
    from .security.suppressions import list_suppressions

    run_shell = _security_shell(security_repo)
    sec_result = run_security_scan(security_repo, run_shell)
    dep_inventory = build_inventory(security_repo, run_shell)
    suppressions = []
    if db_path and project_id:
        suppressions = list_suppressions(StateStore(db_path), project_id)
    posture = compute_security_posture(sec_result.records, dep_inventory.scan_records, suppressions)
    return posture.to_dict()


def _build_infra_payload(infra_repo: str, cloud_provider: Optional[str] = None) -> dict:
    """Phase 5 Part 15: a live infrastructure inventory + posture, computed
    fresh on demand. Opt-in (via `--infra-repo`) for the same reason
    `--security-repo` is: the default `aep status` path must stay fast and
    must not require checkov/hcl2 to be installed."""
    from .infra.discovery import discover_infrastructure
    from .infra.risk import prioritize
    from .infra.scan_runner import run_infrastructure_scan
    from .security.posture import compute_security_posture

    run_shell = _security_shell(infra_repo)
    inventory = discover_infrastructure(infra_repo)
    scan_result = run_infrastructure_scan(infra_repo, run_shell)
    environment_for = {asset.path: asset.environment for asset in inventory.assets}
    scored = prioritize(scan_result.findings, environment_for)
    posture = compute_security_posture(scan_result.records, dependency_records=[])

    payload = {
        "inventory": inventory.to_dict(),
        "posture": posture.to_dict(),
        "top_risks": [
            {"finding_id": finding.id, "rule_id": finding.rule_id, "file": finding.file,
             "resource": finding.resource, **score.to_dict()}
            for finding, score in scored[:15]
        ],
        "scanners": [
            {"scanner": record.scanner, "category": record.category.value,
             "availability": record.availability.value, "findings": record.finding_count,
             "note": record.note[:400]}
            for record in scan_result.records
        ],
    }
    if cloud_provider:
        from .infra.cloud import registry
        result = registry.discover(cloud_provider)
        payload["cloud"] = result.to_dict()
        payload["cloud"]["is_real"] = result.is_real
    return payload


def _print_infra_human(payload: dict) -> None:
    inventory = payload["inventory"]
    print("=" * 78)
    print("INFRASTRUCTURE INTELLIGENCE")
    print("=" * 78)
    print(f"Assets discovered: {inventory['asset_count']}")
    print(f"  kinds:        {', '.join(inventory['kinds']) or 'none'}")
    print(f"  providers:    {', '.join(inventory['provider_hints']) or 'none'}")
    print(f"  environments: {', '.join(inventory['environments']) or 'none'}")
    print()
    print("SCANNERS")
    print("-" * 8)
    width = max((len(s["scanner"]) for s in payload["scanners"]), default=10) + 2
    for scanner in payload["scanners"]:
        status = (f"{scanner['findings']} finding(s)"
                   if scanner["availability"] == "AVAILABLE" else scanner["availability"])
        print(f"  {scanner['scanner']:<{width}}{scanner['category']:<12}{status}")
        if scanner["availability"] not in ("AVAILABLE", "NOT_APPLICABLE") and scanner["note"]:
            print(f"    ! {scanner['note'][:150]}")
    print()
    if payload["top_risks"]:
        print("TOP INFRASTRUCTURE RISKS (risk-weighted, highest first)")
        print("-" * 54)
        for risk in payload["top_risks"][:10]:
            promoted = (f" (promoted from {risk['base_severity']})"
                         if risk["priority_severity"] != risk["base_severity"] else "")
            print(f"  {risk['score']:7.1f}  {risk['priority_severity'].upper():<9}"
                  f"{str(risk['rule_id']):<24}{str(risk['resource'])[:34]}{promoted}")
            print(f"           {risk['environment']}/{risk['blast_radius']}/"
                  f"{risk['exploitability']}")
        print()
    _print_security_posture(payload["posture"])
    if "cloud" in payload:
        cloud = payload["cloud"]
        print()
        print(f"CLOUD ({cloud['provider']}): {cloud['status']}  (is_real={cloud['is_real']})")
        print(f"  {cloud['reason'][:200]}")
        print(f"  resources observed: {cloud['resource_count']}")
    print("=" * 78)


def _build_cicd_payload(cicd_repo: str) -> dict:
    """Phase 6 Part 17: opt-in (via `--cicd-repo`), a live pipeline
    discovery pass - no network required, so this is fast/dependency-free
    unlike --security-repo/--infra-repo."""
    from .cicd.discovery import discover_pipeline

    pipeline = discover_pipeline(cicd_repo)
    return {"pipeline": pipeline.to_dict()}


def _print_cicd_human(payload: dict) -> None:
    pipeline = payload["pipeline"]
    print("CI/CD PIPELINE")
    print("-" * 14)
    print(f"Workflows discovered: {pipeline['workflow_count']}")
    print(f"  build={pipeline['has_build']} test={pipeline['has_test']} "
          f"security={pipeline['has_security']} deploy={pipeline['has_deploy']} "
          f"approval_gate={pipeline['has_approval_gate']} "
          f"rollback_mechanism={pipeline['has_rollback_mechanism']}")
    for workflow in pipeline["workflows"]:
        if workflow["parse_error"]:
            print(f"  ! {workflow['path']}: {workflow['parse_error']}")
            continue
        print(f"  {workflow['path']}: {len(workflow['jobs'])} job(s)")


def _build_status_payload(args: argparse.Namespace, repo_root: Optional[str] = None,
                           roadmap_path: Optional[str] = None) -> dict:
    """`repo_root`/`roadmap_path` are test-injection points only (see
    tests/test_cli_status.py) - the real `aep status`/`aep progress`
    commands always use this repo's own config/roadmap.yaml. Deliberately
    NOT self-referential: a roadmap capability that gates on
    test_cli_status.py must never have that test file call this function
    against the REAL roadmap, or every `aep status` call would recursively
    spawn another full test run inside itself."""
    store = StateStore(args.db) if args.project else None
    progress = compute_progress(repo_root=repo_root or str(REPO_ROOT), roadmap_path=roadmap_path,
                                 store=store)
    deployability = compute_deployability(
        progress, live_github_verified=args.live_github_verified,
        live_cve_feed_verified=not args.live_cve_feed_unverified,
    )
    payload = {
        "overall_percent": progress.overall_percent,
        "tests": {"passed": progress.total_tests_passed, "failed": progress.total_tests_failed},
        "phases": [p.to_dict() for p in progress.phases],
        "deployability": deployability.to_dict(),
    }
    if store is not None and args.project:
        payload["tasks"] = _task_snapshot(store, args.project)
    security_repo = getattr(args, "security_repo", None)
    if security_repo:
        payload["security_posture"] = _build_security_posture(
            security_repo, db_path=args.db if args.project else None, project_id=args.project)
    infra_repo = getattr(args, "infra_repo", None)
    if infra_repo:
        payload["infrastructure"] = _build_infra_payload(
            infra_repo, cloud_provider=getattr(args, "cloud_provider", None))
    cicd_repo = getattr(args, "cicd_repo", None)
    if cicd_repo:
        payload["cicd"] = _build_cicd_payload(cicd_repo)
    return payload


def _print_status_human(payload: dict) -> None:
    print("=" * 78)
    print("AEP PLATFORM STATUS")
    print("=" * 78)
    print(f"Overall Progress: {payload['overall_percent']}%   "
          f"(tests: {payload['tests']['passed']} passed, {payload['tests']['failed']} failed)")
    print()
    for p in payload["phases"]:
        label = f"PHASE {p['id']}: {p['name']}"
        print(f"{label:<38s} {_bar(p['percent'])} {p['percent']:5.1f}%  {p['status']}")
    print()

    current_work = [c for p in payload["phases"] for c in p["capabilities"]
                     if c["status"] in ("IN_PROGRESS", "BLOCKED")]
    if current_work:
        print("CURRENT WORK:")
        for c in current_work:
            print(f"  - {c['id']} ({c['status']}): {c['reason'] or c['description']}")
        print()

    print("COMPLETED:")
    for p in payload["phases"]:
        for cid in p["completed_capabilities"]:
            print(f"  ✓ {cid}")
    print()

    print("NEXT:")
    for p in payload["phases"]:
        for cid in p["pending_capabilities"][:3]:
            desc = next((c["description"] for c in p["capabilities"] if c["id"] == cid), "")
            print(f"  → {cid}: {desc}")
    print()

    dep = payload["deployability"]
    print(f"DEPLOYABILITY: {dep['level']}")
    if dep["blockers"]:
        print("Blocking:")
        for b in dep["blockers"]:
            print(f"  - {b}")
    print("=" * 78)

    if "security_posture" in payload:
        print()
        _print_security_posture(payload["security_posture"])

    if "infrastructure" in payload:
        print()
        _print_infra_human(payload["infrastructure"])

    if "cicd" in payload:
        print()
        _print_cicd_human(payload["cicd"])

    if "tasks" in payload:
        print()
        print("PROJECT TASK SNAPSHOT:")
        print(f"  by status: {payload['tasks']['by_status']}")
        if payload["tasks"]["current_task"]:
            print(f"  current:   {payload['tasks']['current_task']}")
        if payload["tasks"]["next_task"]:
            print(f"  next:      {payload['tasks']['next_task']}")


def _print_security_posture(posture: dict) -> None:
    """Renders exactly the shape given in the Phase 4 spec's Part 10
    example (category name / status two-column block, then a readiness
    line, then why)."""
    print("SECURITY POSTURE")
    print("-" * 16)
    width = max((len(c["name"]) for c in posture["categories"]), default=8) + 2
    for c in posture["categories"]:
        print(f"{c['name']:<{width}}{c['status']}")
    print()
    print("Security readiness:")
    print(posture["readiness"])
    if posture["explanation"]:
        print()
        for line in posture["explanation"]:
            print(f"  - {line}")


def cmd_status(args: argparse.Namespace) -> None:
    payload = _build_status_payload(args)
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    _print_status_human(payload)


def cmd_progress(args: argparse.Namespace) -> None:
    """Same computation as `status`, with the full per-capability
    breakdown printed for every phase (not just current/completed/next)."""
    payload = _build_status_payload(args)
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    print("=" * 78)
    print("AEP PLATFORM PROGRESS (detailed)")
    print("=" * 78)
    print(f"Overall: {payload['overall_percent']}%")
    for p in payload["phases"]:
        print()
        print(f"PHASE {p['id']}: {p['name']}  {_bar(p['percent'])} {p['percent']:5.1f}%  {p['status']}")
        print(f"  {p['description']}")
        for c in p["capabilities"]:
            marker = {"COMPLETE": "✓", "IN_PROGRESS": "~", "BLOCKED": "!", "PENDING": "·"}[c["status"]]
            extra = f" - {c['reason']}" if c["reason"] else ""
            print(f"    {marker} [{c['status']:11s}] {c['id']}: {c['description']}{extra}")
    print()
    dep = payload["deployability"]
    print(f"DEPLOYABILITY: {dep['level']}")
    for b in dep["blockers"]:
        print(f"  - {b}")
    print("=" * 78)
    if "security_posture" in payload:
        print()
        _print_security_posture(payload["security_posture"])
    if "infrastructure" in payload:
        print()
        _print_infra_human(payload["infrastructure"])
    if "cicd" in payload:
        print()
        _print_cicd_human(payload["cicd"])


def cmd_security_status(args: argparse.Namespace) -> None:
    """Standalone security-posture check against any target repo, without
    needing a full platform-wide status computation - `aep status
    --security-repo X` (Part 11) folds the same computation into the
    platform status payload; this is the fast, focused path."""
    posture = _build_security_posture(args.repo, db_path=args.db if args.project else None,
                                        project_id=args.project)
    if args.json:
        print(json.dumps(posture, indent=2))
        return
    _print_security_posture(posture)


def cmd_security_suppress(args: argparse.Namespace) -> None:
    from .security.suppressions import suppress_finding

    store = StateStore(args.db)
    suppress_finding(store, args.project, args.finding_id, args.justification, args.reviewer,
                      args.evidence, expiry=args.expiry)
    print(f"suppressed {args.finding_id} for project '{args.project}' "
          f"(reviewer={args.reviewer!r}, expiry={args.expiry or 'none'})")


def cmd_security_suppressions(args: argparse.Namespace) -> None:
    from .security.suppressions import list_suppressions

    store = StateStore(args.db)
    suppressions = list_suppressions(store, args.project)
    if args.json:
        print(json.dumps([s.__dict__ for s in suppressions], indent=2))
        return
    for s in suppressions:
        state = "REVOKED" if s.revoked else ("ACTIVE" if s.is_active() else "EXPIRED")
        print(f"[{state}] {s.finding_id} - {s.justification} (reviewer={s.reviewer}, "
              f"expiry={s.expiry or 'none'})")


def cmd_infra_status(args: argparse.Namespace) -> None:
    """Standalone infrastructure intelligence report for a target repo."""
    payload = _build_infra_payload(args.repo, cloud_provider=args.cloud_provider)
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    _print_infra_human(payload)


def cmd_infra_inventory(args: argparse.Namespace) -> None:
    """Read-only infrastructure discovery only - no scanners invoked, so
    this runs anywhere regardless of which tools are installed."""
    from .infra.discovery import discover_infrastructure

    inventory = discover_infrastructure(args.repo)
    if args.json:
        print(json.dumps(inventory.to_dict(), indent=2))
        return
    print(f"{len(inventory.assets)} infrastructure asset(s) in {args.repo}")
    for asset in inventory.assets:
        print(f"  {asset.kind.value:24s} {asset.environment.value:12s}"
              f"({asset.environment_confidence:6s}) {asset.path}")
        if asset.detail:
            print(f"    {asset.detail}")
    for entry in inventory.unreadable:
        print(f"  ! {entry['path']}: {entry['reason']}")


def cmd_cloud_status(args: argparse.Namespace) -> None:
    """Reports each cloud provider adapter's real status. Never contacts a
    provider unless --discover is passed, and even then only read-only."""
    from .infra.cloud import registry

    if args.discover:
        result = registry.discover(args.provider)
    else:
        result = registry.describe_provider(args.provider)
    payload = result.to_dict()
    payload["is_real"] = result.is_real
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    print(f"provider:  {result.provider}")
    print(f"status:    {result.status.value}   (is_real={result.is_real})")
    print(f"reason:    {result.reason}")
    print(f"resources: {len(result.resources)}")
    for resource in result.resources:
        print(f"  {resource.resource_id} ({resource.resource_type}): {resource.attributes}")
    for capability, error in (result.capabilities_failed or {}).items():
        print(f"  ! {capability}: {error}")
    print(f"known providers: {', '.join(registry.known_providers())}; "
          f"implemented: {', '.join(registry.supported_providers())}")


def cmd_ci_status(args: argparse.Namespace) -> None:
    """Standalone CI/CD pipeline discovery report for a target repo -
    static, no-network, works regardless of live GitHub Actions
    reachability (see cicd/providers/github_actions.py for why that
    matters in this sandbox)."""
    payload = _build_cicd_payload(args.repo)
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    _print_cicd_human(payload)


def cmd_deploy_status(args: argparse.Namespace) -> None:
    """Deployment readiness/evidence for a project: release-gate status
    (from the last computed gates, if any were recorded) and every
    deployment attempt ever recorded (Part 13/17/18) - never invented, and
    survives process restart because it reads the same StateStore file."""
    from .deployment.evidence import list_deployment_evidence

    store = StateStore(args.db)
    records = list_deployment_evidence(store, args.project)
    payload = {"project": args.project, "deployment_count": len(records),
               "deployments": [r.to_dict() for r in records]}
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    print(f"DEPLOYMENT HISTORY for project '{args.project}' ({len(records)} attempt(s))")
    print("-" * 60)
    for r in records:
        print(f"  [{r.final_state.value:16s}] {r.environment:12s} commit={r.commit_sha[:12]} "
              f"artifact={r.artifact_id} gates_passed={r.release_gates_passed} "
              f"approval={r.approval_status} rollback={r.rollback_status}")


def cmd_verify_phase(args: argparse.Namespace) -> None:
    """Explicitly runs and records verification for a phase (promotes
    COMPLETE -> VERIFIED). Refuses if the phase isn't COMPLETE right now -
    "verified" must mean something."""
    store = StateStore(args.db)
    progress = compute_progress(repo_root=str(REPO_ROOT), store=store)
    phase = progress.phase(args.phase)
    if phase is None:
        print(f"no such phase: {args.phase}", file=sys.stderr)
        sys.exit(2)
    if phase.status not in ("COMPLETE", "VERIFIED"):
        print(f"phase {args.phase} ({phase.name}) is {phase.status}, not COMPLETE - "
              f"refusing to mark VERIFIED", file=sys.stderr)
        sys.exit(1)
    record_phase_verified(store, args.phase, verified_by=args.by)
    print(f"phase {args.phase} ({phase.name}) recorded as VERIFIED by '{args.by}'")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="aep")
    parser.add_argument("--db", default="aep_state.db")
    parser.add_argument("--policy", default="config/policy.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    p_fix = sub.add_parser("run-fix-bug")
    p_fix.add_argument("--project", required=True)
    p_fix.add_argument("--repo", required=True)
    p_fix.add_argument("--file", required=True)
    p_fix.add_argument("--description", required=True)
    p_fix.set_defaults(func=cmd_run_fix_bug)

    p_tasks = sub.add_parser("tasks", help="list a project's tasks (was `status` before Phase 3)")
    p_tasks.add_argument("--project", required=True)
    p_tasks.set_defaults(func=cmd_tasks)

    p_events = sub.add_parser("events")
    p_events.add_argument("--project", required=True)
    p_events.add_argument("--task", default=None)
    p_events.set_defaults(func=cmd_events)

    for name, fn, help_text in (
        ("status", cmd_status, "platform-wide progress/deployability summary"),
        ("progress", cmd_progress, "detailed per-phase/per-capability progress"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--project", default=None, help="optionally fold in this project's task state")
        p.add_argument("--json", action="store_true", help="machine-readable output")
        p.add_argument("--live-github-verified", action="store_true",
                        help="assert live GitHub API integration has been exercised (operator claim)")
        p.add_argument("--live-cve-feed-unverified", action="store_true",
                        help="assert live CVE/advisory feed integration has NOT been verified")
        # Phase 4 Part 11: opt-in (no default) - a live gitleaks/semgrep/
        # checkov scan against a real target repo, not required for plain
        # `aep status`/`aep progress` to stay fast and dependency-free.
        p.add_argument("--security-repo", default=None,
                        help="also compute a live security posture (Part 10) against this repo path")
        # Phase 5: opt-in for the same reason as --security-repo.
        p.add_argument("--infra-repo", default=None,
                        help="also compute a live infrastructure inventory/posture for this repo")
        p.add_argument("--cloud-provider", default=None,
                        help="with --infra-repo, also attempt READ-ONLY cloud discovery")
        # Phase 6: opt-in for the same reason as --security-repo/--infra-repo.
        p.add_argument("--cicd-repo", default=None,
                        help="also compute a live CI/CD pipeline discovery for this repo path")
        p.set_defaults(func=fn)

    p_secstatus = sub.add_parser("security-status",
                                  help="live security posture (secrets/SAST/dependencies/IaC/"
                                       "containers) for a target repo")
    p_secstatus.add_argument("--repo", required=True)
    p_secstatus.add_argument("--project", default=None, help="fold in this project's suppressions")
    p_secstatus.add_argument("--json", action="store_true")
    p_secstatus.set_defaults(func=cmd_security_status)

    p_secsuppress = sub.add_parser("security-suppress",
                                    help="record a justified false-positive suppression "
                                         "(never a silent deletion - see security/suppressions.py)")
    p_secsuppress.add_argument("--project", required=True)
    p_secsuppress.add_argument("--finding-id", required=True)
    p_secsuppress.add_argument("--justification", required=True)
    p_secsuppress.add_argument("--reviewer", required=True)
    p_secsuppress.add_argument("--evidence", required=True)
    p_secsuppress.add_argument("--expiry", default=None, help="ISO8601 timestamp; omit for no expiry")
    p_secsuppress.set_defaults(func=cmd_security_suppress)

    p_secsuppressions = sub.add_parser("security-suppressions",
                                        help="list every suppression ever recorded for a project, "
                                             "including revoked/expired ones")
    p_secsuppressions.add_argument("--project", required=True)
    p_secsuppressions.add_argument("--json", action="store_true")
    p_secsuppressions.set_defaults(func=cmd_security_suppressions)

    p_infra = sub.add_parser("infra-status",
                              help="infrastructure inventory, scanners, risk-ranked findings "
                                   "and posture for a target repo")
    p_infra.add_argument("--repo", required=True)
    p_infra.add_argument("--cloud-provider", default=None,
                          help="also attempt READ-ONLY cloud discovery for this provider")
    p_infra.add_argument("--json", action="store_true")
    p_infra.set_defaults(func=cmd_infra_status)

    p_inventory = sub.add_parser("infra-inventory",
                                  help="read-only infrastructure discovery only (no scanners)")
    p_inventory.add_argument("--repo", required=True)
    p_inventory.add_argument("--json", action="store_true")
    p_inventory.set_defaults(func=cmd_infra_inventory)

    p_cloud = sub.add_parser("cloud-status",
                              help="cloud adapter status; READ-ONLY discovery with --discover")
    p_cloud.add_argument("--provider", required=True)
    p_cloud.add_argument("--discover", action="store_true",
                          help="perform a real read-only discovery pass (never mutates anything)")
    p_cloud.add_argument("--json", action="store_true")
    p_cloud.set_defaults(func=cmd_cloud_status)

    p_ci = sub.add_parser("ci-status", help="CI/CD pipeline discovery for a target repo "
                                             "(static, no network required)")
    p_ci.add_argument("--repo", required=True)
    p_ci.add_argument("--json", action="store_true")
    p_ci.set_defaults(func=cmd_ci_status)

    p_deploy = sub.add_parser("deploy-status", help="deployment evidence/history for a project")
    p_deploy.add_argument("--project", required=True)
    p_deploy.add_argument("--json", action="store_true")
    p_deploy.set_defaults(func=cmd_deploy_status)

    p_verify = sub.add_parser("verify-phase")
    p_verify.add_argument("--phase", type=int, required=True)
    p_verify.add_argument("--by", default="operator")
    p_verify.set_defaults(func=cmd_verify_phase)

    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
