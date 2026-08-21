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
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

from .bootstrap import build_orchestrator
from .models import ProjectConfig, TaskStatus
from .progress.calculator import compute_progress, record_phase_verified
from .progress.deployability import compute_deployability
from .db.factory import build_state_store

# Packaged default: resolves identically from a source checkout and a
# `pip install` of the wheel (BUG-0014 class). Never cwd-relative.
DEFAULT_POLICY_PATH = str(Path(__file__).resolve().parent / "config" / "policy.yaml")
from .state_store import StateStore
from .skills.claude_adapter import project_to_claude_skill, render_claude_skill_markdown
from .skills.definitions import seed_canonical_skills
from .skills.factory import build_skill_registry
from .skills.registry import SkillNotFoundError
from .ai_gateway.fake_provider import FakeAIProvider
from .ai_gateway.gateway import AIGateway, CATEGORY_TAG_RULES
from .ai_gateway.omniroute_provider import OmniRouteConfigError, OmniRouteProvider
from .demo import run_ambiguous_demo, run_demo
from .progress.demo_readiness import compute_demo_readiness, render_demo_readiness

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
        suppressions = list_suppressions(build_state_store(db_path), project_id)
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
    store = build_state_store(args.db) if args.project else None
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
        # Phase 7: fold in operational incident history the same opt-in-
        # only-with-a-project way `tasks` above already does - no new flag
        # needed since a project's incidents are as much "this project's
        # state" as its tasks are.
        from .operations.memory import list_incidents
        incidents = list_incidents(store, args.project)
        payload["operations"] = {
            "incident_count": len(incidents),
            "recurring_fingerprints": sorted({i.fingerprint for i in incidents
                                               if sum(1 for j in incidents
                                                      if j.fingerprint == i.fingerprint) > 1}),
        }
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

    if "operations" in payload:
        print()
        print(f"OPERATIONAL INCIDENTS: {payload['operations']['incident_count']} recorded")
        if payload["operations"]["recurring_fingerprints"]:
            print(f"  recurring: {payload['operations']['recurring_fingerprints']}")

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

    store = build_state_store(args.db)
    suppress_finding(store, args.project, args.finding_id, args.justification, args.reviewer,
                      args.evidence, expiry=args.expiry)
    print(f"suppressed {args.finding_id} for project '{args.project}' "
          f"(reviewer={args.reviewer!r}, expiry={args.expiry or 'none'})")


def cmd_security_suppressions(args: argparse.Namespace) -> None:
    from .security.suppressions import list_suppressions

    store = build_state_store(args.db)
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

    store = build_state_store(args.db)
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


def _build_operations_payload(project_id: str, db_path: str) -> dict:
    """Phase 7 Part 11: durable incident-memory read path, following the
    exact same shape as `_build_cicd_payload`/`cmd_deploy_status` above -
    read-only, reads back whatever `operations_intelligence_agent` already
    recorded through the existing `operations` tool/StateStore, never
    invented."""
    from .operations.memory import list_incidents

    store = build_state_store(db_path)
    records = list_incidents(store, project_id)
    return {"project": project_id, "incident_count": len(records),
            "incidents": [r.to_dict() for r in records]}


def _print_operations_human(payload: dict) -> None:
    print(f"OPERATIONAL INCIDENT HISTORY for project '{payload['project']}' "
          f"({payload['incident_count']} recorded)")
    print("-" * 60)
    for r in payload["incidents"]:
        print(f"  fingerprint={r['fingerprint']:60.60s} remediation={r['remediation_used']:24s} "
              f"succeeded={r['remediation_succeeded']} environment={r['environment']}")


def cmd_operations_status(args: argparse.Namespace) -> None:
    """`aep operations-status --project X`: every operational incident
    ever recorded for a project (Phase 7 Part 9/11), survives a process
    restart because it reads the same durable StateStore file every other
    `*-status` command reads."""
    payload = _build_operations_payload(args.project, args.db)
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    _print_operations_human(payload)


def cmd_incident_status(args: argparse.Namespace) -> None:
    """`aep incident-status --project X --fingerprint F`: advisory lookup
    of prior incidents matching one correlation fingerprint - the same
    "similar incident occurred previously" retrieval
    `operations_intelligence_agent._scan` performs automatically, exposed
    standalone for operator inspection."""
    from .operations.memory import find_similar

    store = build_state_store(args.db)
    records = find_similar(store, args.project, args.fingerprint)
    payload = {"project": args.project, "fingerprint": args.fingerprint,
               "match_count": len(records), "matches": [r.to_dict() for r in records]}
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    print(f"{len(records)} prior incident(s) matching fingerprint {args.fingerprint!r} "
          f"(advisory only)")
    for r in payload["matches"]:
        print(f"  incident={r['incident_id']} remediation={r['remediation_used']} "
              f"succeeded={r['remediation_succeeded']}")


def cmd_verify_phase(args: argparse.Namespace) -> None:
    """Explicitly runs and records verification for a phase (promotes
    COMPLETE -> VERIFIED). Refuses if the phase isn't COMPLETE right now -
    "verified" must mean something."""
    store = build_state_store(args.db)
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


def cmd_runtime_start(args: argparse.Namespace) -> None:
    """`aep runtime start`: runs a CONTROLLED, bounded supervisor session
    (N cycles or M seconds - never an unbounded background loop, see
    src/aep/runtime/supervisor.py module docstring) against the given
    project's repo, then reports what happened and exits."""
    from .policy import PolicyEngine
    from .runtime import scheduler as scheduler_mod
    from .runtime.supervisor import RuntimeSupervisor

    store = build_state_store(args.db)
    policy = PolicyEngine.from_yaml(args.policy)
    scheduler_mod.register_default_jobs(store, args.project, interval_seconds=args.interval)
    supervisor = RuntimeSupervisor(store, policy, num_workers=args.workers)
    repos = {args.project: args.repo} if args.repo else {}
    reports = supervisor.run(max_cycles=args.cycles, max_seconds=args.max_seconds, repos=repos)
    payload = {"supervisor_id": supervisor.supervisor_id, "cycles_run": len(reports),
               "results": [r.__dict__ for r in reports]}
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"runtime supervisor {supervisor.supervisor_id} ran {len(reports)} controlled cycle(s) "
              f"(bounded test-mode run, not a persistent daemon)")
        for r in reports:
            print(f"  cycle {r.cycle}: jobs_dispatched={r.jobs_dispatched} health={r.health}")


def cmd_runtime_status(args: argparse.Namespace) -> None:
    from .runtime.status import build_runtime_status_payload, print_runtime_status_human

    store = build_state_store(args.db)
    payload = build_runtime_status_payload(store, supervisor_id=args.supervisor)
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    print_runtime_status_human(payload)


def cmd_runtime_stop(args: argparse.Namespace) -> None:
    """Marks every worker registered under a supervisor STOPPED (graceful
    shutdown signal) - there is no background process in this environment
    to send a real signal to since `runtime start` runs bounded and exits
    on its own."""
    store = build_state_store(args.db)
    workers = store.list_workers(args.supervisor)
    for w in workers:
        store.heartbeat_worker(w["worker_id"], "STOPPED")
    print(f"marked {len(workers)} worker(s) STOPPED for supervisor={args.supervisor!r}")


def cmd_runtime_workers(args: argparse.Namespace) -> None:
    store = build_state_store(args.db)
    workers = store.list_workers(args.supervisor)
    if args.json:
        print(json.dumps(workers, indent=2))
        return
    for w in workers:
        print(f"  {w['worker_id']:20.20s} status={w['status']:8.8s} "
              f"restarts={w['restart_count']} last_heartbeat={w['last_heartbeat']}")


def cmd_runtime_jobs(args: argparse.Namespace) -> None:
    store = build_state_store(args.db)
    jobs = store.list_schedules()
    if args.json:
        print(json.dumps(jobs, indent=2))
        return
    for j in jobs:
        print(f"  {j['job_id']:40.40s} next_run_at={j['next_run_at']} "
              f"last_status={j['last_status']} failures={j['consecutive_failures']}")


def cmd_runtime_recover(args: argparse.Namespace) -> None:
    """`aep runtime recover`: startup/crash recovery pass - reassesses
    health and releases stale leases so genuinely-stuck work can be
    re-claimed. Never performs destructive recovery and never bypasses
    policy (it only clears runtime bookkeeping, not task outcomes)."""
    from .policy import PolicyEngine
    from .runtime.supervisor import RuntimeSupervisor

    store = build_state_store(args.db)
    policy = PolicyEngine.from_yaml(args.policy)
    supervisor = RuntimeSupervisor(store, policy, num_workers=1, supervisor_id=args.supervisor)
    report = supervisor.recover()
    payload = report.to_dict()
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    print(f"recovery pass complete: health={payload['state']} "
          f"stale_workers={payload['stale_workers']} stuck_tasks={payload['stuck_tasks']}")


# ---- Skills registry CLI (Phase 9 Stage B, Part 20) ------------------------

def _skill_registry_for_args(args: argparse.Namespace):
    return build_skill_registry(backend=getattr(args, "skills_backend", None) or "postgres",
                                 policy_path=args.policy)


def _build_skills_list_payload(args: argparse.Namespace) -> dict:
    registry = _skill_registry_for_args(args)
    if getattr(args, "seed", False):
        seed_canonical_skills(registry)
    skills = []
    for skill in sorted(registry.list_skills(), key=lambda s: s.skill_id):
        versions = registry.list_versions(skill.skill_id)
        published = [v for v in versions if v.lifecycle_state.value == "published"]
        latest = published[-1].version if published else None
        skills.append({
            "skill_id": skill.skill_id, "name": skill.name, "description": skill.description,
            "latest_published_version": latest,
            "version_count": len(versions),
        })
    return {"skills": skills}


def _print_skills_list_human(payload: dict) -> None:
    for s in payload["skills"]:
        print(f"{s['skill_id']:20s} latest={str(s['latest_published_version']):8s} "
              f"versions={s['version_count']:3d}  {s['name']}")


def cmd_skills_list(args: argparse.Namespace) -> None:
    payload = _build_skills_list_payload(args)
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    _print_skills_list_human(payload)


def _build_skills_show_payload(args: argparse.Namespace) -> dict:
    registry = _skill_registry_for_args(args)
    if getattr(args, "seed", False):
        seed_canonical_skills(registry)
    version = (registry.get_version(args.skill_id, args.version) if args.version
               else registry.latest_version(args.skill_id))
    dep_res = registry.resolve_dependencies(version.skill_id, version.version)
    return {
        "skill_id": version.skill_id, "version": version.version,
        "lifecycle_state": version.lifecycle_state.value,
        "risk_level": version.risk_level.value,
        "description": version.description, "purpose": version.purpose, "scope": version.scope,
        "capabilities": version.capabilities, "allowed_tools": sorted(version.allowed_tools),
        "prohibited_actions": sorted(version.prohibited_actions),
        "required_checks": sorted(version.required_checks),
        "verification_rules": sorted(version.verification_rules),
        "escalation_rules": version.escalation_rules,
        "approval_requirements": version.approval_requirements,
        "dependencies": [f"{d.depends_on_skill_id}{d.version_constraint}" for d in version.dependencies],
        "dependency_resolution": {
            "ok": dep_res.ok, "missing": dep_res.missing, "conflicts": dep_res.conflicts,
            "cycle": dep_res.cycle,
        },
    }


def cmd_skills_show(args: argparse.Namespace) -> None:
    payload = _build_skills_show_payload(args)
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    print(f"{payload['skill_id']}@{payload['version']} [{payload['lifecycle_state']}] "
          f"risk={payload['risk_level']}")
    print(f"  purpose: {payload['purpose']}")
    print(f"  allowed_tools: {', '.join(payload['allowed_tools'])}")
    print(f"  dependencies: {', '.join(payload['dependencies']) or '(none)'} "
          f"(resolved ok={payload['dependency_resolution']['ok']})")


def _build_skills_versions_payload(args: argparse.Namespace) -> dict:
    registry = _skill_registry_for_args(args)
    if getattr(args, "seed", False):
        seed_canonical_skills(registry)
    versions = registry.list_versions(args.skill_id)
    return {
        "skill_id": args.skill_id,
        "versions": [{"version": v.version, "lifecycle_state": v.lifecycle_state.value} for v in versions],
    }


def cmd_skills_versions(args: argparse.Namespace) -> None:
    payload = _build_skills_versions_payload(args)
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    for v in payload["versions"]:
        print(f"{payload['skill_id']}@{v['version']}  [{v['lifecycle_state']}]")


def _build_skills_validate_payload(args: argparse.Namespace) -> dict:
    registry = _skill_registry_for_args(args)
    if getattr(args, "seed", False):
        seed_canonical_skills(registry)
    problems: dict[str, list[str]] = {}
    for skill in registry.list_skills():
        for version in registry.list_versions(skill.skill_id):
            found = registry.self_validate(version)
            dep_res = registry.resolve_dependencies(version.skill_id, version.version)
            if not dep_res.ok:
                found = found + [
                    f"unresolved dependencies: missing={dep_res.missing} "
                    f"conflicts={dep_res.conflicts} cycle={dep_res.cycle}"
                ]
            if found:
                problems[f"{version.skill_id}@{version.version}"] = found
    return {"clean": not problems, "problems": problems}


def cmd_skills_validate(args: argparse.Namespace) -> None:
    payload = _build_skills_validate_payload(args)
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    if payload["clean"]:
        print("all skill versions valid (self-validation + dependency resolution)")
    else:
        for key, probs in payload["problems"].items():
            print(f"{key}:")
            for p in probs:
                print(f"  - {p}")


def _build_skills_project_payload(args: argparse.Namespace) -> dict:
    registry = _skill_registry_for_args(args)
    version = (registry.get_version(args.skill_id, args.version) if args.version
               else registry.latest_version(args.skill_id))
    return project_to_claude_skill(version)


def cmd_skills_project(args: argparse.Namespace) -> None:
    registry = _skill_registry_for_args(args)
    if getattr(args, "seed", False):
        seed_canonical_skills(registry)
    version = (registry.get_version(args.skill_id, args.version) if args.version
               else registry.latest_version(args.skill_id))
    if args.markdown:
        print(render_claude_skill_markdown(version))
        return
    payload = project_to_claude_skill(version)
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    print(json.dumps(payload, indent=2, sort_keys=True))


def _build_providers_payload(args: argparse.Namespace) -> dict:
    """Stage C: `aep providers` - lists every registered AI provider/model,
    which is default, which is fallback, and whether real OmniRoute is
    actually reachable in this environment (honest, never faked)."""
    providers = {"fake": FakeAIProvider()}
    omniroute_status = "unavailable"
    omniroute_detail = "AI_BASE_URL/AI_CREDENTIAL not configured in this environment"
    try:
        real = OmniRouteProvider()
        providers["omniroute"] = real
        health = real.health_check()
        omniroute_status = "healthy" if health.healthy else "unreachable"
        omniroute_detail = health.detail
    except OmniRouteConfigError as exc:
        omniroute_detail = str(exc)

    gateway = AIGateway(providers=providers, default_provider_id="fake")
    payload = {
        "default_provider_id": gateway.default_provider_id,
        "fallback_provider_id": gateway.fallback_provider_id,
        "routing_table": dict(CATEGORY_TAG_RULES),
        "omniroute": {"status": omniroute_status, "detail": omniroute_detail},
        "providers": [],
    }
    for provider_id, provider in providers.items():
        payload["providers"].append({
            "provider_id": provider_id,
            "models": [
                {"model_id": m.model_id, "tags": sorted(m.tags),
                 "context_window_tokens": m.context_window_tokens}
                for m in provider.list_models()
            ],
        })
    return payload


def cmd_scan(args: argparse.Namespace) -> None:
    """`aep scan <path>` - capability-routed, READ-ONLY project analysis.

    Detects what the repository actually is, runs only the analyzers that
    apply, and reports precisely why each of the rest did not run. Makes
    no change of any kind to the target repository.
    """
    from .scan import render_report, scan_project

    report = scan_project(args.path)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(render_report(report))


def cmd_start(args: argparse.Namespace) -> None:
    """One-command local product start: local Postgres -> pgvector ->
    migrations -> API -> packaged UI, then print the URL. Every step is
    reported honestly; nothing is faked if it fails."""
    import socket

    from .db.local_postgres import get_data_dir
    from .db.state_store_postgres import dsn_from_env

    print("AEP starting...")
    try:
        dsn_from_env()  # provisions/reuses local Postgres + pgvector + migrations
    except Exception as exc:  # noqa: BLE001 - reported, never swallowed
        print(f"Local database: FAILED - {exc}")
        return
    print(f"Local database: READY  ({get_data_dir()})")
    print("Migrations:     READY")

    omniroute = _build_providers_payload(args)["omniroute"]
    print(f"AI Provider:    {'READY' if omniroute['status'] == 'healthy' else 'NOT_CONFIGURED'}"
          f"  ({omniroute['detail']})")

    ui_dist = Path(__file__).resolve().parent / "ui_dist"
    print(f"UI:             {'READY' if ui_dist.is_dir() else 'NOT_PACKAGED'}")

    # Port 0 lets the OS pick a free port, so a second AEP (or anything
    # already on the default) never collides. Bound to loopback only.
    if args.port == 0:
        with socket.socket() as probe:
            probe.bind((args.host, 0))
            args.port = probe.getsockname()[1]

    # Loopback-only single-user local product: the packaged UI and the API
    # share one origin, so the UI has no way to hold an API key. Dev-mode
    # auth-bypass is what makes that work, and it prints its own loud
    # warning at create_app() time. Not reachable off this machine.
    os.environ.setdefault("AEP_API_DEV_MODE", "1")
    from .api.app import create_app
    app = create_app(db_backend=args.db_backend)

    print(f"Runtime:        READY\n\nOpen: http://{args.host}:{args.port}\n")
    app.run(host=args.host, port=args.port)


def cmd_providers(args: argparse.Namespace) -> None:
    payload = _build_providers_payload(args)
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    print(f"default provider: {payload['default_provider_id']}  "
          f"fallback: {payload['fallback_provider_id'] or '(none configured)'}")
    print(f"OmniRoute: {payload['omniroute']['status']} - {payload['omniroute']['detail']}")
    print("routing table (category -> required tag):")
    for category, tag in payload["routing_table"].items():
        print(f"  {category:20s} -> {tag}")
    for p in payload["providers"]:
        print(f"provider={p['provider_id']}")
        for m in p["models"]:
            print(f"    {m['model_id']:20s} tags={m['tags']}  context={m['context_window_tokens']}")


def cmd_demo_run(args: argparse.Namespace) -> None:
    if args.scenario == "ambiguous":
        result = run_ambiguous_demo()
    else:
        result = run_demo(work_dir=args.work_dir, db_backend=args.db_backend)
    print(result.render())


def cmd_demo_readiness(args: argparse.Namespace) -> None:
    checks = compute_demo_readiness()
    print(render_demo_readiness(checks))
    if not all(c.ok for c in checks):
        sys.exit(1)


def _build_prioritize_payload(args: argparse.Namespace) -> dict:
    """Phase 10 Wave 1: deterministic cross-project finding prioritization.
    Calls the SAME `rank_findings()` the `GET /intelligence/prioritization`
    API handler calls - no ranking logic is duplicated here."""
    from .db.postgres import ConnectionPool, PostgresFindingRepository, PostgresProjectRepository
    from .db.state_store_postgres import dsn_from_env
    from .intelligence.prioritization import prioritized_finding_to_dict, rank_findings

    pool = ConnectionPool(dsn_from_env())
    finding_repo = PostgresFindingRepository(pool)
    project_repo = PostgresProjectRepository(pool)
    project_ids = [args.project_filter] if getattr(args, "project_filter", None) else None
    ranked = rank_findings(finding_repo, project_repo, project_ids=project_ids)
    return {"count": len(ranked), "items": [prioritized_finding_to_dict(r) for r in ranked]}


def cmd_prioritize(args: argparse.Namespace) -> None:
    payload = _build_prioritize_payload(args)
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    print(f"{payload['count']} open finding(s) ranked (deterministic, no AI):")
    for item in payload["items"]:
        print(f"#{item['rank']:<3d} score={item['score']:.4f} "
              f"[{item['severity']:8s}] {item['project_id']:12s} {item['category']:24s} "
              f"resource={item['resource']}")
        for factor, entry in item["breakdown"].items():
            print(f"       {factor:18s} weight={entry['weight']:.2f} "
                  f"score={entry['score']:.2f} contribution={entry['contribution']:.4f} "
                  f"raw={entry['raw']}")


def _build_patterns_payload(args: argparse.Namespace) -> dict:
    """Phase 10 Wave 2: incident-pattern / engineering-health intelligence.
    Calls the SAME `detect_patterns()`/`compute_health_signals()` the
    `GET /intelligence/patterns` and `GET /intelligence/health` API
    handlers call - no logic is duplicated here."""
    from .db.postgres import ConnectionPool, PostgresFindingRepository, PostgresProjectRepository
    from .db.state_store_postgres import dsn_from_env
    from .db.factory import build_state_store
    from .deployment.evidence import list_deployment_evidence
    from .operations.memory import list_incidents
    from .intelligence.incident_patterns import compute_health_signals, detect_patterns

    pool = ConnectionPool(dsn_from_env())
    finding_repo = PostgresFindingRepository(pool)
    project_repo = PostgresProjectRepository(pool)
    store = build_state_store(args.db)
    projects = project_repo.list()
    project_ids = [args.project_filter] if getattr(args, "project_filter", None) else None
    wanted_projects = [p for p in projects if project_ids is None or p.id in project_ids]

    deployment_evidence_by_project = {p.id: list_deployment_evidence(store, p.id) for p in wanted_projects}
    incidents_by_project = {p.id: list_incidents(store, p.id) for p in wanted_projects}

    patterns = detect_patterns(finding_repo, project_ids=project_ids,
                                deployment_evidence_by_project=deployment_evidence_by_project)
    signals = compute_health_signals(
        finding_repo, project_repo,
        deployment_evidence_by_project=deployment_evidence_by_project,
        incidents_by_project=incidents_by_project, project_ids=project_ids,
    )
    return {
        "patterns": [p.to_dict() for p in patterns],
        "health_signals": [s.to_dict() for s in signals],
    }


def _build_risk_payload(args: argparse.Namespace) -> dict:
    """Phase 10 Wave 3: evidence-based predictive risk intelligence.
    Calls the SAME `predict_risk()` the `GET /intelligence/risk` API
    handler calls - no logic is duplicated here."""
    from .db.postgres import ConnectionPool, PostgresFindingRepository, PostgresProjectRepository
    from .db.state_store_postgres import dsn_from_env
    from .db.factory import build_state_store
    from .deployment.evidence import list_deployment_evidence
    from .operations.memory import list_incidents
    from .intelligence.risk_prediction import predict_risk, risk_prediction_to_dict

    pool = ConnectionPool(dsn_from_env())
    finding_repo = PostgresFindingRepository(pool)
    project_repo = PostgresProjectRepository(pool)
    store = build_state_store(args.db)
    projects = project_repo.list()
    project_ids = [args.project_filter] if getattr(args, "project_filter", None) else None
    wanted_projects = [p for p in projects if project_ids is None or p.id in project_ids]

    deployment_evidence_by_project = {p.id: list_deployment_evidence(store, p.id) for p in wanted_projects}
    incidents_by_project = {p.id: list_incidents(store, p.id) for p in wanted_projects}

    predictions = predict_risk(
        finding_repo, project_repo, project_ids=project_ids,
        deployment_evidence_by_project=deployment_evidence_by_project,
        incidents_by_project=incidents_by_project,
    )
    return {"count": len(predictions), "items": [risk_prediction_to_dict(p) for p in predictions]}


def cmd_risk(args: argparse.Namespace) -> None:
    payload = _build_risk_payload(args)
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    print(f"{payload['count']} project risk prediction(s) (deterministic, no ML):")
    for item in payload["items"]:
        print(f"  {item['project_id']:20s} score={item['score']:.4f} "
              f"horizon={item['risk_horizon']:10s} trend={item['trend']:10s}")
        for factor, entry in item["breakdown"].items():
            print(f"       {factor:28s} weight={entry['weight']:.2f} "
                  f"score={entry['score']:.2f} contribution={entry['contribution']:.4f} "
                  f"raw={entry['raw']}")


def _build_architecture_payload(args: argparse.Namespace) -> dict:
    """Phase 10 Wave 4: architecture intelligence. Calls the SAME
    `analyze_architecture()` the `GET /intelligence/architecture` API
    handler calls - no logic is duplicated here."""
    from .db.postgres import ConnectionPool, PostgresFindingRepository, PostgresProjectRepository
    from .db.state_store_postgres import dsn_from_env
    from .intelligence.architecture import analyze_architecture, architectural_risk_to_dict

    pool = ConnectionPool(dsn_from_env())
    finding_repo = PostgresFindingRepository(pool)
    project_repo = PostgresProjectRepository(pool)
    project_ids = [args.project_filter] if getattr(args, "project_filter", None) else None

    risks = analyze_architecture(finding_repo, project_repo, project_ids=project_ids)
    return {"count": len(risks), "items": [architectural_risk_to_dict(r) for r in risks]}


def cmd_architecture(args: argparse.Namespace) -> None:
    payload = _build_architecture_payload(args)
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    print(f"{payload['count']} architectural risk(s) detected (deterministic, no ML):")
    for item in payload["items"]:
        print(f"  [{item['severity']:8s}] {item['risk_id']:28s} "
              f"projects={item['affected_project_ids']} components={item['affected_components']}")


def _build_security_trends_payload(args: argparse.Namespace) -> dict:
    """Phase 10 Wave 6: security posture trend analysis. Calls the SAME
    `analyze_security_trends()` the `GET /intelligence/security-trends`
    API handler calls - no logic is duplicated here."""
    from .db.postgres import ConnectionPool, PostgresFindingRepository
    from .db.state_store_postgres import dsn_from_env
    from .intelligence.security_trends import analyze_security_trends, security_trend_to_dict

    pool = ConnectionPool(dsn_from_env())
    finding_repo = PostgresFindingRepository(pool)
    project_ids = [args.project_filter] if getattr(args, "project_filter", None) else None

    trends = analyze_security_trends(finding_repo, project_ids=project_ids)
    return {"count": len(trends), "items": [security_trend_to_dict(t) for t in trends]}


def cmd_security_trends(args: argparse.Namespace) -> None:
    payload = _build_security_trends_payload(args)
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    print(f"{payload['count']} security trend(s) (deterministic, no ML):")
    for item in payload["items"]:
        print(f"  {item['project_id']:20s} {item['metric']:24s} trend={item['trend']:10s} "
              f"evidence={item['evidence']}")


def _build_dependency_risk_payload(args: argparse.Namespace) -> dict:
    """Phase 10 Wave 7: dependency/deployment risk forecasting. Calls the
    SAME `forecast_deployment_risk()` the `GET /intelligence/dependency-risk`
    API handler calls - no logic is duplicated here."""
    from .db.postgres import ConnectionPool, PostgresFindingRepository, PostgresProjectRepository
    from .db.state_store_postgres import dsn_from_env
    from .db.factory import build_state_store
    from .deployment.evidence import list_deployment_evidence
    from .intelligence.deployment_risk import deployment_risk_forecast_to_dict, forecast_deployment_risk

    pool = ConnectionPool(dsn_from_env())
    finding_repo = PostgresFindingRepository(pool)
    project_repo = PostgresProjectRepository(pool)
    store = build_state_store(args.db)
    projects = project_repo.list()
    project_ids = [args.project_filter] if getattr(args, "project_filter", None) else None
    wanted_projects = [p for p in projects if project_ids is None or p.id in project_ids]

    deployment_evidence_by_project = {p.id: list_deployment_evidence(store, p.id) for p in wanted_projects}

    forecasts = forecast_deployment_risk(
        finding_repo, project_repo, project_ids=project_ids,
        deployment_evidence_by_project=deployment_evidence_by_project,
    )
    return {"count": len(forecasts), "items": [deployment_risk_forecast_to_dict(f) for f in forecasts]}


def cmd_dependency_risk(args: argparse.Namespace) -> None:
    payload = _build_dependency_risk_payload(args)
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    print(f"{payload['count']} deployment risk forecast(s) (deterministic, no ML):")
    for item in payload["items"]:
        print(f"  {item['project_id']:20s} {item['risk_category']:32s} "
              f"trend={item['trend']:10s} horizon={item['horizon']:10s}")
        print(f"       {item['explanation']}")


def _build_technical_debt_payload(args: argparse.Namespace) -> dict:
    """Phase 10 Wave 8: technical debt intelligence. Calls the SAME
    `analyze_technical_debt()` the `GET /intelligence/technical-debt` API
    handler calls - no logic is duplicated here."""
    from .db.postgres import ConnectionPool, PostgresFindingRepository, PostgresProjectRepository
    from .db.state_store_postgres import dsn_from_env
    from .intelligence.technical_debt import analyze_technical_debt, debt_signal_to_dict

    pool = ConnectionPool(dsn_from_env())
    finding_repo = PostgresFindingRepository(pool)
    project_repo = PostgresProjectRepository(pool)
    project_ids = [args.project_filter] if getattr(args, "project_filter", None) else None

    signals = analyze_technical_debt(finding_repo, project_repo, project_ids=project_ids)
    return {"count": len(signals), "items": [debt_signal_to_dict(s) for s in signals]}


def cmd_technical_debt(args: argparse.Namespace) -> None:
    payload = _build_technical_debt_payload(args)
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    print(f"{payload['count']} technical debt signal(s) (deterministic, no ML):")
    for item in payload["items"]:
        print(f"  [{item['severity']:8s}] {item['debt_signal']:32s} "
              f"project={item['affected_project_id']}")
        print(f"       {item['recommended_action']}")


def _build_cross_project_payload(args: argparse.Namespace) -> dict:
    """Phase 10 Wave 9: cross-project learning. Calls the SAME
    `find_cross_project_insights()` the `GET /intelligence/cross-project`
    API handler calls - no logic is duplicated here."""
    from .db.postgres import (
        ConnectionPool,
        PostgresFindingRepository,
        PostgresMemoryRepository,
        PostgresProjectRepository,
    )
    from .db.state_store_postgres import dsn_from_env
    from .intelligence.cross_project_learning import (
        cross_project_insight_to_dict,
        find_cross_project_insights,
    )

    pool = ConnectionPool(dsn_from_env())
    finding_repo = PostgresFindingRepository(pool)
    project_repo = PostgresProjectRepository(pool)
    memory_repo = PostgresMemoryRepository(pool)
    project_ids = [args.project_filter] if getattr(args, "project_filter", None) else None

    insights = find_cross_project_insights(
        finding_repo, project_repo, memory_repo=memory_repo, project_ids=project_ids,
    )
    return {"count": len(insights), "items": [cross_project_insight_to_dict(i) for i in insights]}


def cmd_cross_project(args: argparse.Namespace) -> None:
    payload = _build_cross_project_payload(args)
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    print(f"{payload['count']} cross-project insight(s) (deterministic, no ML):")
    for item in payload["items"]:
        print(f"  fingerprint={item['fingerprint']!r} projects={item['affected_project_ids']}")
        print(f"       {item['current_evidence_summary']}")
        if item["advisory_context"]:
            print(f"       {item['advisory_context']}")


def _build_ci_clusters_payload(args: argparse.Namespace) -> dict:
    """Phase 10 Wave 11: CI failure clustering. Calls the SAME
    `analyze_ci_clusters()` the `GET /intelligence/ci-clusters` API
    handler calls - no logic is duplicated here."""
    from .intelligence.ci_clustering import analyze_ci_clusters, ci_cluster_result_to_dict

    project_ids = [args.project_filter] if getattr(args, "project_filter", None) else None
    result = analyze_ci_clusters(project_ids=project_ids)
    return ci_cluster_result_to_dict(result)


def cmd_ci_clusters(args: argparse.Namespace) -> None:
    payload = _build_ci_clusters_payload(args)
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    print(f"CI cluster status: {payload['status']}")
    print(f"  {payload['reason']}")


def _build_cost_payload(args: argparse.Namespace) -> dict:
    """Phase 10 Wave 5: cost intelligence. Calls the SAME
    `analyze_cost_intelligence()` the `GET /intelligence/cost` API
    handler calls - no logic is duplicated here."""
    from .db.postgres import ConnectionPool, PostgresFindingRepository
    from .db.state_store_postgres import dsn_from_env
    from .intelligence.cost_intelligence import analyze_cost_intelligence, cost_intelligence_result_to_dict

    pool = ConnectionPool(dsn_from_env())
    finding_repo = PostgresFindingRepository(pool)
    project_ids = [args.project_filter] if getattr(args, "project_filter", None) else None

    result = analyze_cost_intelligence(finding_repo, project_ids=project_ids)
    return cost_intelligence_result_to_dict(result)


def cmd_cost(args: argparse.Namespace) -> None:
    payload = _build_cost_payload(args)
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    print("Cost intelligence (Phase 10 Wave 5 - no real cloud cost data in this environment):")
    for s in payload["signals"]:
        print(f"  [{s['status']}] provider={s['provider']}")
        print(f"       {s['reason']}")
    if payload["waste_signal_findings"]:
        print(f"\n{len(payload['waste_signal_findings'])} advisory waste signal(s) "
              "(derived from infrastructure findings, NOT real cost data):")
        for w in payload["waste_signal_findings"]:
            print(f"  finding={w['finding_id']} project={w['project_id']} resource={w['resource']}")


def _build_remediation_decision_payload(args: argparse.Namespace) -> dict:
    """Phase 10 Wave 10: predictive remediation decision engine. Calls the
    SAME `classify_remediation_batch()` the
    `GET /intelligence/remediation-decision` API handler calls."""
    from .db.postgres import ConnectionPool, PostgresFindingRepository
    from .db.state_store_postgres import dsn_from_env
    from .intelligence.predictive_remediation import classify_remediation_batch, remediation_decision_to_dict
    from .policy import PolicyEngine

    pool = ConnectionPool(dsn_from_env())
    finding_repo = PostgresFindingRepository(pool)
    project_ids = [args.project_filter] if getattr(args, "project_filter", None) else None
    all_findings = finding_repo.list(None, None)
    if project_ids is not None:
        wanted = set(project_ids)
        all_findings = [f for f in all_findings if f.project_id in wanted]

    try:
        policy = PolicyEngine.from_yaml(DEFAULT_POLICY_PATH)
    except Exception:
        policy = None
    skill_registry = None

    decisions = classify_remediation_batch(all_findings, finding_repo, skill_registry=skill_registry,
                                            policy=policy)
    return {"count": len(decisions), "items": [remediation_decision_to_dict(d) for d in decisions]}


def cmd_remediation_decision(args: argparse.Namespace) -> None:
    payload = _build_remediation_decision_payload(args)
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    print(f"{payload['count']} remediation decision(s) (classification only - never executes):")
    for item in payload["items"]:
        print(f"  [{item['decision']:22s}] finding={item['finding_id']}")
        print(f"       {item['explanation']}")


def _build_health_score_payload(args: argparse.Namespace) -> dict:
    """Phase 10 Wave 12: engineering health score (per-project aggregate
    summary - distinct from Wave 2's `patterns` command, which reports
    discrete HealthSignal states). Calls the SAME
    `compute_engineering_health()` the `GET /intelligence/health-score`
    API handler calls."""
    from .db.postgres import ConnectionPool, PostgresFindingRepository, PostgresProjectRepository
    from .db.state_store_postgres import dsn_from_env
    from .intelligence.engineering_health_score import (
        compute_engineering_health,
        engineering_health_summary_to_dict,
    )

    pool = ConnectionPool(dsn_from_env())
    finding_repo = PostgresFindingRepository(pool)
    project_repo = PostgresProjectRepository(pool)
    project_ids = [args.project_filter] if getattr(args, "project_filter", None) else None

    summaries = compute_engineering_health(finding_repo, project_repo, project_ids=project_ids)
    return {"count": len(summaries), "items": [engineering_health_summary_to_dict(s) for s in summaries]}


def cmd_health_score(args: argparse.Namespace) -> None:
    payload = _build_health_score_payload(args)
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    print(f"{payload['count']} project engineering health summary(ies):")
    for item in payload["items"]:
        print(f"  project={item['project_id']:20s} overall_state={item['overall_state']:10s} "
              f"score={item['overall_score']}")
        for name, v in item["subsystem_states"].items():
            print(f"       {name:18s} {v['state']:9s} {v['evidence']}")


def cmd_patterns(args: argparse.Namespace) -> None:
    payload = _build_patterns_payload(args)
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    print(f"{len(payload['patterns'])} cross-project incident pattern(s) detected:")
    for p in payload["patterns"]:
        print(f"  fingerprint={p['fingerprint']!r} category={p['category']} "
              f"occurrences={p['occurrence_count']} projects={p['affected_project_ids']}")
    print(f"\n{len(payload['health_signals'])} engineering health signal(s):")
    for s in payload["health_signals"]:
        print(f"  [{s['state']:9s}] {s['signal_id']:28s} severity={s['severity']:8s} "
              f"projects={s['affected_projects']} - {s['explanation']}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="aep")
    parser.add_argument("--db", default="aep_state.db")
    parser.add_argument("--policy", default=DEFAULT_POLICY_PATH)
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

    p_ops = sub.add_parser("operations-status",
                            help="operational incident history for a project (Phase 7)")
    p_ops.add_argument("--project", required=True)
    p_ops.add_argument("--json", action="store_true")
    p_ops.set_defaults(func=cmd_operations_status)

    p_incident = sub.add_parser("incident-status",
                                 help="advisory lookup of prior incidents matching one "
                                      "correlation fingerprint (Phase 7 Part 9)")
    p_incident.add_argument("--project", required=True)
    p_incident.add_argument("--fingerprint", required=True)
    p_incident.add_argument("--json", action="store_true")
    p_incident.set_defaults(func=cmd_incident_status)

    p_verify = sub.add_parser("verify-phase")
    p_verify.add_argument("--phase", type=int, required=True)
    p_verify.add_argument("--by", default="operator")
    p_verify.set_defaults(func=cmd_verify_phase)

    p_rt_start = sub.add_parser("runtime-start",
                                 help="Phase 8: run a controlled/bounded autonomous runtime session")
    p_rt_start.add_argument("--project", required=True)
    p_rt_start.add_argument("--repo", default=None)
    p_rt_start.add_argument("--workers", type=int, default=2)
    p_rt_start.add_argument("--cycles", type=int, default=1)
    p_rt_start.add_argument("--max-seconds", type=float, default=None)
    p_rt_start.add_argument("--interval", type=float, default=3600.0)
    p_rt_start.add_argument("--json", action="store_true")
    p_rt_start.set_defaults(func=cmd_runtime_start)

    p_rt_status = sub.add_parser("runtime-status", help="Phase 8: live runtime operational status")
    p_rt_status.add_argument("--supervisor", default=None)
    p_rt_status.add_argument("--json", action="store_true")
    p_rt_status.set_defaults(func=cmd_runtime_status)

    p_rt_stop = sub.add_parser("runtime-stop", help="Phase 8: graceful worker shutdown signal")
    p_rt_stop.add_argument("--supervisor", required=True)
    p_rt_stop.set_defaults(func=cmd_runtime_stop)

    p_rt_workers = sub.add_parser("runtime-workers", help="Phase 8: list registered runtime workers")
    p_rt_workers.add_argument("--supervisor", default=None)
    p_rt_workers.add_argument("--json", action="store_true")
    p_rt_workers.set_defaults(func=cmd_runtime_workers)

    p_rt_jobs = sub.add_parser("runtime-jobs", help="Phase 8: list durable scheduled jobs")
    p_rt_jobs.add_argument("--json", action="store_true")
    p_rt_jobs.set_defaults(func=cmd_runtime_jobs)

    p_rt_recover = sub.add_parser("runtime-recover", help="Phase 8: crash/startup recovery pass")
    p_rt_recover.add_argument("--supervisor", default=None)
    p_rt_recover.add_argument("--json", action="store_true")
    p_rt_recover.set_defaults(func=cmd_runtime_recover)

    # ---- Skills registry (Phase 9 Stage B, Part 20) ------------------------
    p_skills = sub.add_parser("skills", help="Phase 9 Stage B: canonical AEP skill registry")
    skills_sub = p_skills.add_subparsers(dest="skills_command", required=True)

    def _add_backend_arg(p):
        p.add_argument("--backend", dest="skills_backend", default=None,
                        choices=["postgres", "fake"],
                        help="skill registry storage backend (default: postgres)")
        p.add_argument("--json", action="store_true")

    p_sk_list = skills_sub.add_parser("list", help="list every registered skill and its latest published version")
    _add_backend_arg(p_sk_list)
    p_sk_list.add_argument("--seed", action="store_true",
                            help="seed the 18 canonical skill definitions first (idempotent)")
    p_sk_list.set_defaults(func=cmd_skills_list)

    p_sk_show = skills_sub.add_parser("show", help="show one skill version's full definition")
    _add_backend_arg(p_sk_show)
    p_sk_show.add_argument("skill_id")
    p_sk_show.add_argument("--version", default=None, help="defaults to the latest published version")
    p_sk_show.add_argument("--seed", action="store_true", help="seed canonical skills first (idempotent)")
    p_sk_show.set_defaults(func=cmd_skills_show)

    p_sk_versions = skills_sub.add_parser("versions", help="list every version of one skill")
    _add_backend_arg(p_sk_versions)
    p_sk_versions.add_argument("skill_id")
    p_sk_versions.add_argument("--seed", action="store_true", help="seed canonical skills first (idempotent)")
    p_sk_versions.set_defaults(func=cmd_skills_versions)

    p_sk_validate = skills_sub.add_parser("validate", help="self-validate every registered skill version "
                                                             "(tools/checks/policy actions/dependencies)")
    _add_backend_arg(p_sk_validate)
    p_sk_validate.add_argument("--seed", action="store_true",
                                help="seed the 18 canonical skill definitions first (idempotent)")
    p_sk_validate.set_defaults(func=cmd_skills_validate)

    p_sk_project = skills_sub.add_parser("project", help="deterministically project a skill version "
                                                           "to the Claude-compatible skill format")
    _add_backend_arg(p_sk_project)
    p_sk_project.add_argument("skill_id")
    p_sk_project.add_argument("--version", default=None, help="defaults to the latest published version")
    p_sk_project.add_argument("--markdown", action="store_true", help="render the SKILL.md-shaped artifact instead of JSON")
    p_sk_project.add_argument("--seed", action="store_true", help="seed canonical skills first (idempotent)")
    p_sk_project.set_defaults(func=cmd_skills_project)

    p_providers = sub.add_parser("providers", help="Stage C: list registered AI providers/models, "
                                                     "default/fallback, and OmniRoute reachability")
    p_providers.add_argument("--json", action="store_true")
    p_providers.set_defaults(func=cmd_providers)

    p_demo = sub.add_parser("demo", help="Stage C: reproducible end-to-end demo flow (docs/DEMO.md)")
    demo_sub = p_demo.add_subparsers(dest="demo_command", required=True)

    p_demo_run = demo_sub.add_parser("run", help="run the real demo scenario end to end")
    p_demo_run.add_argument("--scenario", choices=["happy", "ambiguous"], default="happy",
                             help="'happy' runs the full fix-bug/security/persist flow; "
                                  "'ambiguous' demonstrates refusal/clarification-request on an "
                                  "under-specified request instead of executing anything")
    p_demo_run.add_argument("--work-dir", default=None,
                             help="temp directory to materialize the demo fixture into "
                                  "(default: /tmp/aep_demo_run)")
    p_demo_run.add_argument("--db-backend", choices=["postgres", "sqlite"], default="postgres")
    p_demo_run.set_defaults(func=cmd_demo_run)

    p_demo_readiness = demo_sub.add_parser("readiness", help="deterministic DEMO READINESS checklist "
                                                              "(a checklist, not a percentage)")
    p_demo_readiness.set_defaults(func=cmd_demo_readiness)

    p_prioritize = sub.add_parser("prioritize", help="Phase 10 Wave 1: deterministic cross-project "
                                                       "finding prioritization (real Postgres)")
    p_prioritize.add_argument("--project", dest="project_filter", default=None,
                               help="restrict ranking to a single project id (default: all projects)")
    p_prioritize.add_argument("--json", action="store_true")
    p_prioritize.set_defaults(func=cmd_prioritize)

    p_patterns = sub.add_parser("intelligence", help="Phase 10 Wave 2: incident-pattern / "
                                                       "engineering-health intelligence")
    patterns_sub = p_patterns.add_subparsers(dest="intelligence_command", required=True)
    p_patterns_cmd = patterns_sub.add_parser("patterns", help="detected cross-project incident "
                                                                "patterns + engineering health signals")
    p_patterns_cmd.add_argument("--project", dest="project_filter", default=None,
                                 help="restrict to a single project id (default: all projects)")
    p_patterns_cmd.add_argument("--json", action="store_true")
    p_patterns_cmd.set_defaults(func=cmd_patterns)

    p_risk_cmd = patterns_sub.add_parser("risk", help="Phase 10 Wave 3: evidence-based predictive "
                                                        "risk intelligence, per project")
    p_risk_cmd.add_argument("--project", dest="project_filter", default=None,
                             help="restrict to a single project id (default: all projects)")
    p_risk_cmd.add_argument("--json", action="store_true")
    p_risk_cmd.set_defaults(func=cmd_risk)

    p_arch_cmd = patterns_sub.add_parser("architecture", help="Phase 10 Wave 4: deterministic "
                                                                "architecture intelligence")
    p_arch_cmd.add_argument("--project", dest="project_filter", default=None,
                             help="restrict to a single project id (default: all projects)")
    p_arch_cmd.add_argument("--json", action="store_true")
    p_arch_cmd.set_defaults(func=cmd_architecture)

    p_sectrend_cmd = patterns_sub.add_parser("security-trends", help="Phase 10 Wave 6: deterministic "
                                                                       "security posture trend analysis")
    p_sectrend_cmd.add_argument("--project", dest="project_filter", default=None,
                                 help="restrict to a single project id (default: all projects + overall)")
    p_sectrend_cmd.add_argument("--json", action="store_true")
    p_sectrend_cmd.set_defaults(func=cmd_security_trends)

    p_deprisk_cmd = patterns_sub.add_parser("dependency-risk", help="Phase 10 Wave 7: deterministic "
                                                                       "dependency/deployment risk forecasting")
    p_deprisk_cmd.add_argument("--project", dest="project_filter", default=None,
                                help="restrict to a single project id (default: all projects)")
    p_deprisk_cmd.add_argument("--json", action="store_true")
    p_deprisk_cmd.set_defaults(func=cmd_dependency_risk)

    p_debt_cmd = patterns_sub.add_parser("technical-debt", help="Phase 10 Wave 8: deterministic "
                                                                   "technical debt intelligence")
    p_debt_cmd.add_argument("--project", dest="project_filter", default=None,
                             help="restrict to a single project id (default: all projects)")
    p_debt_cmd.add_argument("--json", action="store_true")
    p_debt_cmd.set_defaults(func=cmd_technical_debt)

    p_crossproj_cmd = patterns_sub.add_parser("cross-project", help="Phase 10 Wave 9: cross-project "
                                                                       "learning (advisory memory context)")
    p_crossproj_cmd.add_argument("--project", dest="project_filter", default=None,
                                  help="restrict to a single project id (default: all projects)")
    p_crossproj_cmd.add_argument("--json", action="store_true")
    p_crossproj_cmd.set_defaults(func=cmd_cross_project)

    p_ci_cmd = patterns_sub.add_parser("ci", help="Phase 10 Wave 11: CI failure clustering "
                                                     "(reports NOT_IMPLEMENTED - no CI-run data in schema)")
    p_ci_cmd.add_argument("--project", dest="project_filter", default=None,
                           help="restrict to a single project id (default: all projects)")
    p_ci_cmd.add_argument("--json", action="store_true")
    p_ci_cmd.set_defaults(func=cmd_ci_clusters)

    p_cost_cmd = patterns_sub.add_parser("cost", help="Phase 10 Wave 5: cost intelligence "
                                                         "(reports BLOCKED per provider - no real cloud "
                                                         "cost/billing data in this environment)")
    p_cost_cmd.add_argument("--project", dest="project_filter", default=None,
                             help="restrict to a single project id (default: all projects)")
    p_cost_cmd.add_argument("--json", action="store_true")
    p_cost_cmd.set_defaults(func=cmd_cost)

    p_remdec_cmd = patterns_sub.add_parser("remediation-decision", help="Phase 10 Wave 10: predictive "
                                                                          "remediation decision classification "
                                                                          "(classifies only - never executes)")
    p_remdec_cmd.add_argument("--project", dest="project_filter", default=None,
                               help="restrict to a single project id (default: all projects)")
    p_remdec_cmd.add_argument("--json", action="store_true")
    p_remdec_cmd.set_defaults(func=cmd_remediation_decision)

    p_healthscore_cmd = patterns_sub.add_parser("health-score", help="Phase 10 Wave 12: per-project "
                                                                        "engineering health score (aggregate "
                                                                        "summary - distinct from 'patterns', "
                                                                        "which reports discrete Wave 2 health "
                                                                        "signal states)")
    p_healthscore_cmd.add_argument("--project", dest="project_filter", default=None,
                                    help="restrict to a single project id (default: all projects)")
    p_healthscore_cmd.add_argument("--json", action="store_true")
    p_healthscore_cmd.set_defaults(func=cmd_health_score)

    p_scan = sub.add_parser("scan", help="analyze a project: auto-detects what the repository "
                                          "is and runs only the applicable checks (read-only)")
    p_scan.add_argument("path", nargs="?", default=".",
                         help="path to the repository to analyze (default: current directory)")
    p_scan.add_argument("--json", action="store_true", help="machine-readable output")
    p_scan.set_defaults(func=cmd_scan)

    p_start = sub.add_parser("start", help="one-command local product: local database + "
                                            "migrations + API + packaged UI, then print the URL")
    p_start.add_argument("--host", default="127.0.0.1")
    p_start.add_argument("--port", type=int, default=0,
                          help="0 (default) = let the OS pick a free port")
    p_start.add_argument("--db-backend", default=None)
    p_start.set_defaults(func=cmd_start)

    # Bare `aep` with no subcommand IS the product's start command - the
    # one-command UX. Any actual subcommand behaves exactly as before.
    args = parser.parse_args(argv if argv is not None or len(sys.argv) > 1 else ["start"])
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
