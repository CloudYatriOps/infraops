"""Real dependency/CVE intelligence agent (Phase 3 Part A/B).

Pipeline per the Phase 3 spec: DISCOVER -> UNDERSTAND -> REMEDIATE -> TEST ->
RESCAN -> PR -> CI -> VERIFY. This agent owns DISCOVER/UNDERSTAND/REMEDIATE/
RESCAN (its four `mode`s below); TEST/PR/CI reuse the *existing*
TestingAgent and GitHub push/PR/monitor machinery unmodified
(`dependency/planner.py` wires them together) - nothing here reimplements
git, GitHub, or test execution.

Verification discipline (Phase 3 Part B): a finding is only ever reported
resolved after `mode="rescan"` runs the *same real scanner* again and
confirms the finding is actually gone. Nothing here trusts a version bump
just because it "should" fix the CVE - see ARCHITECTURE.md §14, extended
here from code fixes to dependency remediation.

Ambiguous/unsafe cases (no published fix, unparseable versions, or a
scanner ecosystem this sandbox can't run) are never guessed at: they become
a `dependency_escalate` follow-up task, which always terminates as
FailureClass.HUMAN_REQUIRED - a durable, queryable "this needs a human"
signal, the same shape MonitorCIAgent already uses when a CI loop exhausts
its attempts.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from ..dependency.inventory import build_inventory
from ..dependency.manifest_writer import apply_plan
from ..dependency.models import Ecosystem
from ..dependency.planner import build_remediation_chain
from ..dependency.remediation import plan_remediations
from ..models import Evidence, FailureClass, PolicyDecisionType, Task, TaskResult
from .base import Agent, AgentContext


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DependencyCVEAgent:
    name = "dependency_cve_agent"
    required_capabilities = {
        "filesystem.read", "filesystem.write", "filesystem.list",
        "shell.run", "git.branch", "git.commit", "git.current_branch",
    }

    def run(self, task: Task, ctx: AgentContext) -> TaskResult:
        mode = task.payload.get("mode", "scan")
        if mode == "scan":
            return self._scan(task, ctx)
        if mode == "remediate":
            return self._remediate(task, ctx)
        if mode == "rescan":
            return self._rescan(task, ctx)
        if mode == "escalate":
            return self._escalate(task, ctx)
        raise ValueError(f"unknown dependency_cve_agent mode: {mode!r}")

    # Every scanner subprocess is routed through the existing
    # capability-scoped, audited shell tool - no scanner module in
    # `dependency/scanners/` ever calls subprocess directly.
    def _run_shell(self, ctx: AgentContext, task: Task, project_root: str):
        def run(args, cwd=None, timeout=60):
            try:
                return ctx.tools.call("shell.run", task_id=task.id, args=args,
                                       cwd=cwd or project_root, timeout=timeout)
            except Exception as e:  # noqa: BLE001 - availability probes must not crash the scan
                return {"ok": False, "exit_code": -1, "stdout": "", "stderr": str(e), "args": args}
        return run

    # ---- DISCOVER + UNDERSTAND ---------------------------------------
    def _scan(self, task: Task, ctx: AgentContext) -> TaskResult:
        project_root = task.payload["project_root"]
        run_shell = self._run_shell(ctx, task, project_root)
        inventory = build_inventory(project_root, run_shell)

        evidence: list[Evidence] = []
        for record in inventory.scan_records:
            evidence.append(Evidence(
                source=f"dependency_scan:{record.scanner}", captured_at=record.scanned_at,
                exit_code=record.exit_code,
                summary=f"{record.manifest_path} ({record.ecosystem.value}): "
                        f"{record.finding_count} finding(s) via {record.scanner} "
                        f"{record.scanner_version}"
                        + ("; " + "; ".join(f"{f.package} {f.installed_version} [{f.id}]"
                                             for f in record.findings) if record.findings else ""),
            ))
        for skipped in inventory.unscanned:
            evidence.append(Evidence(
                source="dependency_scan:skipped", captured_at=_now(), exit_code=0,
                summary=f"{skipped['manifest']} ({skipped['ecosystem']}): not scanned - "
                        f"{skipped['reason']}",
            ))

        findings = inventory.findings
        if not findings:
            evidence.append(Evidence(source="dependency_scan", captured_at=_now(), exit_code=0,
                                      summary="no vulnerable dependencies found in any scanned "
                                              "manifest"))
            return TaskResult(success=True, evidence=evidence, message="dependency scan clean")

        plans = plan_remediations(findings)
        safe_plans = [p for p in plans if p.safe]
        unsafe_plans = [p for p in plans if not p.safe]

        # Avoid blind upgrades: a major-version-bump plan is still routed
        # through the *existing* policy engine (src/aep/config/policy.yaml already
        # has a `dependency.upgrade` / major_version_bump rule from Phase 1)
        # before it's allowed to proceed automatically.
        major_bumps = [p for p in safe_plans if p.major_version_bump]
        if major_bumps:
            decision = ctx.policy.evaluate("dependency.upgrade", {"major_version_bump": True})
            evidence.append(Evidence(
                source="policy", captured_at=_now(),
                exit_code=1 if decision.decision == PolicyDecisionType.DENY else 0,
                summary=f"{len(major_bumps)} planned upgrade(s) include a major version bump "
                        f"({[p.package for p in major_bumps]}): {decision.decision.value} - "
                        f"{decision.reason}",
            ))
            if decision.decision == PolicyDecisionType.DENY:
                unsafe_plans = unsafe_plans + major_bumps
                safe_plans = [p for p in safe_plans if not p.major_version_bump]

        follow_ups: list[Task] = []
        if safe_plans:
            plans_payload = [p.to_dict() for p in safe_plans]
            branch_name = task.payload.get("branch_name") or f"aep/dep-fix-{task.id[:8]}"
            has_github_target = bool(task.payload.get("remote_url")
                                      or (task.payload.get("owner") and task.payload.get("repo")))
            follow_ups.extend(build_remediation_chain(
                project_id=task.project_id, project_root=project_root, branch_name=branch_name,
                plans_payload=plans_payload,
                owner=task.payload.get("owner"), repo=task.payload.get("repo"),
                remote_url=task.payload.get("remote_url"),
                base_branch=task.payload.get("base_branch", "main"),
                include_github=has_github_target,
                max_ci_loops=task.payload.get("max_ci_loops", 3),
            ))
            evidence.append(Evidence(
                source="dependency_remediation_plan", captured_at=_now(), exit_code=0,
                summary=f"planned safe upgrade(s) for {[p.package for p in safe_plans]}; "
                        f"scheduled remediate -> test -> rescan"
                        + (" -> push -> PR -> CI" if has_github_target else "")
                        + " chain",
            ))

        for plan in unsafe_plans:
            follow_ups.append(Task(
                id=str(uuid.uuid4()), type="dependency_escalate", project_id=task.project_id,
                owner_agent="dependency_cve_agent", max_attempts=1,
                payload={"mode": "escalate", "plan": plan.to_dict()},
            ))

        return TaskResult(
            success=True, evidence=evidence,
            message=f"{len(findings)} finding(s) across {len(inventory.scan_records)} scanned "
                    f"manifest(s); {len(safe_plans)} safe upgrade(s) planned, "
                    f"{len(unsafe_plans)} escalated for human review",
            follow_up_tasks=follow_ups,
        )

    # ---- REMEDIATE -----------------------------------------------------
    def _remediate(self, task: Task, ctx: AgentContext) -> TaskResult:
        project_root = task.payload["project_root"]
        branch_name = task.payload["branch_name"]
        plans: list[dict] = task.payload["plans"]

        decision = ctx.policy.evaluate("git.branch", {"branch": branch_name})
        if decision.decision == PolicyDecisionType.DENY:
            return TaskResult(success=False, failure_class=FailureClass.SECURITY,
                               message=f"policy denied branch creation: {decision.reason}")

        branch_result = ctx.tools.call("git.branch", task_id=task.id, repo_path=project_root,
                                        branch_name=branch_name)
        evidence = [Evidence(source="git.branch", captured_at=_now(),
                              exit_code=0 if branch_result["ok"] else 1,
                              summary=(branch_result.get("stdout") or "")[:300])]
        if not branch_result["ok"]:
            return TaskResult(success=False, evidence=evidence, failure_class=FailureClass.TOOL,
                               message=f"could not create/checkout branch {branch_name}")

        by_manifest: dict[str, list[dict]] = {}
        for p in plans:
            by_manifest.setdefault(p["manifest_path"], []).append(p)

        applied: list[dict] = []
        for manifest_path, manifest_plans in by_manifest.items():
            read = ctx.tools.call("filesystem.read", task_id=task.id,
                                   project_root=project_root, path=manifest_path)
            if not read["ok"]:
                return TaskResult(success=False, evidence=evidence, failure_class=FailureClass.CODE,
                                   message=f"could not read manifest {manifest_path}: "
                                           f"{read.get('error')}")
            content = read["content"]
            for p in manifest_plans:
                try:
                    content = apply_plan(content, Ecosystem(p["ecosystem"]), p)
                except (ValueError, NotImplementedError) as e:
                    return TaskResult(success=False, evidence=evidence, failure_class=FailureClass.CODE,
                                       message=f"remediation edit failed for {p['package']}: {e}")
                applied.append(p)
            ctx.tools.call("filesystem.write", task_id=task.id, project_root=project_root,
                            path=manifest_path, content=content)

        commit_msg = "aep: security fix - " + ", ".join(
            f"{p['package']} {p['from_version']}->{p['to_version']}" for p in applied)
        commit_result = ctx.tools.call("git.commit", task_id=task.id, repo_path=project_root,
                                        message=commit_msg[:200])
        evidence.append(Evidence(source="git.commit", captured_at=_now(),
                                  exit_code=0 if commit_result["ok"] else 1,
                                  summary=(commit_result.get("stdout") or "")[:300]))
        for p in applied:
            evidence.append(Evidence(
                source="dependency_remediation", captured_at=_now(), exit_code=0,
                summary=f"{p['package']}: {p['from_version']} -> {p['to_version']} "
                        f"(resolves {', '.join(p['finding_ids'])})",
            ))

        # Bumping the manifest text alone doesn't change what's actually
        # importable when run_tests executes next - without this, tests
        # would keep running against the OLD installed version regardless
        # of what the manifest now says, which would make "run tests" a
        # meaningless check. Skippable via payload for fast, offline unit
        # tests of the remediation logic itself (see tests/test_dependency_*).
        if not task.payload.get("skip_install", False) and commit_result["ok"]:
            evidence.extend(self._install_upgraded_packages(ctx, task, project_root, applied))

        return TaskResult(
            success=commit_result["ok"], evidence=evidence,
            message=f"applied {len(applied)} dependency upgrade(s) on branch {branch_name}",
            failure_class=None if commit_result["ok"] else FailureClass.TOOL,
        )

    def _install_upgraded_packages(self, ctx: AgentContext, task: Task, project_root: str,
                                    applied: list[dict]) -> list[Evidence]:
        """Actually installs the upgraded version so the next run_tests step
        exercises the NEW code, not the old one - real `pip`/`npm install`,
        not a claim that the bump "should" work."""
        ev: list[Evidence] = []
        for p in applied:
            eco = Ecosystem(p["ecosystem"])
            if eco == Ecosystem.PYTHON:
                result = ctx.tools.call(
                    "shell.run", task_id=task.id, cwd=project_root, timeout=120,
                    args=["python3", "-m", "pip", "install", "--break-system-packages", "--quiet",
                          f"{p['package']}=={p['to_version']}"],
                )
                ev.append(Evidence(
                    source="pip.install", captured_at=_now(), exit_code=result.get("exit_code", -1),
                    summary=f"installed {p['package']}=={p['to_version']}: "
                            + ("ok" if result.get("ok") else (result.get("stderr") or "")[:200]),
                ))
            elif eco == Ecosystem.NODE:
                manifest_dir = str(Path(project_root, p["manifest_path"]).parent)
                result = ctx.tools.call(
                    "shell.run", task_id=task.id, cwd=manifest_dir, timeout=180,
                    args=["npm", "install", f"{p['package']}@{p['to_version']}"],
                )
                ev.append(Evidence(
                    source="npm.install", captured_at=_now(), exit_code=result.get("exit_code", -1),
                    summary=f"installed {p['package']}@{p['to_version']}: "
                            + ("ok" if result.get("ok") else (result.get("stderr") or "")[:200]),
                ))
        return ev

    # ---- RESCAN / VERIFY ------------------------------------------------
    def _rescan(self, task: Task, ctx: AgentContext) -> TaskResult:
        project_root = task.payload["project_root"]
        plans: list[dict] = task.payload["plans"]
        run_shell = self._run_shell(ctx, task, project_root)

        touched_manifests = {p["manifest_path"] for p in plans}
        inventory = build_inventory(project_root, run_shell,
                                     manifest_filter=lambda m: m.path in touched_manifests)

        current_findings = inventory.findings
        still_vulnerable: list[dict] = []
        resolved: list[dict] = []
        for p in plans:
            hit = next((f for f in current_findings
                        if f.package == p["package"]
                        and (f.id in p["finding_ids"] or f.installed_version == p["from_version"])),
                       None)
            (still_vulnerable if hit else resolved).append(p)

        evidence = [Evidence(
            source=f"dependency_rescan:{record.scanner}", captured_at=record.scanned_at,
            exit_code=record.exit_code,
            summary=f"{record.manifest_path}: {record.finding_count} finding(s) reported on the "
                    f"post-remediation scan",
        ) for record in inventory.scan_records]

        if still_vulnerable:
            evidence.append(Evidence(
                source="dependency_rescan", captured_at=_now(), exit_code=1,
                summary=f"NOT resolved: {[p['package'] for p in still_vulnerable]} - the second, "
                        f"real scan still reports the finding; refusing to claim this is fixed",
            ))
            return TaskResult(
                success=False, evidence=evidence, failure_class=FailureClass.CODE,
                message=f"post-remediation scan still shows "
                        f"{[p['package'] for p in still_vulnerable]} vulnerable; the upgrade did "
                        f"not resolve the finding as expected",
            )

        evidence.append(Evidence(
            source="dependency_rescan", captured_at=_now(), exit_code=0,
            summary=f"CONFIRMED resolved by a second, independent scan: "
                    f"{[p['package'] for p in resolved]}",
        ))
        return TaskResult(
            success=True, evidence=evidence,
            message=f"verified {[p['package'] for p in resolved]} no longer reported vulnerable",
        )

    # ---- ESCALATE --------------------------------------------------------
    def _escalate(self, task: Task, ctx: AgentContext) -> TaskResult:
        plan = task.payload["plan"]
        return TaskResult(
            success=False, failure_class=FailureClass.HUMAN_REQUIRED,
            evidence=[Evidence(
                source="dependency_remediation_escalation", captured_at=_now(), exit_code=1,
                summary=f"{plan['package']} {plan['from_version']}: {plan['reason']} "
                        f"(finding(s): {', '.join(plan['finding_ids'])})",
            )],
            message=f"no safe automated remediation for {plan['package']}: {plan['reason']}",
        )
