"""InfrastructureIntelligenceAgent (Phase 5 Part 11).

discover -> inventory -> analyze -> prioritize -> plan -> remediate ->
validate -> security scan -> evidence -> PR, built entirely on the
EXISTING orchestrator and task graph (Part 11: "Do not create an
independent orchestration system"). Same four-mode shape as
`DependencyCVEAgent` (Phase 3) and `SecurityAgent` (Phase 4) -
`scan`/`remediate`/`rescan`/`escalate` - because the pipeline shape is the
same and a third variation would be a third thing to reason about.

Two things distinguish this agent from Phase 4's:

1. **Validation is a first-class step, and a blocked validator never
   counts as a pass.** `_remediate` runs `infra/validation.py` after
   every change and, per Part 10, refuses to report success when no
   validator could run. In THIS environment that matters constantly:
   `terraform fmt`/`terraform validate`/`helm lint`/`helm template` are
   all BLOCKED, so a Terraform remediation is validated only by the HCL2
   structural parse, and the evidence says exactly that rather than
   implying `terraform validate` passed.

2. **Risk-based prioritization drives what gets fixed automatically.**
   Findings are scored by `infra/risk.py` (environment x blast radius x
   exploitability) and the *priority* severity - not the raw scanner
   severity - is what the policy engine evaluates. A HIGH finding in
   production with cluster-wide blast radius is escalated like a CRITICAL,
   which is the entire point of Part 8's weighting.

Live infrastructure is never touched. This agent has no capability that
could apply Terraform or reach a cluster; the only mutations it makes are
to files in a git working tree, on a branch, behind the existing PR flow.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from ..infra import remediation as infra_remediation
from ..infra.discovery import discover_infrastructure
from ..infra.planner import build_infra_remediation_chain
from ..infra.risk import prioritize
from ..infra.scan_runner import run_infrastructure_scan
from ..infra.validation import (
    summarize, validate_helm_chart, validate_kubernetes_manifest, validate_terraform_change,
)
from ..models import Evidence, FailureClass, PolicyDecisionType, Task, TaskResult
from ..security.models import SecuritySeverity
from .base import Agent, AgentContext


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_file(project_root: str, relative_path: str, run_shell) -> list:
    """Dispatches to the right validator set for a file type. A file this
    platform has no validator for returns an empty list, which
    `summarize()` correctly reports as "nothing ran" rather than "passed"."""
    lowered = relative_path.lower()
    if lowered.endswith(".tf"):
        return validate_terraform_change(project_root, relative_path, run_shell)
    if lowered.endswith((".yaml", ".yml")):
        return [validate_kubernetes_manifest(project_root, relative_path)]
    return []


class InfrastructureIntelligenceAgent:
    name = "infrastructure_intelligence_agent"
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
        raise ValueError(f"unknown infrastructure_intelligence_agent mode: {mode!r}")

    def _run_shell(self, ctx: AgentContext, task: Task, project_root: str):
        def run(args, cwd=None, timeout=180):
            try:
                return ctx.tools.call("shell.run", task_id=task.id, args=args,
                                       cwd=cwd or project_root, timeout=timeout)
            except Exception as e:  # noqa: BLE001 - availability probes must not crash a scan
                return {"ok": False, "exit_code": -1, "stdout": "", "stderr": str(e), "args": args}
        return run

    # ---- DISCOVER + INVENTORY + ANALYZE + PRIORITIZE + PLAN -------------
    def _scan(self, task: Task, ctx: AgentContext) -> TaskResult:
        project_root = task.payload["project_root"]
        run_shell = self._run_shell(ctx, task, project_root)

        inventory = discover_infrastructure(project_root)
        evidence = [Evidence(
            source="infra_inventory", captured_at=_now(), exit_code=0,
            summary=f"{len(inventory.assets)} asset(s); kinds="
                    f"{sorted(k.value for k in inventory.kinds)}; providers="
                    f"{sorted(inventory.provider_hints)}",
        )]
        if not inventory.assets:
            evidence.append(Evidence(source="infra_scan", captured_at=_now(), exit_code=0,
                                      summary="no infrastructure assets found - nothing to scan"))
            return TaskResult(success=True, evidence=evidence,
                               message="no infrastructure discovered in this repository")

        scan_result = run_infrastructure_scan(project_root, run_shell)
        for record in scan_result.records:
            if record.availability.value != "AVAILABLE":
                evidence.append(Evidence(
                    source=f"infra_scan:{record.scanner}", captured_at=record.scanned_at,
                    exit_code=0,
                    summary=f"{record.category.value}: {record.availability.value} - "
                            f"{record.note[:400]}",
                ))
                continue
            evidence.append(Evidence(
                source=f"infra_scan:{record.scanner}", captured_at=record.scanned_at,
                exit_code=record.exit_code,
                summary=f"{record.category.value}: {record.finding_count} finding(s) via "
                        f"{record.scanner} {record.scanner_version}",
            ))

        findings = scan_result.findings
        if not findings:
            evidence.append(Evidence(source="infra_scan", captured_at=_now(), exit_code=0,
                                      summary="no infrastructure findings across any available "
                                              "scanner"))
            return TaskResult(success=True, evidence=evidence, message="infrastructure scan clean")

        # PRIORITIZE (Part 8): environment comes from the discovery
        # inventory, so risk weighting is grounded in what was actually
        # found rather than assumed.
        environment_for = {asset.path: asset.environment for asset in inventory.assets}
        scored = prioritize(findings, environment_for)
        evidence.append(Evidence(
            source="infra_risk", captured_at=_now(), exit_code=0,
            summary="top risks: " + "; ".join(
                f"{s.finding_id} score={s.score} {s.base_severity}->{s.priority_severity} "
                f"({s.blast_radius}/{s.exploitability})" for _, s in scored[:5]),
        ))

        safe: list[dict] = []
        escalate: list[dict] = []
        for finding, score in scored:
            # The PRIORITY severity (risk-adjusted), not the raw scanner
            # severity, is what policy sees - that is what makes Part 8's
            # production weighting actually change behavior.
            decision = ctx.policy.evaluate("infra.finding",
                                            {"severity": score.priority_severity})
            if decision.decision == PolicyDecisionType.DENY:
                escalate.append({"finding": finding.to_dict(), "risk": score.to_dict(),
                                  "reason": f"policy DENY for priority severity "
                                            f"{score.priority_severity}: {decision.reason}"})
                continue
            if (decision.decision == PolicyDecisionType.ALLOW
                    and finding.severity in (SecuritySeverity.LOW, SecuritySeverity.INFO)):
                continue  # tracked in evidence above, never auto-remediated

            if not infra_remediation.can_remediate(finding):
                escalate.append({"finding": finding.to_dict(), "risk": score.to_dict(),
                                  "reason": "no deterministic, verified-shape fix exists for "
                                            f"{finding.rule_id} - Part 9 requires ambiguous "
                                            f"IAM/network changes to go to a human"})
                continue
            if not finding.file:
                escalate.append({"finding": finding.to_dict(), "risk": score.to_dict(),
                                  "reason": "finding has no file to remediate"})
                continue
            read = ctx.tools.call("filesystem.read", task_id=task.id, project_root=project_root,
                                   path=finding.file)
            if not read.get("ok"):
                escalate.append({"finding": finding.to_dict(), "risk": score.to_dict(),
                                  "reason": f"could not read {finding.file}: {read.get('error')}"})
                continue
            plan = infra_remediation.plan_for(finding, read["content"])
            if plan is None:
                escalate.append({"finding": finding.to_dict(), "risk": score.to_dict(),
                                  "reason": f"{finding.rule_id} did not match the verified "
                                            f"structural shape its fixer requires - refusing to "
                                            f"guess"})
                continue
            safe.append({"finding": finding.to_dict(), "risk": score.to_dict(),
                          "plan": plan.to_dict()})

        follow_ups: list[Task] = []
        if safe:
            branch_name = task.payload.get("branch_name") or f"aep/infra-fix-{task.id[:8]}"
            has_github_target = bool(task.payload.get("remote_url")
                                      or (task.payload.get("owner") and task.payload.get("repo")))
            follow_ups.extend(build_infra_remediation_chain(
                project_id=task.project_id, project_root=project_root, branch_name=branch_name,
                remediations=safe, owner=task.payload.get("owner"), repo=task.payload.get("repo"),
                remote_url=task.payload.get("remote_url"),
                base_branch=task.payload.get("base_branch", "main"),
                include_github=has_github_target,
                max_ci_loops=task.payload.get("max_ci_loops", 3),
            ))
            evidence.append(Evidence(
                source="infra_remediation_plan", captured_at=_now(), exit_code=0,
                summary=f"planned {len(safe)} deterministic fix(es): "
                        f"{[s['finding']['rule_id'] for s in safe]}; scheduled remediate -> "
                        f"validate -> test -> rescan"
                        + (" -> push -> PR -> CI" if has_github_target else "") + " chain",
            ))

        for item in escalate:
            follow_ups.append(Task(
                id=str(uuid.uuid4()), type="infra_escalate", project_id=task.project_id,
                owner_agent="infrastructure_intelligence_agent", max_attempts=1,
                payload={"mode": "escalate", **item},
            ))

        return TaskResult(
            success=True, evidence=evidence,
            message=f"{len(findings)} infrastructure finding(s); {len(safe)} auto-remediable, "
                    f"{len(escalate)} escalated for human approval",
            follow_up_tasks=follow_ups,
        )

    # ---- REMEDIATE + VALIDATE -------------------------------------------
    def _remediate(self, task: Task, ctx: AgentContext) -> TaskResult:
        project_root = task.payload["project_root"]
        branch_name = task.payload["branch_name"]
        remediations: list[dict] = task.payload["remediations"]
        run_shell = self._run_shell(ctx, task, project_root)

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

        by_file: dict[str, list[dict]] = {}
        for item in remediations:
            by_file.setdefault(item["plan"]["file"], []).append(item)

        applied: list[dict] = []
        for file_path, items in by_file.items():
            read = ctx.tools.call("filesystem.read", task_id=task.id, project_root=project_root,
                                   path=file_path)
            if not read["ok"]:
                return TaskResult(success=False, evidence=evidence, failure_class=FailureClass.CODE,
                                   message=f"could not read {file_path}: {read.get('error')}")
            content = read["content"]
            for item in items:
                plan = infra_remediation.InfraRemediationPlan(**item["plan"])
                try:
                    content = infra_remediation.apply_plan(content, plan)
                except (ValueError, KeyError) as e:
                    return TaskResult(success=False, evidence=evidence,
                                       failure_class=FailureClass.CODE,
                                       message=f"remediation failed for {plan.finding_id}: {e}")
                applied.append(item)
                if plan.caveat:
                    evidence.append(Evidence(
                        source="infra_remediation:caveat", captured_at=_now(), exit_code=0,
                        summary=f"{plan.finding_id}: {plan.caveat}",
                    ))
            ctx.tools.call("filesystem.write", task_id=task.id, project_root=project_root,
                            path=file_path, content=content)

            # VALIDATE (Part 10) - immediately, per file, before committing.
            results = _validate_file(project_root, file_path, run_shell)
            validated, explanation = summarize(results)
            for result in results:
                evidence.append(Evidence(
                    source=f"infra_validation:{result.validator}", captured_at=_now(),
                    exit_code=0 if (result.ran and result.passed) else 1,
                    summary=f"{result.target}: ran={result.ran} passed={result.passed} - "
                            f"{result.detail[:300]}",
                ))
            evidence.append(Evidence(
                source="infra_validation", captured_at=_now(), exit_code=0 if validated else 1,
                summary=f"{file_path}: {explanation}",
            ))
            if not validated:
                # Part 10: never report remediation successful without
                # evidence. A change we could not validate is reverted
                # rather than committed on hope.
                ctx.tools.call("filesystem.write", task_id=task.id, project_root=project_root,
                                path=file_path, content=read["content"])
                evidence.append(Evidence(
                    source="infra_remediation:reverted", captured_at=_now(), exit_code=1,
                    summary=f"{file_path}: change REVERTED because it could not be validated "
                            f"({explanation}); refusing to commit an unvalidated infrastructure "
                            f"change",
                ))
                return TaskResult(
                    success=False, evidence=evidence, failure_class=FailureClass.CODE,
                    message=f"infrastructure change to {file_path} could not be validated: "
                            f"{explanation}",
                )

        commit_message = "aep: infrastructure security fix - " + ", ".join(
            sorted({item["finding"]["rule_id"] for item in applied}))
        commit_result = ctx.tools.call("git.commit", task_id=task.id, repo_path=project_root,
                                        message=commit_message[:200])
        evidence.append(Evidence(source="git.commit", captured_at=_now(),
                                  exit_code=0 if commit_result["ok"] else 1,
                                  summary=(commit_result.get("stdout") or "")[:300]))
        for item in applied:
            evidence.append(Evidence(
                source="infra_remediation", captured_at=_now(), exit_code=0,
                summary=f"{item['finding']['rule_id']} on {item['finding']['resource']} "
                        f"({item['plan']['file']}): applied `{item['plan']['fix']}` "
                        f"[risk score {item['risk']['score']}, "
                        f"{item['risk']['environment']}/{item['risk']['blast_radius']}]",
            ))

        return TaskResult(
            success=commit_result["ok"], evidence=evidence,
            message=f"applied and validated {len(applied)} infrastructure fix(es) on branch "
                    f"{branch_name}",
            failure_class=None if commit_result["ok"] else FailureClass.TOOL,
        )

    # ---- RESCAN / VERIFY --------------------------------------------------
    def _rescan(self, task: Task, ctx: AgentContext) -> TaskResult:
        project_root = task.payload["project_root"]
        remediations: list[dict] = task.payload["remediations"]
        run_shell = self._run_shell(ctx, task, project_root)

        categories = sorted({item["finding"]["category"] for item in remediations})
        scan_result = run_infrastructure_scan(project_root, run_shell, categories=categories)
        current_ids = {f.id for f in scan_result.findings}

        still_present = [i for i in remediations if i["finding"]["id"] in current_ids]
        resolved = [i for i in remediations if i["finding"]["id"] not in current_ids]

        evidence = [Evidence(
            source=f"infra_rescan:{record.scanner}", captured_at=record.scanned_at,
            exit_code=record.exit_code,
            summary=f"{record.category.value}: {record.finding_count} finding(s) on the "
                    f"post-remediation scan (availability={record.availability.value})",
        ) for record in scan_result.records]

        if still_present:
            evidence.append(Evidence(
                source="infra_rescan", captured_at=_now(), exit_code=1,
                summary=f"NOT resolved: {[i['finding']['rule_id'] for i in still_present]} - the "
                        f"second, real scan still reports these findings; refusing to claim the "
                        f"infrastructure issue is fixed",
            ))
            return TaskResult(
                success=False, evidence=evidence, failure_class=FailureClass.CODE,
                message=f"post-remediation scan still reports "
                        f"{[i['finding']['rule_id'] for i in still_present]}",
            )

        evidence.append(Evidence(
            source="infra_rescan", captured_at=_now(), exit_code=0,
            summary=f"CONFIRMED resolved by a second, independent scan: "
                    f"{[i['finding']['rule_id'] for i in resolved]}",
        ))
        return TaskResult(
            success=True, evidence=evidence,
            message=f"verified {len(resolved)} infrastructure finding(s) no longer reported",
        )

    # ---- ESCALATE ---------------------------------------------------------
    def _escalate(self, task: Task, ctx: AgentContext) -> TaskResult:
        finding = task.payload["finding"]
        risk = task.payload.get("risk", {})
        reason = task.payload.get("reason", "")
        return TaskResult(
            success=False, failure_class=FailureClass.HUMAN_REQUIRED,
            evidence=[Evidence(
                source="infra_escalation", captured_at=_now(), exit_code=1,
                summary=f"{finding['id']} ({finding['category']}, base "
                        f"{finding['severity']} / priority "
                        f"{risk.get('priority_severity', finding['severity'])}, risk score "
                        f"{risk.get('score', 'n/a')}, {risk.get('environment', 'unknown')} "
                        f"environment, {risk.get('blast_radius', 'unknown')} blast radius): "
                        f"{finding['description']} - {reason}. Remediation guidance: "
                        f"{finding['remediation']}",
            )],
            message=f"human approval required for {finding['id']}: {reason}",
        )
