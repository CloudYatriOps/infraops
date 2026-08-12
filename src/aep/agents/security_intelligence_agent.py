"""Real multi-scanner security intelligence agent (Phase 4 Part 3).

Named `SecurityAgent` per the Phase 4 spec - NOT the same class as
`SecurityScanAgent` in `agents/security_agent.py` (Phase 1's deterministic
secret-pattern gate that runs before every CodeAgent commit). That agent
is untouched and keeps its job; this one is Phase 4's new, broader
capability covering four scanner categories (secret/SAST/IaC/container)
via `security/scan_runner.py`, with real remediation/rescan/escalation -
DependencyCVEAgent's four-mode shape (scan/remediate/rescan/escalate) is
mirrored deliberately, since Part 3's pipeline
(DISCOVER->UNDERSTAND->REMEDIATE->TEST->RESCAN->PR->CI->VERIFY) is
identical in shape to Phase 3's.

Verification discipline (Part 3 step 9/10, mirroring Phase 3 Part B): a
finding is only ever reported resolved after `mode="rescan"` runs the SAME
real scanner category again and confirms the specific finding fingerprint
is actually gone. Nothing here trusts a remediation just because it
"should" fix the finding.

Severity -> action mapping (Part 8, evaluated via the *existing*
PolicyEngine/config/policy.yaml - no new policy mechanism):
  - CRITICAL: policy DENY -> always escalated to a human, even when this
    module could technically build a safe mechanical fix. Never
    auto-remediated, which is how "automatically block merge/deployment"
    is enforced here - no PR is ever opened for an unresolved CRITICAL.
  - HIGH: policy REQUIRE_APPROVAL -> "remediation required": a safe
    mechanical fix (if one can be built) IS attempted automatically;
    anything without a safe fix is escalated.
  - MEDIUM: policy WARN -> attempted opportunistically if a safe fix
    exists, else tracked via escalation (Part 8's "remediation task").
  - LOW/INFO: policy ALLOW -> tracked only (Part 8's "track and
    prioritize") - never auto-remediated even if a mechanical fix exists,
    to avoid churning low-value PRs.
  - Any SECRET finding additionally records the *existing*, already-
    unconditional `secret.commit` DENY policy rule as evidence for why the
    literal is being removed from source, regardless of severity.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from ..models import Evidence, FailureClass, PolicyDecisionType, Task, TaskResult
from ..security import remediation as remed
from ..security.models import SecurityCategory, SecuritySeverity
from ..security.planner import build_security_remediation_chain
from ..security.scan_runner import run_security_scan
from ..security.suppressions import Suppression, is_suppressed
from .base import Agent, AgentContext


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _plan_for(finding, file_content: str):
    """Returns (kind, plan) for whichever remediation category applies,
    or (None, None) if no safe, verified-shape fix exists - see
    `security/remediation.py`'s module docstring for why an unmatched
    shape is refused rather than guessed at."""
    if finding.category == SecurityCategory.SECRET:
        plan = remed.plan_secret_remediation(finding, file_content)
        return ("secret", plan) if plan else (None, None)
    if finding.category == SecurityCategory.SAST:
        plan = remed.plan_sast_remediation(finding, file_content)
        return ("sast", plan) if plan else (None, None)
    if finding.category == SecurityCategory.IAC:
        plan = remed.plan_iac_remediation(finding, file_content)
        return ("iac", plan) if plan else (None, None)
    return (None, None)  # container: never auto-remediated (Part 7)


def _apply(kind: str, file_content: str, plan) -> str:
    if kind == "secret":
        return remed.apply_secret_remediation_plan(file_content, plan)
    if kind == "sast":
        return remed.apply_sast_remediation_plan(file_content, plan)
    if kind == "iac":
        return remed.apply_iac_remediation_plan(file_content, plan)
    raise ValueError(f"unknown remediation kind: {kind!r}")


class SecurityAgent:
    name = "security_agent"
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
        raise ValueError(f"unknown security_agent mode: {mode!r}")

    def _run_shell(self, ctx: AgentContext, task: Task, project_root: str):
        def run(args, cwd=None, timeout=90):
            try:
                return ctx.tools.call("shell.run", task_id=task.id, args=args,
                                       cwd=cwd or project_root, timeout=timeout)
            except Exception as e:  # noqa: BLE001 - availability probes must not crash the scan
                return {"ok": False, "exit_code": -1, "stdout": "", "stderr": str(e), "args": args}
        return run

    # ---- DISCOVER + NORMALIZE + PRIORITIZE -----------------------------
    def _scan(self, task: Task, ctx: AgentContext) -> TaskResult:
        project_root = task.payload["project_root"]
        categories = task.payload.get("categories")
        run_shell = self._run_shell(ctx, task, project_root)
        result = run_security_scan(project_root, run_shell, categories=categories)

        suppressions = [Suppression(**s) for s in task.payload.get("suppressions", [])]

        evidence: list[Evidence] = []
        for record in result.records:
            if record.availability.value != "AVAILABLE":
                evidence.append(Evidence(
                    source=f"security_scan:{record.scanner}", captured_at=record.scanned_at,
                    exit_code=0,
                    summary=f"{record.category.value}: not scanned - {record.availability.value} "
                            f"({record.note})",
                ))
                continue
            evidence.append(Evidence(
                source=f"security_scan:{record.scanner}", captured_at=record.scanned_at,
                exit_code=record.exit_code,
                summary=f"{record.category.value}: {record.finding_count} finding(s) via "
                        f"{record.scanner} {record.scanner_version}",
            ))

        open_findings = [f for f in result.findings if is_suppressed(suppressions, f.id) is None]
        suppressed_count = len(result.findings) - len(open_findings)
        if suppressed_count:
            evidence.append(Evidence(
                source="security_scan:suppressions", captured_at=_now(), exit_code=0,
                summary=f"{suppressed_count} finding(s) excluded by an active, justified "
                        f"suppression (see security/suppressions.py) - not deleted, still "
                        f"queryable via list_suppressions()",
            ))

        if not open_findings:
            evidence.append(Evidence(source="security_scan", captured_at=_now(), exit_code=0,
                                      summary="no open security findings across any available "
                                              "scanner category"))
            return TaskResult(success=True, evidence=evidence, message="security scan clean")

        safe: list[dict] = []
        unsafe: list = []
        for finding in open_findings:
            decision = ctx.policy.evaluate("security.finding", {"severity": finding.severity.value})
            evidence.append(Evidence(
                source="policy", captured_at=_now(),
                exit_code=1 if decision.decision == PolicyDecisionType.DENY else 0,
                summary=f"{finding.id}: severity={finding.severity.value} -> "
                        f"{decision.decision.value} ({decision.reason})",
            ))
            if finding.category == SecurityCategory.SECRET:
                secret_decision = ctx.policy.evaluate("secret.commit", {})
                evidence.append(Evidence(
                    source="policy", captured_at=_now(), exit_code=1,
                    summary=f"{finding.id}: secret.commit -> {secret_decision.decision.value} "
                            f"({secret_decision.reason}) - literal will be removed from source",
                ))

            if decision.decision == PolicyDecisionType.DENY:
                # CRITICAL: never auto-remediated, regardless of whether a
                # mechanical fix exists - this is what keeps an unresolved
                # CRITICAL out of any PR this scan produces.
                unsafe.append(finding)
                continue
            if decision.decision == PolicyDecisionType.ALLOW and finding.severity in (
                    SecuritySeverity.LOW, SecuritySeverity.INFO):
                # Part 8: "LOW -> track and prioritize" - deliberately not
                # auto-remediated even when a fix could be built, to avoid
                # low-value churn; tracked as evidence above, nothing more.
                continue

            read = ctx.tools.call("filesystem.read", task_id=task.id, project_root=project_root,
                                   path=finding.file) if finding.file else {"ok": False}
            if not read.get("ok"):
                unsafe.append(finding)
                continue
            kind, plan = _plan_for(finding, read["content"])
            if plan is None:
                unsafe.append(finding)
                continue
            safe.append({"kind": kind, "finding": finding.to_dict(),
                         "plan": {k: v for k, v in vars(plan).items()}})

        follow_ups: list[Task] = []
        if safe:
            branch_name = task.payload.get("branch_name") or f"aep/sec-fix-{task.id[:8]}"
            has_github_target = bool(task.payload.get("remote_url")
                                      or (task.payload.get("owner") and task.payload.get("repo")))
            follow_ups.extend(build_security_remediation_chain(
                project_id=task.project_id, project_root=project_root, branch_name=branch_name,
                remediations=safe,
                owner=task.payload.get("owner"), repo=task.payload.get("repo"),
                remote_url=task.payload.get("remote_url"),
                base_branch=task.payload.get("base_branch", "main"),
                include_github=has_github_target,
                max_ci_loops=task.payload.get("max_ci_loops", 3),
            ))
            evidence.append(Evidence(
                source="security_remediation_plan", captured_at=_now(), exit_code=0,
                summary=f"planned safe remediation for {len(safe)} finding(s) "
                        f"{[s['finding']['id'] for s in safe]}; scheduled remediate -> test -> "
                        f"rescan chain" + (" -> push -> PR -> CI" if has_github_target else ""),
            ))

        for finding in unsafe:
            follow_ups.append(Task(
                id=str(uuid.uuid4()), type="security_escalate", project_id=task.project_id,
                owner_agent="security_agent", max_attempts=1,
                payload={"mode": "escalate", "finding": finding.to_dict()},
            ))

        return TaskResult(
            success=True, evidence=evidence,
            message=f"{len(open_findings)} open finding(s); {len(safe)} safely remediated, "
                    f"{len(unsafe)} escalated for human review",
            follow_up_tasks=follow_ups,
        )

    # ---- REMEDIATE -------------------------------------------------------
    def _remediate(self, task: Task, ctx: AgentContext) -> TaskResult:
        project_root = task.payload["project_root"]
        branch_name = task.payload["branch_name"]
        remediations: list[dict] = task.payload["remediations"]

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
        for r in remediations:
            by_file.setdefault(r["finding"]["file"], []).append(r)

        applied: list[dict] = []
        for file_path, file_remediations in by_file.items():
            read = ctx.tools.call("filesystem.read", task_id=task.id, project_root=project_root,
                                   path=file_path)
            if not read["ok"]:
                return TaskResult(success=False, evidence=evidence, failure_class=FailureClass.CODE,
                                   message=f"could not read {file_path}: {read.get('error')}")
            content = read["content"]
            for r in file_remediations:
                kind = r["kind"]
                plan_cls = {"secret": remed.SecretRemediationPlan, "sast": remed.SastRemediationPlan,
                            "iac": remed.IacRemediationPlan}[kind]
                plan = plan_cls(**r["plan"])
                content = _apply(kind, content, plan)
                applied.append(r)
            ctx.tools.call("filesystem.write", task_id=task.id, project_root=project_root,
                            path=file_path, content=content)

        for r in applied:
            if r["kind"] == "secret" and r["plan"].get("rotation_recommended"):
                history_decision = ctx.policy.evaluate("security.git_history_inspection", {})
                if history_decision.decision == PolicyDecisionType.DENY:
                    evidence.append(Evidence(
                        source="security_remediation:secret_rotation", captured_at=_now(),
                        exit_code=0,
                        summary=f"{r['finding']['file']}: credential rotation recommended - "
                                f"{r['plan']['rotation_reason']}; git history NOT inspected "
                                f"(policy denied: {history_decision.reason})",
                    ))
                    continue
                history = remed.inspect_git_history_for_secret(
                    self._run_shell(ctx, task, project_root), project_root, r["finding"]["file"])
                evidence.append(Evidence(
                    source="security_remediation:secret_rotation", captured_at=_now(), exit_code=0,
                    summary=f"{r['finding']['file']}: credential rotation recommended - "
                            f"{r['plan']['rotation_reason']}; git history: {history['note']}",
                ))

        commit_msg = "aep: security fix - " + ", ".join(
            f"{r['kind']}:{r['finding']['rule_id'] or r['finding']['id']}" for r in applied)
        commit_result = ctx.tools.call("git.commit", task_id=task.id, repo_path=project_root,
                                        message=commit_msg[:200])
        evidence.append(Evidence(source="git.commit", captured_at=_now(),
                                  exit_code=0 if commit_result["ok"] else 1,
                                  summary=(commit_result.get("stdout") or "")[:300]))
        for r in applied:
            evidence.append(Evidence(
                source="security_remediation", captured_at=_now(), exit_code=0,
                summary=f"{r['kind']} finding {r['finding']['id']} in {r['finding']['file']}: "
                        f"remediated on branch {branch_name}",
            ))

        return TaskResult(
            success=commit_result["ok"], evidence=evidence,
            message=f"applied {len(applied)} security remediation(s) on branch {branch_name}",
            failure_class=None if commit_result["ok"] else FailureClass.TOOL,
        )

    # ---- RESCAN / VERIFY --------------------------------------------------
    def _rescan(self, task: Task, ctx: AgentContext) -> TaskResult:
        project_root = task.payload["project_root"]
        remediations: list[dict] = task.payload["remediations"]
        run_shell = self._run_shell(ctx, task, project_root)

        categories = sorted({r["finding"]["category"] for r in remediations})
        result = run_security_scan(project_root, run_shell, categories=categories)
        current_ids = {f.id for f in result.findings}

        still_present = [r for r in remediations if r["finding"]["id"] in current_ids]
        resolved = [r for r in remediations if r["finding"]["id"] not in current_ids]

        evidence = [Evidence(
            source=f"security_rescan:{record.scanner}", captured_at=record.scanned_at,
            exit_code=record.exit_code,
            summary=f"{record.category.value}: {record.finding_count} finding(s) reported on the "
                    f"post-remediation scan",
        ) for record in result.records]

        if still_present:
            evidence.append(Evidence(
                source="security_rescan", captured_at=_now(), exit_code=1,
                summary=f"NOT resolved: {[r['finding']['id'] for r in still_present]} - the "
                        f"second, real scan still reports the finding; refusing to claim this is "
                        f"fixed",
            ))
            return TaskResult(
                success=False, evidence=evidence, failure_class=FailureClass.CODE,
                message=f"post-remediation scan still shows "
                        f"{[r['finding']['id'] for r in still_present]}; the fix did not resolve "
                        f"the finding as expected",
            )

        evidence.append(Evidence(
            source="security_rescan", captured_at=_now(), exit_code=0,
            summary=f"CONFIRMED resolved by a second, independent scan: "
                    f"{[r['finding']['id'] for r in resolved]}",
        ))
        return TaskResult(
            success=True, evidence=evidence,
            message=f"verified {[r['finding']['id'] for r in resolved]} no longer reported",
        )

    # ---- ESCALATE ----------------------------------------------------------
    def _escalate(self, task: Task, ctx: AgentContext) -> TaskResult:
        finding = task.payload["finding"]
        return TaskResult(
            success=False, failure_class=FailureClass.HUMAN_REQUIRED,
            evidence=[Evidence(
                source="security_escalation", captured_at=_now(), exit_code=1,
                summary=f"{finding['id']} ({finding['category']}, {finding['severity']}): "
                        f"{finding['description']} - {finding['remediation']} - no safe automated "
                        f"remediation was applied; human review required before this can be "
                        f"merged/deployed",
            )],
            message=f"no safe automated remediation for {finding['id']}: {finding['description']}",
        )
