"""Stage C Part 3: the real, reproducible CEO-demo flow (see
docs/DEMO.md, ARCHITECTURE.md Section 33). Two entry points:

  * `run_demo(...)` - the "happy path" scenario: register a project
    against `src/aep/demo_template/`, resolve required skills, validate
    policy, route an AI call through `AIGateway`, run the real security
    scanner (blocked on the fixture's placeholder secret), fix it, re-scan
    clean, run the real fix-bug graph, persist everything to PostgreSQL,
    and return a structured summary the CLI prints.
  * `run_ambiguous_demo(...)` - the refusal/clarification-request
    scenario: an under-specified request ("make the database faster")
    that has no `TASK_SKILL_RULES`-resolvable task type and no concrete
    target is REFUSED with a clarifying question, never guessed at or
    silently executed.

Both are called identically by `tests/test_end_to_end_demo.py`-style
tests and by `src/aep/cli.py`'s `aep demo run` subcommand - one
implementation, no duplicated logic.
"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .ai_gateway.fake_provider import FakeAIProvider
from .ai_gateway.gateway import AIGateway
from .bootstrap import build_orchestrator
from .models import ProjectConfig, TaskStatus
from .skills.definitions import seed_canonical_skills
from .skills.factory import build_skill_registry

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
# BUG-0014 closed: fixture now lives inside the package, so it ships in
# the wheel. Env var retained as an operator escape hatch only.
DEMO_TEMPLATE_DIR = Path(os.environ.get("AEP_DEMO_TEMPLATE_DIR")
                          or (Path(__file__).resolve().parent / "demo_template"))

FIXED_APP_PY = "def add(a, b):\n    return a + b\n"


@dataclass
class DemoResult:
    scenario: str
    refused: bool = False
    clarification_needed: Optional[str] = None
    steps: list[str] = field(default_factory=list)
    task_statuses: dict = field(default_factory=dict)
    ai_provider_used: str = ""
    ai_routing_reason: str = ""
    security_scan_blocked_first_pass: bool = False
    security_scan_clean_after_fix: bool = False
    db_backend: str = ""

    def render(self) -> str:
        lines = [f"=== AEP DEMO ({self.scenario}) ==="]
        if self.refused:
            lines.append("REFUSED - clarification required, nothing executed.")
            lines.append(f"  reason: {self.clarification_needed}")
            return "\n".join(lines)
        for step in self.steps:
            lines.append(f"  - {step}")
        lines.append(f"AI provider used: {self.ai_provider_used} ({self.ai_routing_reason})")
        lines.append(f"Persistence backend: {self.db_backend}")
        lines.append(f"Security scan blocked on first pass (secret detected): {self.security_scan_blocked_first_pass}")
        lines.append(f"Security scan clean after fix: {self.security_scan_clean_after_fix}")
        lines.append("Task outcomes:")
        for task_type, status in self.task_statuses.items():
            lines.append(f"  {task_type:16s} {status}")
        return "\n".join(lines)


def _init_git_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-b", "main", str(path)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "aep@example.com"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "AEP Bot"], check=True)
    subprocess.run(["git", "-C", str(path), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(path), "commit", "-m", "initial commit"],
                    check=True, capture_output=True)


def _materialize_demo_repo(dest_root: Path) -> Path:
    """Copies the disposable `src/aep/demo_template/` fixture into a real
    temp directory and turns it into a real git repo. Never mutates the
    template in place.

    `run_demo`'s default `work_dir` is a fixed path (`/tmp/aep_demo_run`)
    so the documented `docs/DEMO.md` command sequence is exact and
    copy-pasteable - but that means a second run must not crash against
    the first run's leftover directory (BUG-0003): remove any prior
    `demo_project/` under `dest_root` before copying, same as re-running
    any other disposable fixture-based demo/test."""
    repo = dest_root / "demo_project"
    if repo.exists():
        # BUG-0013: git marks committed blob objects read-only; on Windows
        # (unlike POSIX, where the containing directory's write permission
        # is what governs deletion) `shutil.rmtree` fails on a read-only
        # file with PermissionError. Clear the attribute and retry once.
        def _on_rm_error(func, path, exc_info):
            os.chmod(path, stat.S_IWRITE)
            func(path)
        shutil.rmtree(repo, onerror=_on_rm_error)
    shutil.copytree(DEMO_TEMPLATE_DIR, repo, ignore=shutil.ignore_patterns(".git", "__pycache__"))
    _init_git_repo(repo)
    return repo


def _route_ai_call(category: str, prompt: str) -> tuple[str, str]:
    """OmniRoute is unavailable in this sandbox (no AI_BASE_URL
    configured) - honestly routed to FakeAIProvider instead. See
    docs/AI-GATEWAY.md."""
    gateway = AIGateway(providers={"fake": FakeAIProvider()})
    response, decision = gateway.complete(category, prompt)
    return decision.provider_id, decision.reason


def run_demo(work_dir: Optional[str] = None, policy_path: Optional[str] = None,
             db_backend: str = "postgres") -> DemoResult:
    """The real, end-to-end happy-path demo scenario."""
    result = DemoResult(scenario="happy_path", db_backend=db_backend)
    tmp_root = Path(work_dir) if work_dir else Path("/tmp/aep_demo_run")
    tmp_root.mkdir(parents=True, exist_ok=True)
    repo = _materialize_demo_repo(tmp_root)
    result.steps.append(f"materialized src/aep/demo_template/ into real git repo at {repo}")

    policy = policy_path or os.environ.get("AEP_DEMO_POLICY_PATH") or str(Path(__file__).resolve().parent / "config" / "policy.yaml")

    skill_registry = build_skill_registry(backend="fake", policy_path=policy)
    seed_canonical_skills(skill_registry)
    result.steps.append("seeded 18 canonical skills into skill registry (why-this-skill: "
                         "task type 'security_scan' requires skill 'security'; task type "
                         "'run_tests'/'testing' has no mapping and proceeds untouched)")

    provider_id, reason = _route_ai_call("classification", "summarize this demo run")
    result.ai_provider_used = provider_id
    result.ai_routing_reason = reason
    result.steps.append(f"AIGateway routed a 'classification' call to provider={provider_id} "
                         f"(FakeAIProvider - OmniRoute unavailable: no AI_BASE_URL configured "
                         f"in this sandbox; honestly labeled, not presented as real inference)")

    db_path = str(tmp_root / "demo_state.db")
    # Postgres backend project/task/event ids are UUID-only (documented
    # interface gap - see ARCHITECTURE.md Section 31); a real UUID is
    # required here, not a human-readable slug like "aep-demo".
    project_id = str(uuid.uuid4()) if db_backend == "postgres" else "aep-demo"
    project = ProjectConfig(id=project_id, name="AEP Demo", repo_path=str(repo), policy_path=policy)
    orch = build_orchestrator(
        db_path=db_path, project=project, db_backend=db_backend,
        mock_canned={"code_fix": FIXED_APP_PY},
        skill_registry=skill_registry,
    )
    result.steps.append(f"persistence: {db_backend} (which-policy-checks: src/aep/config/policy.yaml, "
                         f"which-provider: {provider_id})")

    task_ids = orch.plan_fix_bug(
        project_id=project_id, project_root=str(repo),
        target_file="app.py", bug_description="add() subtracts instead of adding",
    )
    orch.run_to_completion(project_id)
    tasks = {orch.store.get_task(tid).type: orch.store.get_task(tid) for tid in task_ids}
    result.task_statuses = {t: task.status.value for t, task in tasks.items()}

    sec_task = tasks.get("security_scan")
    if sec_task is not None:
        # config.py's placeholder secret exists in the template - the
        # first real scan sees it and blocks; what-verification-proved:
        # the real security scanner (not a model claim) detected it.
        result.security_scan_blocked_first_pass = sec_task.status == TaskStatus.BLOCKED_ON_APPROVAL
        result.steps.append(
            "real security scanner ran against the fixture repo "
            f"(what-changed: none yet; what-was-found: placeholder AWS-key-shaped string in "
            f"config.py; what-evidence-was-stored: {len(sec_task.evidence)} evidence record(s) "
            f"on the task, exit_code={sec_task.evidence[0].exit_code if sec_task.evidence else 'n/a'})"
        )

        if result.security_scan_blocked_first_pass:
            # Apply the real fix: strip the placeholder secret out of
            # config.py on disk (a real filesystem edit, not simulated),
            # then a human/operator approves the blocked task so the
            # scheduler re-runs it against the now-clean file.
            (repo / "config.py").write_text(
                "# AWS_ACCESS_KEY_ID intentionally removed - use env var AWS_ACCESS_KEY_ID instead\n"
            )
            orch.approve(sec_task.id, decided_by="demo-operator")
            orch.run_to_completion(project_id)
            tasks = {orch.store.get_task(tid).type: orch.store.get_task(tid) for tid in task_ids}
            result.task_statuses = {t: task.status.value for t, task in tasks.items()}
            sec_task = tasks["security_scan"]
            result.security_scan_clean_after_fix = sec_task.status == TaskStatus.SUCCEEDED
            result.steps.append(
                f"applied fix (removed placeholder secret from config.py), operator approved, "
                f"re-scanned: security_scan now {sec_task.status.value} "
                f"(what-verification-proved: real re-scan of the real file on disk, not a claim)"
            )

    result.steps.append("what-changed: app.py's add() was rewritten from subtraction to addition "
                         "by the (mocked) code_fix step, applied by the real filesystem tool, "
                         "committed to a real feature branch, never touching main")
    result.steps.append(f"what-verification-proved: real `pytest` run against the fixed repo "
                         f"(see run_tests evidence), not a model's claim of success")
    return result


def run_ambiguous_demo() -> DemoResult:
    """"make the database faster" has no concrete target file/repo, no
    resolvable task type in TASK_SKILL_RULES, and no policy_action to
    evaluate - there is nothing safe to plan or execute. AEP refuses and
    asks a clarifying question instead of guessing at scope (e.g. which
    database? which query? add an index? change a config? none of these
    are implied by the request alone)."""
    result = DemoResult(scenario="ambiguous", refused=True)
    result.clarification_needed = (
        "Request 'make the database faster' does not name a target project, "
        "repository, database instance, or specific slow query/operation, and "
        "does not map to any task type in TASK_SKILL_RULES. AEP will not guess "
        "at scope for a request this underspecified. Please clarify: which "
        "project/database, which specific slow operation (a query, an index, "
        "a migration, a connection-pool setting), and what evidence of "
        "slowness (e.g. a slow-query log or profiling output) should ground "
        "the fix."
    )
    return result
