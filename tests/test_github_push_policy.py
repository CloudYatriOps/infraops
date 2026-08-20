"""Direct tests of requirement 6 from the Phase 2 brief: the existing
policy engine (unmodified) gates GitHub pushes exactly like local git
pushes - protected branches are denied, force-push requires approval,
ordinary feature-branch pushes are allowed and actually happen."""
import subprocess
from pathlib import Path

from aep.bootstrap import build_orchestrator
from aep.github.planner import build_push_task
from aep.models import ProjectConfig, TaskStatus


def _repo_with_remote(tmp_path: Path):
    local = tmp_path / "local"
    local.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(local)], check=True)
    subprocess.run(["git", "-C", str(local), "config", "user.email", "a@b.com"], check=True)
    subprocess.run(["git", "-C", str(local), "config", "user.name", "aep"], check=True)
    (local / "f.txt").write_text("v1\n")
    subprocess.run(["git", "-C", str(local), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(local), "commit", "-q", "-m", "init"], check=True)
    subprocess.run(["git", "-C", str(local), "checkout", "-q", "-b", "aep/fix-1"], check=True)

    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
    return local, remote


def _orch(tmp_path, policy_path, repo_path):
    project = ProjectConfig(id="p", name="p", repo_path=repo_path, policy_path=policy_path)
    return build_orchestrator(db_path=str(tmp_path / "s.db"), project=project, enable_github=True, db_backend="sqlite")


def test_push_to_main_via_github_push_branch_is_denied(tmp_path, policy_path):
    local, remote = _repo_with_remote(tmp_path)
    orch = _orch(tmp_path, policy_path, str(local))
    task = build_push_task("p", str(local), branch_name="main", remote_url=str(remote))
    orch.submit_graph("p", [task])
    orch.run_to_completion("p")

    result = orch.store.get_task(task.id)
    assert result.status == TaskStatus.CANCELLED
    events = orch.store.query_events("p", task.id)
    assert any(e.decision == "DENY" for e in events)
    # And no branch called "main" push actually happened beyond what already existed.
    branches = subprocess.run(["git", "--git-dir", str(remote), "branch"],
                               capture_output=True, text=True).stdout
    assert "main" not in branches  # nothing was ever pushed - the gate fired before PushAgent ran


def test_force_push_requires_approval(tmp_path, policy_path):
    local, remote = _repo_with_remote(tmp_path)
    orch = _orch(tmp_path, policy_path, str(local))
    task = build_push_task("p", str(local), branch_name="aep/fix-1", remote_url=str(remote), force=True)
    orch.submit_graph("p", [task])
    orch.run_to_completion("p")

    result = orch.store.get_task(task.id)
    assert result.status == TaskStatus.BLOCKED_ON_APPROVAL
    events = orch.store.query_events("p", task.id)
    assert any(e.decision == "REQUIRE_APPROVAL" for e in events)

    # A human approves it explicitly - only then does the push actually happen.
    orch.approve(task.id, decided_by="a-human")
    orch.run_to_completion("p")
    assert orch.store.get_task(task.id).status == TaskStatus.SUCCEEDED
    branches = subprocess.run(["git", "--git-dir", str(remote), "branch"],
                               capture_output=True, text=True).stdout
    assert "aep/fix-1" in branches


def test_ordinary_feature_branch_push_is_allowed_and_real(tmp_path, policy_path):
    local, remote = _repo_with_remote(tmp_path)
    orch = _orch(tmp_path, policy_path, str(local))
    task = build_push_task("p", str(local), branch_name="aep/fix-1", remote_url=str(remote))
    orch.submit_graph("p", [task])
    orch.run_to_completion("p")

    result = orch.store.get_task(task.id)
    assert result.status == TaskStatus.SUCCEEDED
    branches = subprocess.run(["git", "--git-dir", str(remote), "branch"],
                               capture_output=True, text=True).stdout
    assert "aep/fix-1" in branches
