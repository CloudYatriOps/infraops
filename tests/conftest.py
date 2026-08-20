import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

REPO_ROOT = Path(__file__).resolve().parent.parent

# Stage A.5's production default flipped `db/factory.py::build_state_store`
# (and everything that delegates to it - `build_orchestrator`, `cli.py`) to
# Postgres when no backend is explicitly requested. So that default path is
# actually exercisable in this environment without every test needing to
# know the local dev credential, set the documented local-dev password
# (see docs/DATABASE.md's example DSN / tests/db_pg_helper.py's LOCAL_DSN)
# as the default here - `setdefault` so a real environment's own
# AEP_PG_PASSWORD always wins over this fallback.
os.environ.setdefault("AEP_PG_PASSWORD", "aep_local_dev_only")


@pytest.fixture()
def policy_path() -> str:
    return str(REPO_ROOT / "config" / "policy.yaml")


def _init_git_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-b", "main", str(path)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "aep@example.com"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "AEP Bot"], check=True)


@pytest.fixture()
def demo_repo(tmp_path: Path) -> Path:
    """A small real git repo with one intentional bug: app.py's add()
    subtracts instead of adds, and test_app.py asserts the correct
    behavior (so it fails until the bug is fixed)."""
    repo = tmp_path / "demo_project"
    repo.mkdir()
    _init_git_repo(repo)

    (repo / "app.py").write_text(textwrap.dedent("""\
        def add(a, b):
            return a - b  # BUG: should be addition
        """))
    (repo / "test_app.py").write_text(textwrap.dedent("""\
        from app import add

        def test_add():
            assert add(2, 3) == 5
        """))
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "initial commit"],
                    check=True, capture_output=True)
    return repo


@pytest.fixture()
def demo_repo_with_secret(tmp_path: Path) -> Path:
    """Same as demo_repo, but with a fake/placeholder secret-shaped string
    committed into a config file, to exercise SecurityScanAgent blocking a
    task graph. This is not a real credential."""
    repo = tmp_path / "demo_project_secret"
    repo.mkdir()
    _init_git_repo(repo)
    (repo / "app.py").write_text("def add(a, b):\n    return a - b\n")
    (repo / "config.py").write_text(
        'AWS_ACCESS_KEY_ID = "AKIAABCD1234EFGH5678"  # placeholder, not real\n'
    )
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "initial commit"],
                    check=True, capture_output=True)
    return repo


