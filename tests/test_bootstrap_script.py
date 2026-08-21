"""Stage D Wave 2 (item 19): a CI/sandbox-safe test for
`scripts/bootstrap.sh` using its `--check-only` mode (added this wave) -
verifies preconditions (env var set, Postgres reachable, CLI importable)
without installing packages or re-applying migrations on every test run.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.db_pg_helper import local_postgres_available

# (AEP_PG_PASSWORD no longer set here: setting any AEP_PG_* var opts OUT
# of AEP's zero-config embedded local PostgreSQL - see tests/conftest.py.)

pytestmark = pytest.mark.skipif(not local_postgres_available(),
                                 reason="local Postgres not reachable")

REPO_ROOT = Path(__file__).resolve().parent.parent
BOOTSTRAP = REPO_ROOT / "scripts" / "bootstrap.sh"


def test_check_only_mode_exists_and_skips_install_and_migrations():
    source = BOOTSTRAP.read_text()
    assert "--check-only" in source
    assert "skipped: no migrations applied" in source or "skipped - no migrations applied" in source


def test_check_only_run_succeeds_without_mutating_state():
    result = subprocess.run(
        ["bash", str(BOOTSTRAP), "--check-only"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=30,
        # Pass the interpreter running the suite: a bare `python3` can
        # resolve to a completely different install (no `aep` module).
        env={**os.environ, "PYTHON_BIN": sys.executable},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    # The database step reports one of two outcomes: it reached an
    # operator-configured Postgres, or it is using AEP's own embedded
    # local one (the default when no AEP_PG_*/AEP_POSTGRES_DSN is set).
    # Both are a pass; asserting only the former made this test require a
    # separately-installed Postgres that the product no longer needs.
    assert ("PostgreSQL is reachable." in result.stdout
            or "embedded local PostgreSQL" in result.stdout)
    assert "(--check-only: skipped)" in result.stdout
    assert "-m aep.cli --help ran successfully." in result.stdout
