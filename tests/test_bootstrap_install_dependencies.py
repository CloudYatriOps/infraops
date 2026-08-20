"""BUG-0004 regression test (see BUGFIX.md).

`pyproject.toml`'s `[project.optional-dependencies].postgres` used to hold
`psycopg2-binary`/`pgvector`, with a comment claiming the SQLite
StateStore remained the default/production path - false as of Stage A.5
(`src/aep/db/factory.py::resolve_backend` defaults to `"postgres"`). A
clean `pip install .` (no extras) therefore installed a package whose
DEFAULT runtime path raised `ModuleNotFoundError: No module named
'psycopg2'` the moment anything touched the default backend.

A full venv-based `pip install -e .` + subprocess reproduction is the
most faithful regression test, but is slow/heavy for this suite's normal
run (spinning up a fresh venv on every `pytest` invocation). This test
takes the lightweight, static-check half of what the bug report asks
for - parsing `pyproject.toml` and asserting the fix's actual shape:
`psycopg2-binary`/`pgvector` are required dependencies, not only
optional ones - plus a fast in-process import check that exercises the
real failure mode directly."""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python <3.11 fallback
    import tomli as tomllib


def _load_pyproject() -> dict:
    with open(REPO_ROOT / "pyproject.toml", "rb") as f:
        return tomllib.load(f)


def test_psycopg2_and_pgvector_are_required_not_only_optional():
    """The default runtime backend (db/factory.py::resolve_backend) is
    Postgres, so a bare `pip install .` must pull in psycopg2/pgvector -
    they must NOT live only under `[project.optional-dependencies]`."""
    data = _load_pyproject()
    deps = data["project"]["dependencies"]
    dep_names = {d.split(">=")[0].split("==")[0].strip().lower() for d in deps}
    assert "psycopg2-binary" in dep_names, (
        "psycopg2-binary must be a required dependency (BUG-0004): "
        "PostgreSQL is the default runtime backend, so an install with "
        "no extras must still be able to construct it."
    )
    assert "pgvector" in dep_names, "pgvector must be a required dependency (BUG-0004), same reasoning."


def test_default_backend_resolution_is_postgres_matching_the_dependency_fix():
    """Confirms the premise the fix depends on: if a future change flips
    the default backend back to sqlite, this dependency requirement
    should be revisited too - this test documents the coupling."""
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from aep.db.factory import resolve_backend
    import os
    saved = os.environ.pop("AEP_DB_BACKEND", None)
    try:
        assert resolve_backend(None) == "postgres"
    finally:
        if saved is not None:
            os.environ["AEP_DB_BACKEND"] = saved


def test_importing_db_factory_module_does_not_raise_modulenotfounderror():
    """Direct reproduction of BUG-0004's actual failure mode: importing
    the module that constructs the default backend must not blow up with
    `ModuleNotFoundError: No module named 'psycopg2'` in an environment
    where the fixed dependency set is actually installed (this test
    process's own environment, per pyproject.toml's now-required deps)."""
    sys.path.insert(0, str(REPO_ROOT / "src"))
    import importlib
    import aep.db.factory as factory_mod
    importlib.reload(factory_mod)  # pragma: no branch - just proves re-import is clean
    import aep.db.state_store_postgres  # noqa: F401 - the module psycopg2-binary actually backs
