"""Single canonical entry point for constructing the durable state store
used by both `cli.py` and `bootstrap.py::build_orchestrator`.

Resolution order for the backend to use:
  1. `db_backend` argument, if passed explicitly (any non-None value wins,
     including an explicit `"sqlite"`).
  2. `AEP_DB_BACKEND` env var, if set (including an explicit `sqlite`).
  3. **Default: `"postgres"`.** This is the Stage A.5 production default -
     SQLite is no longer the ambient/implicit choice; it is only used when
     something explicitly asks for it (via either mechanism above).

This function is the ONLY place that resolution logic should live -
`build_orchestrator` and every `cli.py` call site delegate to it rather
than re-implementing the same `if backend == "postgres" ...` branching in
multiple places.
"""
from __future__ import annotations

import os
from typing import Optional

from .state_store_postgres import PostgresStateStore
from ..state_store import StateStore

VALID_BACKENDS = ("sqlite", "postgres")


def resolve_backend(db_backend: Optional[str] = None) -> str:
    """Resolves which backend name to use, without constructing anything."""
    backend = (db_backend or os.environ.get("AEP_DB_BACKEND") or "postgres").strip().lower()
    if backend not in VALID_BACKENDS:
        raise ValueError(f"unknown db_backend {backend!r}; expected 'sqlite' or 'postgres'")
    return backend


def build_state_store(db_path: str, db_backend: Optional[str] = None):
    """Builds the durable state store to use for `db_path`.

    * `db_backend="postgres"` (or the resolved default, when nothing else
      says otherwise) returns a `PostgresStateStore` - connecting via
      `AEP_POSTGRES_DSN`/`AEP_PG_*` env vars (see
      `state_store_postgres.dsn_from_env`), running the startup gate
      (`db/startup.verify_database`), and raising
      `DatabaseUnavailableError`/`SchemaDriftError` rather than ever
      silently falling back to SQLite. `db_path` is ignored in this mode.
    * `db_backend="sqlite"` (explicit, or via `AEP_DB_BACKEND=sqlite`)
      returns the existing `StateStore` at `db_path`, unchanged.
    """
    backend = resolve_backend(db_backend)
    if backend == "postgres":
        return PostgresStateStore()
    return StateStore(db_path)
