"""Canonical entry point for constructing a `SkillRegistry`, mirroring
`db/factory.py::build_state_store`'s single-resolution-point pattern.

* `backend="postgres"` (or the default) builds real
  `PostgresSkillRepository`/`PostgresSkillVersionRepository` instances
  against a `ConnectionPool` built from the same `AEP_POSTGRES_DSN`/
  `AEP_PG_*` env vars `state_store_postgres.py` uses.
* `backend="fake"` builds the in-memory `FakeSkillRepository`/
  `FakeSkillVersionRepository` pair - zero network dependency, used by
  fast unit tests.

Both `db_backend="sqlite"` (the runtime StateStore default before Stage
A.5) and Stage B's skill registry are orthogonal - the skill registry has
no SQLite implementation; a project running with `AEP_DB_BACKEND=sqlite`
for its task/event store can still use `backend="postgres"` (or `"fake"`
in tests) here, since skills are platform-wide configuration, not
per-project runtime state.
"""
from __future__ import annotations

from typing import Optional

from .registry import SkillRegistry
from ..db.fake import FakeSkillRepository, FakeSkillVersionRepository
from ..db.state_store_postgres import dsn_from_env

VALID_BACKENDS = ("fake", "postgres")


def build_skill_registry(backend: str = "postgres", policy_path: Optional[str] = None) -> SkillRegistry:
    backend = backend.strip().lower()
    if backend not in VALID_BACKENDS:
        raise ValueError(f"unknown skill registry backend {backend!r}; expected 'fake' or 'postgres'")
    if backend == "fake":
        return SkillRegistry(FakeSkillRepository(), FakeSkillVersionRepository(), policy_path=policy_path)
    from ..db.postgres import ConnectionPool, PostgresSkillRepository, PostgresSkillVersionRepository
    pool = ConnectionPool(dsn_from_env())
    return SkillRegistry(PostgresSkillRepository(pool), PostgresSkillVersionRepository(pool), policy_path=policy_path)
