"""Stage B Part 3/4: real PostgreSQL persistence for the skill registry -
against actual local Postgres, verified with an INDEPENDENT connection
(never trusting only the writer's own return values), plus proof that the
immutability guarantee holds at the DATABASE layer (a raw UPDATE via a
second, independent connection is rejected by the trigger), not merely by
application discipline.
"""
from __future__ import annotations

import uuid

import psycopg2
import pytest

from aep.db.postgres import (
    ConnectionPool,
    PostgresSkillRepository,
    PostgresSkillVersionRepository,
    dsn_from_parts,
)
from aep.skills.models import LifecycleState, RiskLevel, Skill, SkillDependency, SkillVersion
from aep.skills.registry import SkillImmutabilityError, SkillRegistry

LOCAL_DSN = dsn_from_parts("localhost", 5432, "aep", "aep_local_dev_only", "aep_platform")


@pytest.fixture()
def pg_registry():
    pool = ConnectionPool(LOCAL_DSN)
    registry = SkillRegistry(PostgresSkillRepository(pool), PostgresSkillVersionRepository(pool),
                              policy_path="config/policy.yaml")
    yield registry
    pool.closeall()


def _unique_skill_id() -> str:
    return f"test_skill_{uuid.uuid4().hex[:8]}"


def test_publish_persists_and_is_independently_readable(pg_registry):
    skill_id = _unique_skill_id()
    pg_registry.register_skill(Skill(skill_id=skill_id, name="Test Skill"))
    pg_registry.publish(SkillVersion(skill_id=skill_id, version="1.0.0", allowed_tools=["shell.run"]))

    # Independent connection - no shared Python objects with the writer.
    conn = psycopg2.connect(LOCAL_DSN)
    try:
        cur = conn.cursor()
        cur.execute("SELECT skill_id, name FROM skills WHERE skill_id=%s", (skill_id,))
        row = cur.fetchone()
        assert row is not None
        assert row[0] == skill_id
        cur.execute("SELECT skill_id, version, lifecycle_state FROM skill_versions WHERE skill_id=%s", (skill_id,))
        vrow = cur.fetchone()
        assert vrow == (skill_id, "1.0.0", "published")
    finally:
        conn.close()


def test_dependency_rows_persist_and_are_independently_readable(pg_registry):
    parent_id = _unique_skill_id()
    dep_id = _unique_skill_id()
    pg_registry.register_skill(Skill(skill_id=dep_id, name="Dep"))
    pg_registry.register_skill(Skill(skill_id=parent_id, name="Parent"))
    pg_registry.publish(SkillVersion(skill_id=dep_id, version="1.0.0"))
    pg_registry.publish(SkillVersion(skill_id=parent_id, version="1.0.0",
                                       dependencies=[SkillDependency(dep_id, ">=1.0.0")]))
    conn = psycopg2.connect(LOCAL_DSN)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT depends_on_skill_id, version_constraint FROM skill_dependencies sd "
            "JOIN skill_versions sv ON sv.id = sd.skill_version_id "
            "WHERE sv.skill_id=%s AND sv.version=%s",
            (parent_id, "1.0.0"),
        )
        rows = cur.fetchall()
        assert rows == [(dep_id, ">=1.0.0")]
    finally:
        conn.close()


def test_republishing_existing_version_is_rejected_at_app_layer(pg_registry):
    skill_id = _unique_skill_id()
    pg_registry.register_skill(Skill(skill_id=skill_id, name="Test Skill"))
    pg_registry.publish(SkillVersion(skill_id=skill_id, version="1.0.0"))
    with pytest.raises(SkillImmutabilityError):
        pg_registry.publish(SkillVersion(skill_id=skill_id, version="1.0.0", description="different"))


def test_database_trigger_rejects_raw_update_of_published_content(pg_registry):
    """Proves immutability holds even against a caller that bypasses the
    Python repository layer entirely (a raw psycopg2 UPDATE from an
    INDEPENDENT connection) - the migration 0006 trigger, not just
    application discipline."""
    skill_id = _unique_skill_id()
    pg_registry.register_skill(Skill(skill_id=skill_id, name="Test Skill"))
    pg_registry.publish(SkillVersion(skill_id=skill_id, version="1.0.0", description="original"))

    conn = psycopg2.connect(LOCAL_DSN)
    try:
        cur = conn.cursor()
        with pytest.raises(psycopg2.errors.RaiseException):
            cur.execute(
                "UPDATE skill_versions SET description='HACKED' WHERE skill_id=%s AND version=%s",
                (skill_id, "1.0.0"),
            )
        conn.rollback()
        # Content is genuinely untouched - re-read to confirm, not assumed.
        cur.execute("SELECT description FROM skill_versions WHERE skill_id=%s AND version=%s",
                    (skill_id, "1.0.0"))
        assert cur.fetchone()[0] == "original"
    finally:
        conn.close()


def test_database_trigger_allows_the_one_way_deprecate_transition(pg_registry):
    skill_id = _unique_skill_id()
    pg_registry.register_skill(Skill(skill_id=skill_id, name="Test Skill"))
    pg_registry.publish(SkillVersion(skill_id=skill_id, version="1.0.0"))
    pg_registry.deprecate(skill_id, "1.0.0")
    assert pg_registry.is_deprecated(skill_id, "1.0.0")

    conn = psycopg2.connect(LOCAL_DSN)
    try:
        cur = conn.cursor()
        cur.execute("SELECT lifecycle_state FROM skill_versions WHERE skill_id=%s AND version=%s",
                    (skill_id, "1.0.0"))
        assert cur.fetchone()[0] == "deprecated"
    finally:
        conn.close()


def test_real_canonical_seed_round_trips_through_real_postgres(pg_registry):
    """The real 18-skill canonical set, seeded through the real registry
    path against real Postgres, then re-read via a brand-new registry
    instance backed by a fresh connection pool (simulating a fresh
    process)."""
    from aep.skills.definitions import seed_canonical_skills
    seed_canonical_skills(pg_registry)  # idempotent if already seeded by another test run

    fresh_pool = ConnectionPool(LOCAL_DSN)
    try:
        fresh_registry = SkillRegistry(PostgresSkillRepository(fresh_pool),
                                        PostgresSkillVersionRepository(fresh_pool),
                                        policy_path="config/policy.yaml")
        security = fresh_registry.latest_version("security")
        assert security.version == "1.0.0"
        assert "gitleaks" in security.required_checks
        dep_res = fresh_registry.resolve_dependencies("deployment", "1.0.0")
        assert dep_res.ok
    finally:
        fresh_pool.closeall()
