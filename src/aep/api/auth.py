"""Minimal per-request API-key auth boundary (Stage D Wave 1, item 2).

A key is a random 32-byte token issued once and shown to the caller
exactly one time (`issue_key`) - only its sha256 hash is ever persisted
(`api_keys.key_hash`, migration 0007). `project_scope` is nullable: NULL
means the key is org-wide (any project), a project id scopes the key to
that one project only - this is the minimal seed of organization/project
isolation; a real org/user model is a documented future step (see
docs/API.md), not built here.

`AEP_API_DEV_MODE=1` disables this entirely for local demo convenience -
loud, obvious, printed once at app startup, never silent. This is a
documented dev-only security boundary (docs/API.md), never meant for a
shared/production deployment.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import uuid
from dataclasses import dataclass
from typing import Optional

from ..db.postgres import ConnectionPool


def hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def generate_raw_key() -> str:
    return "aep_" + secrets.token_urlsafe(32)


@dataclass
class ApiKeyCheckResult:
    ok: bool
    project_scope: Optional[str] = None
    reason: str = ""


def issue_key(pool: ConnectionPool, label: str = "", project_scope: Optional[str] = None) -> tuple[str, str]:
    """Creates a new key, returns (key_id, raw_key). The raw key is
    returned to the caller ONCE here and never again - only its hash is
    stored."""
    raw_key = generate_raw_key()
    key_id = str(uuid.uuid4())
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO api_keys (key_id, key_hash, project_scope, label) VALUES (%s, %s, %s, %s)",
                (key_id, hash_key(raw_key), project_scope, label),
            )
        conn.commit()
    finally:
        pool.putconn(conn)
    return key_id, raw_key


def verify_key(pool: ConnectionPool, raw_key: Optional[str]) -> ApiKeyCheckResult:
    if not raw_key:
        return ApiKeyCheckResult(ok=False, reason="missing Authorization: Bearer <key> header")
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT project_scope FROM api_keys WHERE key_hash = %s AND revoked_at IS NULL",
                (hash_key(raw_key),),
            )
            row = cur.fetchone()
    finally:
        pool.putconn(conn)
    if row is None:
        return ApiKeyCheckResult(ok=False, reason="invalid or revoked API key")
    return ApiKeyCheckResult(ok=True, project_scope=str(row[0]) if row[0] else None)


def revoke_key(pool: ConnectionPool, key_id: str) -> None:
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE api_keys SET revoked_at = now() WHERE key_id = %s", (key_id,))
        conn.commit()
    finally:
        pool.putconn(conn)


def dev_mode_enabled() -> bool:
    return os.environ.get("AEP_API_DEV_MODE") == "1"
