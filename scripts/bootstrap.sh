#!/usr/bin/env bash
# Local dev bootstrap for the AEP platform. See docs/BOOTSTRAP.md for the
# full explanation of every step and its failure modes. This script never
# assumes `service postgresql start` exists (that's specific to this
# project's own sandbox) - it only checks whether Postgres is reachable
# and tells you how to fix it if not.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# --check-only: verify the bootstrap PRECONDITIONS (env var set, Postgres
# reachable, `aep` importable) without installing packages or applying
# migrations - safe to run repeatedly in CI/sandbox without mutating any
# state. Added Stage D Wave 2 for tests/test_bootstrap_script.py.
CHECK_ONLY=0
if [ "${1:-}" = "--check-only" ]; then
    CHECK_ONLY=1
fi

echo "== 1/5: installing Python dependencies =="
if [ "$CHECK_ONLY" = "1" ]; then
    echo "(--check-only: skipped)"
else
    # BUG-0004 fix: psycopg2-binary/pgvector are now REQUIRED dependencies
    # (pyproject.toml), so this one install command is enough - no extras
    # flag needed for the default (Postgres) runtime path to work.
    pip install -e ".[dev,api]"
fi

echo "== 2/5: checking AEP_PG_PASSWORD / AEP_DB_BACKEND =="
: "${AEP_DB_BACKEND:=postgres}"
if [ "$AEP_DB_BACKEND" = "postgres" ] && [ -z "${AEP_PG_PASSWORD:-}" ]; then
    echo "AEP_PG_PASSWORD is not set and AEP_DB_BACKEND=postgres (the default)."
    echo "Set it before running anything that touches the default backend, e.g.:"
    echo "  export AEP_PG_PASSWORD=aep_local_dev_only   # matches docs/DATABASE.md's local dev convention"
    exit 1
fi
echo "AEP_DB_BACKEND=$AEP_DB_BACKEND"

echo "== 3/5: checking PostgreSQL is reachable =="
PGHOST="${AEP_PG_HOST:-localhost}"
PGPORT="${AEP_PG_PORT:-5432}"
PGUSER="${AEP_PG_USER:-aep}"
PGDBNAME="${AEP_PG_DBNAME:-aep_platform}"
if command -v pg_isready >/dev/null 2>&1; then
    if ! PGPASSWORD="${AEP_PG_PASSWORD:-}" pg_isready -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDBNAME" >/dev/null 2>&1; then
        echo "PostgreSQL is not reachable at $PGHOST:$PGPORT (db=$PGDBNAME, user=$PGUSER)."
        echo "This script does not assume any particular service manager. Common fixes:"
        echo "  - This sandbox / a systemd-less container: service postgresql start"
        echo "  - A systemd host:                          sudo systemctl start postgresql"
        echo "  - Docker:                                  docker run -e POSTGRES_USER=$PGUSER ... postgres:16"
        echo "Then re-run this script."
        exit 1
    fi
else
    echo "pg_isready not found; falling back to a direct python connection check."
    python3 - <<PYEOF
import os, sys
sys.path.insert(0, "src")
try:
    import psycopg2
    psycopg2.connect(host="$PGHOST", port=$PGPORT, user="$PGUSER",
                      password=os.environ.get("AEP_PG_PASSWORD", ""),
                      dbname="$PGDBNAME", connect_timeout=3).close()
except Exception as exc:
    print(f"PostgreSQL is not reachable: {exc}")
    sys.exit(1)
PYEOF
fi
echo "PostgreSQL is reachable."

echo "== 4/5: running pending migrations =="
if [ "$CHECK_ONLY" = "1" ]; then
    echo "(--check-only: skipped - no migrations applied)"
else
python3 - <<'PYEOF'
import sys
sys.path.insert(0, "src")
import psycopg2
from aep.db.migrations import apply_pending
from aep.db.state_store_postgres import dsn_from_env

conn = psycopg2.connect(dsn_from_env())
applied = apply_pending(conn)
conn.commit()
print(f"applied migrations: {applied or '(none pending)'}")
PYEOF
fi

echo "== 5/5: sanity-checking the CLI entrypoint =="
# There is no installed `aep` console-script entry point (checked
# pyproject.toml - none declared); the CLI is always invoked as
# `python -m aep.cli`, matching every example in README.md/docs/DEMO.md.
python3 -m aep.cli --help >/dev/null
echo "python3 -m aep.cli --help ran successfully."

cat <<'EOF'

Bootstrap complete.

Known, expected sandbox limitations (not bootstrap failures):
  - Live OmniRoute (AI_BASE_URL/AI_CREDENTIAL unset) is UNAVAILABLE by
    design in a constrained sandbox - `aep providers` reports this
    honestly rather than faking a call.
  - Live GitHub API / live Kubernetes access may be BLOCKED by network
    egress policy in constrained sandboxes - any endpoint/command that
    needs them reports BLOCKED/UNAVAILABLE explicitly rather than
    silently succeeding or failing.

See docs/BOOTSTRAP.md and docs/API.md for what to run next.
EOF
