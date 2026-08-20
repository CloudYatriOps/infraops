# Deployment (Stage D)

This is a local/dev deployment note, not a production infra build-out —
see the "future production architecture" paragraph at the bottom for what
a real deployment would add.

## Clean local deployment sequence

```bash
git clone <repo> && cd aep-platform

# Install (installs psycopg2/pgvector as required deps - BUG-0004 fix)
pip install -e .

# Bootstrap / migrate (see docs/BOOTSTRAP.md for full detail)
export AEP_PG_PASSWORD=aep_local_dev_only
scripts/bootstrap.sh

# Start the API (dev mode for local convenience - never in a shared env)
export AEP_API_DEV_MODE=1
python3 -m flask --app 'aep.api.app:create_app()' run

# Start the UI (separate shell)
cd ui && npm install && npm run dev

# Run the CEO demo (works standalone, with or without the API/UI running)
aep demo run
aep demo run --scenario ambiguous
aep demo readiness
```

## Future production deployment architecture (not built here)

A production deployment would containerize the API (`src/aep/api/app.py`
behind gunicorn) and the built UI (`ui/dist/`, served as static assets)
as separate images, run against a managed PostgreSQL instance (e.g. RDS
or Supabase-hosted Postgres with pgvector enabled) rather than a local
Postgres role, pull `AEP_PG_PASSWORD`/`AI_CREDENTIAL`/API-key material from
a secrets manager (e.g. AWS Secrets Manager or Vault) instead of shell
env vars, and put a load balancer / reverse proxy (with TLS termination
and real auth, replacing `AEP_API_DEV_MODE`) in front of the API so the
UI and any other client only ever reach it through that boundary.
