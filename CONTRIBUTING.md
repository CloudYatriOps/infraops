# Contributing to AEP

## Development model: pull requests only

**Do not push directly to `main`.** `main` is protected - direct pushes are
rejected. Every change goes through a feature branch and a pull request:

```
feature branch → commit → local validation → push branch → open PR → CI → review/approval → merge
```

### 1. Create a feature branch

```bash
git checkout -b your-name/short-description
```

### 2. Make your change

Keep it scoped - a bug fix doesn't need an unrelated refactor riding along.

### 3. Run local validation before opening a PR

```bash
# Python
python -m pip install -e ".[all,dev]"
python -m compileall -q src
python -m pytest -q                       # full suite once, after your change is stable

# Security scan of the repo itself (AEP scanning its own source)
python -m aep.cli security . --json

# UI (only if you touched ui/)
cd ui && npm ci && npx tsc --noEmit && VITE_API_BASE= npx vite build --outDir ../src/aep/ui_dist --emptyOutDir

# Package build (only if you touched pyproject.toml/packaging)
python -m build && python -m twine check dist/*
```

If your change touches `src/aep/migrations_sql/`, also run:

```bash
python -m pytest -q tests/test_db_migrations.py tests/test_db_schema_drift.py
```

and see "Database migrations" below before opening the PR.

### 4. Push your branch and open a pull request

```bash
git push -u origin your-name/short-description
gh pr create
```

Fill in the PR template completely - Summary, Why, Scope, Tests, Security
impact, Migration impact, Rollback/recovery, Evidence, Breaking changes.
"None"/"N/A" is a fine answer where genuinely true, but say so explicitly.

### 5. CI and review

- CI (`.github/workflows/ci.yml`) must pass: syntax check, full test suite,
  a built-in security scan of the repository, UI typecheck/build, and a
  package build + `twine check`.
- At least one approval is required.
- Resolve all review conversations before merging.
- Pushing new commits to an already-approved PR dismisses the stale
  approval - re-request review after addressing feedback.

### 6. Merge

Once CI is green and the PR is approved, merge it. Do not force-push to
`main` or delete `main` - both are blocked by branch protection.

## Database migrations

`src/aep/migrations_sql/` is the single source of truth for schema
changes (see `src/aep/db/migrations.py`'s module docstring). Rules:

- **Never edit an already-applied migration file.** Add a new one instead,
  even to fix a mistake in a previous one.
- Prefer additive changes (`ADD COLUMN`, `CREATE TABLE`) over anything that
  could destroy data.
- Explain the affected tables, the backward-compatibility story, and the
  rollback approach in the migration file's own header comment (see any
  existing migration for the convention).
- Run `tests/test_db_migrations.py` and `tests/test_db_schema_drift.py`
  before opening the PR - the drift detector will catch a schema change
  that isn't correctly declared in a migration file.

## Security-sensitive changes

If your change touches secret detection/redaction, the policy engine, API
authentication, or anything that decides what gets read/written/executed,
say so explicitly in the PR's "Security impact" section and describe how
you verified it (a test that would fail if the protection regressed is
the strongest evidence).

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md) - please do not open a public issue for a
suspected vulnerability.
