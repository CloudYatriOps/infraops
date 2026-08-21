# Memory Architecture - Stage A slice only

**Scope warning:** this document describes ONLY what Phase 9 Stage A
actually built - a single PostgreSQL + pgvector table
(`memory_records`, see `src/aep/migrations_sql/0001_initial_schema.sql`)
and the repository code in `src/aep/db/repositories.py` /
`src/aep/db/postgres.py` / `src/aep/db/fake.py`. It does not describe a
fully governed memory subsystem - that is later-stage work (Stage
B/C/D's skill registry and AI gateway will be the first real consumers
of this table). Do not read anything below as more complete than it is.

## What exists today

- One table, `memory_records`, with a `memory_class` column covering all
  6 memory classes named in the platform spec: `PROJECT_MEMORY`,
  `ENGINEERING_MEMORY`, `SECURITY_MEMORY`, `OPERATIONAL_MEMORY`,
  `ARCHITECTURAL_MEMORY`, `USER_ORG_MEMORY`. One table rather than six,
  because every class needs the same operations (structured lookup,
  semantic ANN search, exact fingerprint lookup, supersession, advisory
  retrieval) - see `src/aep/migrations_sql/0001_initial_schema.sql`'s
  comment for the full justification.
- Structured metadata: `content jsonb`.
- Semantic retrieval: `embedding vector(8)` (pgvector), with a real
  `ivfflat`/cosine ANN index (`idx_memory_embedding_ann`), proven against
  real test vectors in `tests/test_db_repositories_postgres.py::
  test_memory_repository_real_postgres_ann_cosine_search` and the fake
  double in `tests/test_db_repositories_fake.py::
  test_memory_ann_search_orders_by_cosine_similarity`. The dimension (8)
  is a deliberately small placeholder for Stage A's test vectors, not a
  production embedding-model dimension.
- Exact retrieval: `fingerprint text` (indexed), for content-hash-style
  exact lookups.
- Evidence linkage: `evidence_ref text`.
- Confidence: `confidence double precision`.
- Source: `source text`.
- Scope: `project_scope uuid` (references `projects`); `org_scope uuid`
  is present but nullable/unused - no organizations table exists yet in
  Stage A, so this is explicitly deferred rather than silently omitted.
- Lifecycle: `lifecycle_state text` (`ACTIVE`/`SUPERSEDED`/`ARCHIVED`/
  `RETRACTED`) plus a self-referential `superseded_by uuid` pointer -
  `MemoryRepository.supersede()` marks the old row `SUPERSEDED` and
  points it at the new row; it never deletes the old row.
- Advisory-only retrieval: `MemoryRepository.retrieve()` always returns
  `(record, True)` pairs - the `True` is not a placeholder, it is the
  contract: memory is always advisory context for the caller to weigh
  against current evidence. The memory layer itself never mutates any
  decision state. See `tests/test_db_repositories_fake.py::
  test_memory_retrieval_is_always_advisory_and_never_mutates_caller_state`.

## What is explicitly NOT implemented (deferred)

- **Real embedding generation.** Nothing in this stage calls an embedding
  model. Every embedding used in tests is a hand-constructed test vector.
  This is honestly marked `NOT_IMPLEMENTED`, not faked.
- **The 6-class governance model** (who can write which class, retention/
  redaction policy per class, cross-project memory sharing rules). Stage
  A only proves the storage/retrieval mechanics work; policy over *how*
  memory is used belongs to a later stage (likely Stage D, governance).
- **Organization scoping.** `org_scope` exists as a column but is
  unpopulated - Stages B/C/D introduce the organization/multi-tenant
  model this column will actually serve.
- **Row-Level Security policies.** Not implemented in Stage A. See
  ARCHITECTURE.md Section 30 for the RLS foundation/plan.
