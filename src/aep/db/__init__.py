"""Stage A PostgreSQL persistence foundation (Phase 9 Stage A).

This package is the new, canonical-going-forward persistence layer built
on real PostgreSQL (+ pgvector for memory). It does NOT replace
`aep.state_store.StateStore` in this stage - that remains Phase 1-8's
tested production path. See ARCHITECTURE.md Section 30 for the full
design discussion and existing-state mapping.
"""
