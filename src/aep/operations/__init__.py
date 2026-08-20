"""Phase 7: Autonomous Operations & Reliability Intelligence.

Reuses, rather than duplicates, the machinery Phases 1-6 already built:
`PolicyEngine` (deny-by-default action evaluation), `StateStore`/`Event`
(durable evidence and incident memory), `FailureClass` (failure taxonomy,
extended additively), and the four-mode agent shape
(`scan`/`remediate`/`rescan`/`escalate`) already used by
`DependencyCVEAgent`, `SecurityAgent`, and `InfrastructureIntelligenceAgent`.

See ARCHITECTURE.md §28 for the full design rationale.
"""
