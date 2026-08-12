"""Dependency & CVE intelligence (Phase 3, Part A/B).

Kept as its own package, parallel to `github/`, rather than folded into
existing modules - the same "vendor/domain logic lives outside the core"
principle `github/planner.py` documents. Nothing in `orchestrator.py`,
`models.py`, or `tool_registry.py` was changed to add this.
"""
