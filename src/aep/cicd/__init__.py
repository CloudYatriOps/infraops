"""CI/CD & Deployment Intelligence (Phase 6).

Sibling package to `infra/` and `security/`: plain dataclasses/enums for
pipeline structure, CI provider status, build artifacts, and release
gates, plus a provider-agnostic CI adapter contract (`providers/`) with
exactly one fully-implemented provider (GitHub Actions, reusing the
existing `github/client.py` transport-injection pattern) - the same
"implement the architecture, fully implement ONE provider" discipline
Phase 5 applied to cloud adapters. Nothing here touches the orchestrator,
policy engine, or scanner framework; it only adds to them.
"""
