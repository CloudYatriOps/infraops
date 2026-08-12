"""Deployment abstraction + verification + rollback (Phase 6 Part 7-10,
13). Sibling package to `cicd/`: `provider.py` is the vendor-agnostic
contract (`plan`/`deploy`/`status`/`verify`/`rollback`), `local_provider.py`
is the one fully-implemented, safe-by-default provider (a deterministic
local fixture "cluster"), and `kubernetes_provider.py` is the architecture
for a real cluster with an honest UNAVAILABLE status in this sandbox (no
`kubectl`, no cluster - verified during Phase 6 investigation).
"""
