"""Provider-agnostic CI adapter contract (Phase 6 Part 1).

Mirrors `infra/cloud/base.py`'s shape deliberately: a `Protocol` with a
`status()` real-round-trip check and a normalized result type, so "can
this be reached, and if not why" reads the same way for CI providers as
it does for cloud providers and security scanners. Additional providers
(GitLab CI, Jenkins, a generic webhook-based adapter) implement this same
surface later; nothing outside `cicd/providers/` branches on provider
identity except `registry.py`.
"""
from __future__ import annotations

from typing import Optional, Protocol

from ..models import CIRun, CIStatusResult


class CIProviderAdapter(Protocol):
    provider: str

    def status(self) -> tuple:
        """Returns (CIProviderAvailability, reason) from a REAL round-trip
        attempt when possible - never from "credentials/token are present"
        alone (see `infra/cloud/aws_adapter.py`'s documented false-positive
        for why that check is insufficient)."""
        ...

    def latest_run(self, owner: str, repo: str, branch: Optional[str] = None) -> CIStatusResult: ...

    def list_jobs(self, owner: str, repo: str, run_id: int) -> list[dict]: ...
