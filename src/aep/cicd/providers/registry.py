"""CI provider registry (Phase 6 Part 1).

Same shape and same honesty discipline as `infra/cloud/registry.py`:
exactly one provider is registered (`github_actions`); GitLab CI, Jenkins,
and a generic webhook-based CI provider are named as architecturally
supported but deliberately NOT stubbed, because a stub that returns "no
runs" is indistinguishable from a real adapter reporting a clean pipeline
- the same false-assurance failure mode Phase 4/5 already documented for
Helm/Azure/GCP/OCI.
"""
from __future__ import annotations

from typing import Optional

from .base import CIProviderAdapter
from .github_actions import PROVIDER as GITHUB_ACTIONS

_REGISTERED = {GITHUB_ACTIONS}

_KNOWN_UNIMPLEMENTED = {
    "gitlab_ci": "no GitLab CI adapter ships in Phase 6 (implement the architecture, fully "
                 "implement one provider first); gitlab.com is not verified reachable from this "
                 "sandbox and no GitLab project exists to test against",
    "jenkins": "no Jenkins adapter ships in Phase 6 (see gitlab_ci); Jenkins requires a "
               "self-hosted server this sandbox does not have",
    "generic": "no generic/webhook-based CI adapter ships in Phase 6; the `CIProviderAdapter` "
               "contract is stable enough to add one without touching any other module",
}


def known_providers() -> list[str]:
    return sorted(_REGISTERED | set(_KNOWN_UNIMPLEMENTED))


def supported_providers() -> list[str]:
    return sorted(_REGISTERED)


def describe_unimplemented(provider: str) -> Optional[str]:
    return _KNOWN_UNIMPLEMENTED.get(provider)
