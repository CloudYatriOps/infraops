"""The platform's approved secret mechanism (ARCHITECTURE.md §11/§16).

Nothing in this codebase accepts a raw credential as a literal value in a
Task payload, a ProjectConfig, or a YAML config file. Every tool that needs
one (currently: the GitHub tool) is handed a `SecretManager` at construction
time and resolves the value fresh on every call via `.get(name)` - never
cached in a way that could leak into an event, a prompt, or Task state.

`EnvSecretManager` is the concrete Phase 1/2 implementation: it reads from
environment variables by a fixed naming convention, which is the sandbox's
only available "approved" store. A production deployment would swap this
for an AWS Secrets Manager / Vault-backed implementation of the exact same
two-method protocol, with zero changes anywhere else in the platform - the
same adapter pattern ARCHITECTURE.md §7 uses for AI providers.
"""
from __future__ import annotations

import os
from typing import Protocol


class SecretNotFoundError(RuntimeError):
    pass


class SecretManager(Protocol):
    def get(self, name: str) -> str: ...
    def has(self, name: str) -> bool: ...


class EnvSecretManager:
    """Resolves `name` -> the environment variable `{prefix}{NAME_UPPER}`.

    e.g. get("github_token") reads AEP_SECRET_GITHUB_TOKEN. This is a
    deliberately narrow convention: it is never confused with an agent's own
    task payload data because agents cannot read the process environment
    directly (they only have what AgentContext hands them), and no code path
    copies an environment variable into a Task, Event, or GenerationRequest.
    """

    def __init__(self, prefix: str = "AEP_SECRET_"):
        self._prefix = prefix

    def _env_key(self, name: str) -> str:
        return f"{self._prefix}{name.upper()}"

    def get(self, name: str) -> str:
        key = self._env_key(name)
        value = os.environ.get(key)
        if not value:
            raise SecretNotFoundError(
                f"secret '{name}' not found (expected environment variable {key} to be set)"
            )
        return value

    def has(self, name: str) -> bool:
        return bool(os.environ.get(self._env_key(name)))


class StaticSecretManager:
    """In-memory secret manager for tests only. Never used outside tests -
    production wiring always goes through EnvSecretManager (or a future
    Vault/Secrets-Manager-backed implementation)."""

    def __init__(self, values: dict[str, str]):
        self._values = dict(values)

    def get(self, name: str) -> str:
        if name not in self._values:
            raise SecretNotFoundError(f"secret '{name}' not found in StaticSecretManager")
        return self._values[name]

    def has(self, name: str) -> bool:
        return name in self._values
