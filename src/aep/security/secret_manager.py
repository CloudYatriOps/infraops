"""Generic REPO-FACING secret-reference abstraction (Phase 4 Part 4).

IMPORTANT - do not confuse this with `src/aep/secrets.py::SecretManager`:
that Protocol resolves credentials the AEP PLATFORM ITSELF needs (e.g. its
own GitHub token) from an approved store at runtime. This module is about
a completely different question: when `SecurityAgent` finds a hardcoded
secret INSIDE A TARGET REPOSITORY it is remediating, what should the
replacement source code look like? i.e. "replace this literal with a
reference to secret X" - the reference shape (`os.environ[...]`, a
HashiCorp Vault lookup, an AWS Secrets Manager call, ...) depends on
whatever secret-management convention that target repo/org uses, which
this platform cannot know in general. Per Part 4's explicit instruction
("do not hard-code AWS/Azure/OCI/etc. into the core - support adapters
later"), only one concrete adapter ships today (`EnvVarSecretReference`,
the same "environment variable by convention" default `EnvSecretManager`
already uses for the platform's own secrets) - the Protocol is what lets a
Vault/AWS/Azure-backed adapter be added later with zero changes to
`remediation.py` or `SecurityAgent`.
"""
from __future__ import annotations

import re
from typing import Protocol


class SecretReferenceManager(Protocol):
    """Describes how to reference a secret from source code, without ever
    needing (or seeing) the secret's actual value."""

    def suggest_env_var_name(self, file_hint: str, rule_id: str) -> str: ...

    def reference_snippet(self, language: str, var_name: str) -> str:
        """Returns the source-code snippet that should replace the
        hardcoded literal, e.g. `os.environ["FOO"]` for python."""
        ...

    def setup_instructions(self, var_name: str) -> str:
        """Human-readable instructions for how an operator makes this
        reference resolve at runtime - never a command that could itself
        leak a value (it names the variable, never a value)."""
        ...


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_").upper()


class EnvVarSecretReference:
    """Default adapter: suggests an environment-variable reference,
    following the exact same naming convention `EnvSecretManager`
    (`src/aep/secrets.py`) already uses for the platform's own secrets -
    consistent mental model for anyone reading both, even though they
    resolve entirely different values."""

    def __init__(self, prefix: str = ""):
        self._prefix = prefix

    def suggest_env_var_name(self, file_hint: str, rule_id: str) -> str:
        base = _slug(rule_id) or "SECRET"
        return f"{self._prefix}{base}"

    def reference_snippet(self, language: str, var_name: str) -> str:
        if language == "python":
            return f'os.environ["{var_name}"]'
        if language in ("node", "javascript", "typescript"):
            return f"process.env.{var_name}"
        # Generic fallback for languages this adapter doesn't special-case -
        # still a reference, never a guess at the value.
        return f"${{{var_name}}}"

    def setup_instructions(self, var_name: str) -> str:
        return (
            f"set the {var_name} environment variable in your deployment/secret-manager "
            f"before running this service; never commit its value to source control"
        )
