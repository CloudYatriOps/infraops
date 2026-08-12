"""Shared secret-pattern detection & redaction.

Used in three places that all matter for the threat model in
ARCHITECTURE.md §16: (1) before any string is placed into an AIProvider
prompt, (2) before tool inputs/outputs are written to the audit event log,
and (3) by SecurityScanAgent as the actual deterministic security gate on
commits. Keeping one implementation means the redaction applied to prompts
and logs can never drift from what the scanner treats as "a secret."
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?")),
    ("private_key_block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----")),
    ("generic_api_key_assignment", re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd)\b\s*[:=]\s*"
        r"['\"]?[A-Za-z0-9\-_./+=]{12,}['\"]?")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("github_fine_grained_pat", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("github_url_embedded_credential", re.compile(r"https://[^\s@/:]+:[^\s@/]+@github\.com")),
    ("high_entropy_generic", re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")),
]

# high_entropy_generic is deliberately last and treated as low-confidence;
# callers can filter it out when they only want high-confidence matches.
HIGH_CONFIDENCE_KINDS = {n for n, _ in _PATTERNS if n != "high_entropy_generic"}


@dataclass
class SecretMatch:
    kind: str
    start: int
    end: int
    snippet: str  # redacted preview, never the raw secret


def find_secrets(text: str, high_confidence_only: bool = True) -> list[SecretMatch]:
    matches: list[SecretMatch] = []
    for kind, pattern in _PATTERNS:
        if high_confidence_only and kind not in HIGH_CONFIDENCE_KINDS:
            continue
        for m in pattern.finditer(text):
            raw = m.group(0)
            preview = raw[:4] + "…redacted…" if len(raw) > 4 else "…redacted…"
            matches.append(SecretMatch(kind=kind, start=m.start(), end=m.end(), snippet=preview))
    return matches


def redact(text: str, high_confidence_only: bool = True) -> str:
    """Return text with any detected secret spans replaced by a placeholder."""
    matches = find_secrets(text, high_confidence_only=high_confidence_only)
    if not matches:
        return text
    matches.sort(key=lambda m: m.start)
    out = []
    cursor = 0
    for m in matches:
        if m.start < cursor:
            continue  # overlapping match, skip
        out.append(text[cursor:m.start])
        out.append(f"[REDACTED:{m.kind}]")
        cursor = m.end
    out.append(text[cursor:])
    return "".join(out)


def redact_literal(text: str, *secret_values: str) -> str:
    """Scrub known exact secret values out of text regardless of whether
    they match any pattern above. This is the backstop used right after a
    subprocess call that may have echoed a credential (e.g. git push output)
    - pattern matching is a second layer, not the only one, per
    ARCHITECTURE.md §16."""
    for value in secret_values:
        if value:
            text = text.replace(value, "[REDACTED]")
    return text


def redact_mapping(d: dict) -> dict:
    """Recursively redact string values in a dict (used for tool inputs/outputs)."""
    result = {}
    for k, v in d.items():
        if isinstance(v, str):
            result[k] = redact(v)
        elif isinstance(v, dict):
            result[k] = redact_mapping(v)
        elif isinstance(v, list):
            result[k] = [redact(x) if isinstance(x, str) else x for x in v]
        else:
            result[k] = v
    return result
