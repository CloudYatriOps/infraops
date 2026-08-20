"""Plain MAJOR.MINOR.PATCH version parsing/comparison for skill versions
(Stage B Part 12). Deliberately not `packaging.version` - three integers
is the entire contract this platform needs, and pulling in a general
PEP 440 parser for it would be unverified surface area for no benefit.
"""
from __future__ import annotations


def parse_version(version: str) -> tuple[int, int, int]:
    parts = version.strip().split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise ValueError(f"invalid skill version {version!r}; expected MAJOR.MINOR.PATCH")
    a, b, c = parts
    return (int(a), int(b), int(c))


def compare_versions(a: str, b: str) -> int:
    """Returns -1, 0, or 1 (a &lt; b, a == b, a &gt; b)."""
    pa, pb = parse_version(a), parse_version(b)
    if pa < pb:
        return -1
    if pa > pb:
        return 1
    return 0


def satisfies(version: str, constraint: str) -> bool:
    """Supports `"*"` (any), `"==X.Y.Z"` (exact), `">=X.Y.Z"` (minimum)."""
    constraint = constraint.strip()
    if constraint in ("", "*"):
        return True
    if constraint.startswith(">="):
        return compare_versions(version, constraint[2:].strip()) >= 0
    if constraint.startswith("=="):
        return compare_versions(version, constraint[2:].strip()) == 0
    # Bare "X.Y.Z" is treated as an exact match, same as "==X.Y.Z".
    return compare_versions(version, constraint) == 0
