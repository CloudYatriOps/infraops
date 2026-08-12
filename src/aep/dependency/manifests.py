"""Dependency manifest discovery.

Walks a project root for real manifest files. Deliberately NOT Python-only
(Phase 3 instruction: "do not assume Python only") - Node.js, Go, and
container manifests are discovered the same way Python's are. Whether a
discovered manifest actually gets *scanned* depends on whether a scanner
for its ecosystem is available in this environment (see
`dependency/inventory.py`) - discovery and scanning are deliberately
separate steps so "we found a go.mod but can't scan it here" is a
recorded, honest fact rather than a silent gap.
"""
from __future__ import annotations

import os
from pathlib import Path

from .models import DependencyManifest, Ecosystem

_IGNORED_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".tox"}

# (filename, ecosystem, format-label). Order doesn't matter; a directory can
# legitimately contain more than one manifest (e.g. requirements.txt AND
# package.json in a mixed-language repo).
_PATTERNS = [
    ("requirements.txt", Ecosystem.PYTHON, "requirements.txt"),
    ("requirements-dev.txt", Ecosystem.PYTHON, "requirements.txt"),
    ("pyproject.toml", Ecosystem.PYTHON, "pyproject.toml"),
    ("package.json", Ecosystem.NODE, "package.json"),
    ("go.mod", Ecosystem.GO, "go.mod"),
    ("Dockerfile", Ecosystem.CONTAINER, "Dockerfile"),
]


def discover_manifests(project_root: str) -> list[DependencyManifest]:
    root = Path(project_root).resolve()
    found: list[DependencyManifest] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _IGNORED_DIRS]
        for fname in filenames:
            for pattern, ecosystem, fmt in _PATTERNS:
                if fname == pattern:
                    rel = str(Path(dirpath, fname).resolve().relative_to(root))
                    found.append(DependencyManifest(ecosystem=ecosystem, path=rel, format=fmt))
    return found
