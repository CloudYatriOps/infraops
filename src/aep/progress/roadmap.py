"""Loads the versioned, machine-readable platform roadmap (Phase 3 Part G).

`config/roadmap.yaml` is the single source of truth for what phases and
capabilities exist. ARCHITECTURE.md's prose roadmap section describes
history/design and must stay *consistent* with this file, but this file is
what `aep status`/`aep progress`/any future dashboard actually reads -
never a hardcoded percentage in a doc.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import yaml


@dataclass
class CapabilityDef:
    id: str
    description: str
    test_paths: list[str] = field(default_factory=list)
    blocked: bool = False
    blocked_reason: str = ""


@dataclass
class PhaseDef:
    id: int
    name: str
    description: str
    capabilities: list[CapabilityDef] = field(default_factory=list)


@dataclass
class Roadmap:
    version: int
    phases: list[PhaseDef]


def load_roadmap(path: str) -> Roadmap:
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    phases: list[PhaseDef] = []
    for p in data.get("phases", []):
        caps = [
            CapabilityDef(
                id=c["id"], description=(c.get("description") or "").strip(),
                test_paths=list(c.get("test_paths") or []),
                blocked=bool(c.get("blocked", False)),
                blocked_reason=(c.get("blocked_reason") or "").strip(),
            )
            for c in p.get("capabilities", [])
        ]
        phases.append(PhaseDef(id=p["id"], name=p["name"],
                                description=(p.get("description") or "").strip(), capabilities=caps))
    phases.sort(key=lambda ph: ph.id)
    return Roadmap(version=data.get("version", 1), phases=phases)
