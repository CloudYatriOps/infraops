"""Sandboxed filesystem access, restricted to a project root and denylist.

Real filesystem I/O (no mocking) but with a hard boundary: any path outside
the configured project root raises, and paths under `config/` (the
platform's own policy files) are always denied — this is the concrete
enforcement referenced in ARCHITECTURE.md §16 (self-modification/overreach
protection).
"""
from __future__ import annotations

import os
from pathlib import Path

from ..models import RiskLevel
from ..tool_registry import Tool

_DENIED_SUBPATHS = ("config/",)


def _resolve_safe(project_root: str, rel_path: str) -> Path:
    root = Path(project_root).resolve()
    target = (root / rel_path).resolve()
    if not str(target).startswith(str(root)):
        raise PermissionError(f"path '{rel_path}' escapes project root")
    norm_rel = str(target.relative_to(root)).replace(os.sep, "/")
    for denied in _DENIED_SUBPATHS:
        if norm_rel.startswith(denied):
            raise PermissionError(f"path '{rel_path}' is in a denied location ({denied})")
    return target


def _handler(capability: str, **kwargs) -> dict:
    project_root = kwargs["project_root"]

    if capability == "filesystem.read":
        path = _resolve_safe(project_root, kwargs["path"])
        if not path.exists():
            return {"ok": False, "error": "not found"}
        if path.is_dir():
            return {"ok": False, "error": "is a directory"}
        try:
            content = path.read_text()
        except (UnicodeDecodeError, ValueError):
            # Binary/non-utf8 file (e.g. a stray db/image under the project
            # root). Reported as a clean, expected miss rather than an
            # uncaught exception - a crash here would otherwise surface as
            # a generic TOOL failure and get retried/quarantined for no
            # real reason (caught by the manual end-to-end smoke test).
            return {"ok": False, "error": "binary or non-utf8 content, skipped"}
        return {"ok": True, "content": content}

    if capability == "filesystem.write":
        path = _resolve_safe(project_root, kwargs["path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(kwargs["content"])
        return {"ok": True, "path": str(path)}

    if capability == "filesystem.list":
        rel = kwargs.get("path", ".")
        base = _resolve_safe(project_root, rel)
        entries = sorted(str(p.relative_to(Path(project_root).resolve())) for p in base.rglob("*")
                          if ".git" not in p.parts and p.is_file())
        return {"ok": True, "entries": entries}

    raise ValueError(f"unsupported capability for filesystem tool: {capability}")


def build_filesystem_tool() -> Tool:
    return Tool(
        name="filesystem",
        capabilities={"filesystem.read", "filesystem.write", "filesystem.list"},
        risk=RiskLevel.MEDIUM,
        description="Sandboxed read/write/list scoped to a project root; config/ is always denied.",
        handler=_handler,
    )
