"""Tool abstraction & capability-scoped registry.

Agents never get raw access to a Tool implementation; they get a
`ScopedRegistry` limited to the capability strings they declared, and every
invocation is logged through the provided EventLogger with inputs/outputs
redacted. This is the enforcement point for §6 and §16 of ARCHITECTURE.md.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .events import EventLogger
from .models import RiskLevel


@dataclass
class Tool:
    name: str
    capabilities: set[str]
    risk: RiskLevel
    description: str
    # handler receives (capability, **kwargs) -> dict result
    handler: Callable[..., dict]


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, Tool] = {}
        # capability -> tool name, so lookups by capability are O(1)
        self._capability_index: dict[str, str] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool
        for cap in tool.capabilities:
            if cap in self._capability_index and self._capability_index[cap] != tool.name:
                raise ValueError(f"capability '{cap}' already claimed by tool "
                                  f"'{self._capability_index[cap]}'")
            self._capability_index[cap] = tool.name

    def all_capabilities(self) -> set[str]:
        return set(self._capability_index.keys())

    def scoped_for(self, capabilities: set[str], actor: str, project_id: str,
                    logger: Optional[EventLogger] = None) -> "ScopedRegistry":
        unknown = capabilities - self.all_capabilities()
        if unknown:
            raise ValueError(f"unknown capabilities requested: {unknown}")
        return ScopedRegistry(self, capabilities, actor, project_id, logger)


class PermissionError(Exception):
    pass


class ScopedRegistry:
    """A view of the ToolRegistry limited to a fixed set of capabilities."""

    def __init__(self, registry: ToolRegistry, allowed_capabilities: set[str],
                 actor: str, project_id: str, logger: Optional[EventLogger]):
        self._registry = registry
        self._allowed = allowed_capabilities
        self._actor = actor
        self._project_id = project_id
        self._logger = logger

    def call(self, capability: str, task_id: Optional[str] = None, **kwargs) -> dict:
        if capability not in self._allowed:
            if self._logger:
                self._logger.log(
                    actor=self._actor, action="tool_call_denied",
                    project_id=self._project_id, task_id=task_id,
                    decision="DENY",
                    details={"capability": capability, "reason": "not in agent's scoped capabilities"},
                )
            raise PermissionError(
                f"actor '{self._actor}' does not have capability '{capability}'"
            )
        tool_name = self._registry._capability_index[capability]
        tool = self._registry._tools[tool_name]
        result = tool.handler(capability, **kwargs)
        if self._logger:
            self._logger.log(
                actor=self._actor, action="tool_call",
                project_id=self._project_id, task_id=task_id,
                decision="EXECUTED",
                details={"tool": tool_name, "capability": capability,
                         "inputs": kwargs, "result": result},
            )
        return result
