"""Agent contract. Every agent is `run(task, ctx) -> TaskResult`; it never
touches the state store, policy engine internals, or another agent
directly - only what AgentContext exposes (ARCHITECTURE.md §5)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ..events import EventLogger
from ..models import ProjectConfig, Task, TaskResult
from ..policy import PolicyEngine
from ..providers.router import ModelRouter
from ..tool_registry import ScopedRegistry, ToolRegistry


@dataclass
class AgentContext:
    tools: ScopedRegistry
    router: ModelRouter
    policy: PolicyEngine
    project: ProjectConfig
    logger: EventLogger


class Agent(Protocol):
    name: str
    required_capabilities: set[str]

    def run(self, task: Task, ctx: AgentContext) -> TaskResult: ...


def build_context(task: Task, agent: Agent, tool_registry: ToolRegistry,
                   router: ModelRouter, policy: PolicyEngine,
                   project: ProjectConfig, logger: EventLogger) -> AgentContext:
    scoped = tool_registry.scoped_for(
        agent.required_capabilities, actor=agent.name,
        project_id=project.id, logger=logger,
    )
    return AgentContext(tools=scoped, router=router, policy=policy,
                          project=project, logger=logger)
