"""Part 5: operational service dependency graph.

This is deliberately a NEW, narrower concept from `infra/drift.py`'s
infrastructure-resource drift detection - that module reasons about
Terraform/Kubernetes resource drift, not runtime service call
relationships. Nothing here duplicates it; this graph is a simple directed
adjacency structure (service -> the services/resources it calls) built from
a deterministic fixture (a plain dict), used only to compute blast radius
during incident analysis.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class BlastRadius:
    service: str
    directly_affected: list[str]
    upstream_dependencies: list[str]
    downstream_services: list[str]
    potentially_affected_deployments: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class ServiceDependencyGraph:
    """`edges[a] = [b, c]` means service `a` DEPENDS ON `b` and `c` (a
    calls/relies on them) - e.g. `edges["service-a"] = ["database"]`,
    `edges["database"] = []`, matching the Part 5 example
    `Service A -> Database -> Cache -> Message Queue -> External API`."""

    def __init__(self, edges: dict[str, list[str]] | None = None,
                 deployments: dict[str, str] | None = None):
        self.edges: dict[str, list[str]] = {k: list(v) for k, v in (edges or {}).items()}
        # service -> deployment/version identifier, for
        # "potentially affected deployments".
        self.deployments: dict[str, str] = dict(deployments or {})

    def add_dependency(self, service: str, depends_on: str) -> None:
        self.edges.setdefault(service, [])
        if depends_on not in self.edges[service]:
            self.edges[service].append(depends_on)
        self.edges.setdefault(depends_on, [])

    def upstream(self, service: str) -> list[str]:
        """Services/resources `service` depends on, transitively."""
        seen: list[str] = []
        stack = list(self.edges.get(service, []))
        while stack:
            node = stack.pop(0)
            if node in seen:
                continue
            seen.append(node)
            stack.extend(self.edges.get(node, []))
        return seen

    def downstream(self, service: str) -> list[str]:
        """Services that depend on `service`, transitively (reverse
        edges)."""
        reverse: dict[str, list[str]] = {}
        for node, deps in self.edges.items():
            for dep in deps:
                reverse.setdefault(dep, []).append(node)
        seen: list[str] = []
        stack = list(reverse.get(service, []))
        while stack:
            node = stack.pop(0)
            if node in seen:
                continue
            seen.append(node)
            stack.extend(reverse.get(node, []))
        return seen

    def blast_radius(self, service: str) -> BlastRadius:
        upstream = self.upstream(service)
        downstream = self.downstream(service)
        affected_services = [service, *downstream]
        deployments = sorted({self.deployments[s] for s in affected_services
                               if s in self.deployments})
        return BlastRadius(
            service=service, directly_affected=[service],
            upstream_dependencies=upstream, downstream_services=downstream,
            potentially_affected_deployments=deployments,
        )
