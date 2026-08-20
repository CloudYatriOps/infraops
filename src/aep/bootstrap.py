"""Wires the concrete Phase 1+2 components together into an Orchestrator.
Kept separate from cli.py/tests so both use identical wiring."""
from __future__ import annotations

import os
from typing import Optional

from .agents import (
    CIIntelligenceAgent, CodeAgent, DependencyCVEAgent, DeploymentAgent,
    DeploymentVerificationAgent, DiagnoseCIFailureAgent, InfrastructureDiscoveryAgent,
    InfrastructureIntelligenceAgent, MonitorCIAgent, OperationsIntelligenceAgent, PullRequestAgent,
    PushAgent, ReconAgent, SecurityAgent, SecurityScanAgent, TestingAgent,
)
from .deployment.local_provider import LocalFixtureDeploymentProvider
from .github.client import Transport
from .models import ProjectConfig
from .orchestrator import Orchestrator
from .policy import PolicyEngine
from .providers.mock_provider import MockProvider
from .providers.router import ModelRouter, RouteEntry
from .secrets import EnvSecretManager, SecretManager
from .db.factory import build_state_store
from .skills.factory import build_skill_registry
from .skills.registry import SkillRegistry
from .state_store import StateStore
from .tool_registry import ToolRegistry
from .tools import (
    build_deployment_tool, build_filesystem_tool, build_git_tool, build_github_tool,
    build_operations_tool, build_shell_tool,
)


def build_tool_registry(enable_github: bool = False,
                         github_secret_manager: Optional[SecretManager] = None,
                         github_transport: Optional[Transport] = None,
                         github_base_url: str = "https://api.github.com",
                         store: Optional[StateStore] = None,
                         deployment_state_dir: Optional[str] = None) -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(build_git_tool())
    registry.register(build_filesystem_tool())
    registry.register(build_shell_tool())
    if enable_github:
        secret_manager = github_secret_manager or EnvSecretManager()
        registry.register(build_github_tool(secret_manager, transport=github_transport,
                                             base_url=github_base_url))
    # Phase 6: the deployment tool needs the SAME StateStore instance the
    # orchestrator persists tasks to (Part 13's "survives a process
    # restart" durability guarantee), so it is only registered when one is
    # supplied - `build_orchestrator` below always supplies it. The default
    # provider is the safe, fully-implemented local fixture (see
    # `deployment/local_provider.py`); nothing here ever defaults to the
    # Kubernetes provider, which must be opted into explicitly.
    if store is not None:
        state_dir = deployment_state_dir or "aep_deployments"
        registry.register(build_deployment_tool(
            store, provider_factory=lambda: LocalFixtureDeploymentProvider(state_dir)))
        # Phase 7: same rationale as the deployment tool above - incident
        # memory needs the SAME StateStore instance the orchestrator
        # persists tasks to, so it is only registered when one is supplied.
        registry.register(build_operations_tool(store))
    return registry


def build_default_agents(enable_github: bool = False) -> dict:
    agents = {
        "recon": ReconAgent(),
        "code_agent": CodeAgent(),
        "testing_agent": TestingAgent(),
        "security_scan_agent": SecurityScanAgent(),
        # Dependency/CVE scanning only needs filesystem/shell/git capabilities
        # (always registered below), so it's available regardless of
        # enable_github - the *remediation chain* it builds only reaches
        # into push/PR/CI tasks when a github target is actually given
        # (see dependency/planner.py::build_remediation_chain).
        "dependency_cve_agent": DependencyCVEAgent(),
        # Phase 4: same story as dependency_cve_agent above - security
        # scanning/remediation only needs filesystem/shell/git, so it's
        # always registered; the remediation chain only reaches push/PR/CI
        # tasks when a github target is given (security/planner.py).
        "security_agent": SecurityAgent(),
        # Phase 5: same rationale as the two agents above - infrastructure
        # analysis needs only filesystem/shell/git, so it is always
        # registered; the remediation chain only reaches push/PR/CI tasks
        # when a github target is given (infra/planner.py).
        "infrastructure_discovery_agent": InfrastructureDiscoveryAgent(),
        "infrastructure_intelligence_agent": InfrastructureIntelligenceAgent(),
        # Phase 6: CI inspection needs only filesystem capabilities (always
        # registered above); deployment_agent/deployment_verification_agent
        # need the deployment tool, which is only registered when a
        # StateStore is supplied to build_tool_registry (see above) -
        # build_orchestrator always supplies one, so these are safe to
        # register unconditionally the same way the Phase 3/4/5 agents are.
        "ci_intelligence_agent": CIIntelligenceAgent(),
        "deployment_agent": DeploymentAgent(),
        "deployment_verification_agent": DeploymentVerificationAgent(),
        # Phase 7: needs deployment.list_evidence/deployment.rollback (for
        # the deployment tool, present whenever a StateStore is supplied -
        # see build_tool_registry above) plus operations.* incident-memory
        # capabilities from the operations tool registered alongside it.
        "operations_intelligence_agent": OperationsIntelligenceAgent(),
    }
    if enable_github:
        agents.update({
            "push_agent": PushAgent(),
            "pull_request_agent": PullRequestAgent(),
            "ci_monitor_agent": MonitorCIAgent(),
            "ci_diagnose_agent": DiagnoseCIFailureAgent(),
        })
    return agents


def build_router(use_anthropic: bool = False, token_budget: Optional[int] = None,
                  mock_canned: Optional[dict[str, str]] = None) -> ModelRouter:
    providers: dict = {"mock": MockProvider(canned_responses=mock_canned)}
    default_route = RouteEntry(primary="mock")

    if use_anthropic and os.environ.get("ANTHROPIC_API_KEY"):
        from .providers.anthropic_provider import AnthropicProvider
        providers["anthropic"] = AnthropicProvider()
        default_route = RouteEntry(primary="anthropic", fallbacks=["mock"])

    routing_table = {
        "code_fix": default_route,
        "diagnose_ci_failure": default_route,
    }
    return ModelRouter(providers=providers, routing_table=routing_table,
                        default_route=default_route, token_budget=token_budget)


def build_orchestrator(db_path: str, project: ProjectConfig,
                        use_anthropic: bool = False,
                        token_budget: Optional[int] = None,
                        mock_canned: Optional[dict[str, str]] = None,
                        sleep_fn=None,
                        enable_github: bool = False,
                        github_secret_manager: Optional[SecretManager] = None,
                        github_transport: Optional[Transport] = None,
                        github_base_url: str = "https://api.github.com",
                        deployment_state_dir: Optional[str] = None,
                        db_backend: Optional[str] = None,
                        skill_registry: Optional[SkillRegistry] = None,
                        skill_registry_backend: Optional[str] = None) -> Orchestrator:
    """`db_backend` selects the durable store implementation via the single
    canonical resolution in `db/factory.py::build_state_store`:
      * `db_backend="postgres"` (or the default, when neither this
        argument nor `AEP_DB_BACKEND` says otherwise) - the
        `PostgresStateStore` (see `db/state_store_postgres.py`),
        connecting via `AEP_POSTGRES_DSN`/`AEP_PG_*` env vars. Construction
        runs the startup gate (`db/startup.verify_database`) and raises
        `DatabaseUnavailableError`/`SchemaDriftError` rather than ever
        silently falling back to SQLite - `db_path` is ignored in this
        mode.
      * `db_backend="sqlite"` (explicit, or via `AEP_DB_BACKEND=sqlite`) -
        the existing, unchanged SQLite `StateStore` at `db_path`. As of
        Stage A.5's default flip, this is no longer the ambient default -
        it must be explicitly requested (tests that want it pass
        `db_backend="sqlite"` explicitly)."""
    store = build_state_store(db_path, db_backend=db_backend)
    tool_registry = build_tool_registry(
        enable_github=enable_github, github_secret_manager=github_secret_manager,
        github_transport=github_transport, github_base_url=github_base_url,
        store=store, deployment_state_dir=deployment_state_dir,
    )
    router = build_router(use_anthropic=use_anthropic, token_budget=token_budget,
                           mock_canned=mock_canned)
    agents = build_default_agents(enable_github=enable_github)
    policy = PolicyEngine.from_yaml(project.policy_path)
    kwargs = {}
    if sleep_fn is not None:
        kwargs["sleep_fn"] = sleep_fn
    # Stage C: skill-gate enforcement is strictly opt-in here - passing
    # neither `skill_registry` nor `skill_registry_backend` keeps
    # `Orchestrator.skill_registry` None, which is a guaranteed no-op gate
    # (see `_apply_skill_gate`), preserving every pre-Stage-C caller's
    # behavior exactly. Callers that want enforcement pass one explicitly.
    if skill_registry is not None:
        kwargs["skill_registry"] = skill_registry
    elif skill_registry_backend is not None:
        kwargs["skill_registry"] = build_skill_registry(backend=skill_registry_backend)
    return Orchestrator(
        store=store, tool_registry=tool_registry, router=router,
        agents=agents, policies={project.id: policy}, projects={project.id: project},
        **kwargs,
    )
