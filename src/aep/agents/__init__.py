from .base import Agent, AgentContext, build_context
from .recon_agent import ReconAgent
from .code_agent import CodeAgent
from .testing_agent import TestingAgent
from .security_agent import SecurityScanAgent
from .push_agent import PushAgent
from .pull_request_agent import PullRequestAgent
from .ci_monitor_agent import MonitorCIAgent
from .ci_diagnose_agent import DiagnoseCIFailureAgent
from .dependency_cve_agent import DependencyCVEAgent
from .security_intelligence_agent import SecurityAgent
from .infrastructure_discovery_agent import InfrastructureDiscoveryAgent
from .infrastructure_intelligence_agent import InfrastructureIntelligenceAgent
from .ci_intelligence_agent import CIIntelligenceAgent
from .deployment_agent import DeploymentAgent
from .deployment_verification_agent import DeploymentVerificationAgent
from .operations_intelligence_agent import OperationsIntelligenceAgent

__all__ = [
    "Agent", "AgentContext", "build_context",
    "ReconAgent", "CodeAgent", "TestingAgent", "SecurityScanAgent",
    "PushAgent", "PullRequestAgent", "MonitorCIAgent", "DiagnoseCIFailureAgent",
    "DependencyCVEAgent",
    # Phase 4: SecurityAgent (multi-scanner: secret/SAST/IaC/container) is a
    # DIFFERENT class from SecurityScanAgent above (Phase 1's deterministic
    # pre-commit secret gate) - see security_intelligence_agent.py's
    # module docstring for why both exist.
    "SecurityAgent",
    # Phase 5: infrastructure discovery is a SEPARATE, deliberately
    # narrower agent from the intelligence agent - it holds only
    # filesystem capabilities, so it is structurally read-only.
    "InfrastructureDiscoveryAgent", "InfrastructureIntelligenceAgent",
    # Phase 6: CI/CD & Deployment Intelligence. `DeploymentVerificationAgent`
    # is deliberately a SEPARATE, read-only-over-the-provider agent from
    # `DeploymentAgent` - same "narrower sibling" pattern as Phase 5's
    # discovery/intelligence split above.
    "CIIntelligenceAgent", "DeploymentAgent", "DeploymentVerificationAgent",
    # Phase 7: Autonomous Operations & Reliability Intelligence - the
    # closed-loop operational agent (see operations_intelligence_agent.py).
    "OperationsIntelligenceAgent",
]
