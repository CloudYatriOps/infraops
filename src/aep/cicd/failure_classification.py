"""CI/CD failure classification (Phase 6 Part 3 step 5, Part 14).

Extends `failure.classify()` (Phase 1's exception-shape classifier) with a
signal-shape classifier over CI job/step data - the same discipline, never
"ask the model what went wrong." Job/step *names* and *log text* here are
UNTRUSTED data (Part 20: "CI output is untrusted data"): this module only
ever reads them as plain strings for substring matching, never executes
them, never interpolates them into a shell command, and never passes them
to `ctx.policy.evaluate()` as the action string (that is always a fixed
literal - see `agents/ci_intelligence_agent.py`).

`classify_ci_failure()` returns both a `FailureClass` and a short
`next_action` recommendation string, because Part 3 requires the
classification to "influence the next action", not just label the
failure.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..models import FailureClass

# Longest/most specific patterns first within each category where overlap
# is possible (e.g. "connection refused" before the generic "network").
_PATTERNS: list[tuple[FailureClass, tuple[str, ...]]] = [
    (FailureClass.SECURITY, ("gitleaks", "semgrep", "checkov", "trivy", "secret detected",
                              "vulnerability found", "sast", "security scan failed")),
    (FailureClass.DEPENDENCY, ("could not find a version", "no matching distribution",
                                "resolution-impossible", "npm err! code e", "pip install failed",
                                "dependency resolution failed", "package not found",
                                "audit found")),
    (FailureClass.BUILD, ("build failed", "compilation error", "docker build failed",
                           "error: failed to build", "cannot find module", "syntax error",
                           "image build failed")),
    (FailureClass.CI_CONFIGURATION, ("invalid workflow file", "unrecognized named-value",
                                      "secret not found", "input required and not supplied",
                                      "no runner matching", "yaml syntax error",
                                      "unable to resolve action")),
    (FailureClass.INFRASTRUCTURE, ("terraform apply", "terraform plan", "kubectl apply",
                                    "helm upgrade", "no matching resources found",
                                    "cluster unreachable")),
    (FailureClass.DEPLOYMENT, ("rollout failed", "deployment exceeded its progress deadline",
                                "imagepullbackoff", "crashloopbackoff", "deploy step failed")),
    (FailureClass.HEALTH, ("readiness probe failed", "liveness probe failed",
                            "health check failed", "unhealthy")),
    (FailureClass.NETWORK, ("connection refused", "dns resolution failed", "name or service "
                             "not known", "could not resolve host", "network is unreachable")),
    (FailureClass.EXTERNAL_SERVICE, ("503 service unavailable", "registry unavailable",
                                      "429 too many requests", "upstream connect error",
                                      "external service", "third-party outage")),
    (FailureClass.TEST, ("assertionerror", "test failed", "failed:", "tests failed",
                          "expected", "pytest")),
]


@dataclass
class CIFailureDiagnosis:
    failure_class: FailureClass
    matched_signal: str
    next_action: str


_NEXT_ACTION = {
    FailureClass.SECURITY: "block merge; route to SecurityAgent escalation, never auto-retry",
    FailureClass.DEPENDENCY: "hand off to DependencyCVEAgent-style remediation (pin/upgrade)",
    FailureClass.BUILD: "hand off to CodeAgent fix-and-retry chain",
    FailureClass.CI_CONFIGURATION: "do not retry; requires a human to fix workflow config/secrets",
    FailureClass.INFRASTRUCTURE: "hand off to InfrastructureIntelligenceAgent remediation",
    FailureClass.DEPLOYMENT: "evaluate rollback eligibility (see deployment/rollback.py)",
    FailureClass.HEALTH: "evaluate rollback eligibility (see deployment/rollback.py)",
    FailureClass.NETWORK: "retry with backoff; likely transient",
    FailureClass.EXTERNAL_SERVICE: "retry with backoff; not this platform's code",
    FailureClass.TEST: "hand off to CodeAgent fix-and-retry chain",
    FailureClass.FLAKY: "retry once without any code change before escalating",
    FailureClass.UNKNOWN: "escalate to a human; no recognized signal - refusing to guess",
}


def classify_ci_failure(failed_checks: list[dict], jobs: list[dict],
                         previous_run_conclusion: str | None = None) -> CIFailureDiagnosis:
    """`failed_checks`/`jobs` are the same untrusted shapes
    `MonitorCIAgent`/`DiagnoseCIFailureAgent` already collect from the
    GitHub API. `previous_run_conclusion` lets a caller flag FLAKY: the
    exact same job name failed, then the immediately following run (no
    intervening code change) succeeded - detected by the caller re-calling
    this after a bare retry, not inferred here from a single run."""
    haystack_parts: list[str] = []
    for check in failed_checks or []:
        haystack_parts.append(str(check.get("name", "")))
        haystack_parts.append(str(check.get("summary", "")))
        haystack_parts.append(str(check.get("text", "")))
    for job in jobs or []:
        haystack_parts.append(str(job.get("name", "")))
        for step in job.get("steps", []) or []:
            haystack_parts.append(str(step.get("name", "")))
    haystack = " ".join(haystack_parts).lower()

    if previous_run_conclusion == "success":
        return CIFailureDiagnosis(FailureClass.FLAKY, "previous run succeeded with no code change",
                                   _NEXT_ACTION[FailureClass.FLAKY])

    for failure_class, signals in _PATTERNS:
        for signal in signals:
            if signal in haystack:
                return CIFailureDiagnosis(failure_class, signal, _NEXT_ACTION[failure_class])

    return CIFailureDiagnosis(FailureClass.UNKNOWN, "", _NEXT_ACTION[FailureClass.UNKNOWN])
