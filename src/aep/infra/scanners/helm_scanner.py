"""Helm chart security scanner (Phase 5 Part 4).

## The trap this module exists to avoid

checkov ships a `--framework helm`, and it looked like the obvious answer.
It is not, in this environment, and the failure mode is dangerous enough
to document at the top of the file:

    $ checkov -d . --framework helm -o json --quiet      # helm binary ABSENT
    {"passed": 0, "failed": 0, "resource_count": 0, ...}
    $ echo $?
    0

checkov's Helm runner shells out to the real `helm` binary to render the
chart first. With no `helm` on PATH it renders nothing, finds nothing, and
exits **0** — a naive integration would have reported "Helm: PASS" for a
chart that (as verified against the fixture in
`tests/fixtures/infra/helm/`) is full of privileged/root/NodePort/wildcard-
RBAC problems. That is precisely the "do not fake results if unavailable"
failure Part 3 warns about, arrived at not by fabricating anything but by
trusting a tool's exit code without checking whether it actually ran.

So this module checks for the `helm` binary FIRST and reports
`BLOCKED` when it is missing, regardless of what checkov would say.

## What this environment can and cannot do

`helm` is unobtainable here: `get.helm.sh` is unreachable through the
sandbox egress proxy (curl returns `000`, the same block pattern
documented for `releases.hashicorp.com`, `dl.k8s.io`, `proxy.golang.org`,
and `registry-1.docker.io` in §23–§25). So `helm lint` and `helm template`
(Part 4's required validations) are BLOCKED, and full template rendering —
which needs a real Go-template engine plus Helm's built-in objects — is
not something this platform will approximate. Approximating it would
produce findings against manifests that never existed.

What IS real and runs here is a **static analysis of the chart's own
non-templated files**: `values.yaml` is plain YAML, it is where a chart's
insecure defaults actually live, and it is what an operator overrides. So
`scan()` reports `BLOCKED` for the rendering path while still returning
genuine findings from a real parse of real values — every finding carries
the exact YAML path it came from, and the record's `note` states plainly
that rendered-template coverage did not happen. Availability is
`BLOCKED`, never `AVAILABLE`, so nothing downstream can mistake partial
values-level coverage for a full chart scan.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import yaml

from ...security.models import (
    AvailabilityResult, ScannerAvailability, ScannerDescriptor, SecurityCategory,
    SecurityFinding, SecurityScanRecord, SecuritySeverity,
)

SCANNER_ID = "helm-static"
CATEGORY = SecurityCategory.HELM
SUPPORTED = ["Chart.yaml", "values.yaml"]
TOOL_NAME = "helm"
REMEDIATION_SUPPORTED = False  # values-level fixes need chart-specific knowledge

_BLOCKED_REASON = (
    "the `helm` binary is not installed and cannot be obtained here (get.helm.sh is unreachable "
    "through this sandbox's egress proxy, curl returns 000), so `helm lint` and `helm template` "
    "cannot run and charts cannot be rendered for full analysis. NOTE: `checkov --framework helm` "
    "silently reports 0 findings and exit code 0 in this state because it shells out to that same "
    "missing binary - this scanner deliberately does NOT trust that result. Values-level static "
    "findings below are real, but are strictly narrower than a rendered-chart scan."
)

# (values.yaml key path, matching predicate, severity, description, remediation)
# Each rule targets an insecure *default* a chart ships - the thing an
# operator inherits by running `helm install` with no overrides.
_VALUES_RULES: list[tuple[tuple[str, ...], object, SecuritySeverity, str, str]] = [
    (("securityContext", "privileged"), True, SecuritySeverity.CRITICAL,
     "chart defaults to a privileged container",
     "set securityContext.privileged=false; privileged containers can escape to the host"),
    (("securityContext", "runAsUser"), 0, SecuritySeverity.HIGH,
     "chart defaults to running as root (runAsUser: 0)",
     "set a non-zero runAsUser and runAsNonRoot: true"),
    (("securityContext", "allowPrivilegeEscalation"), True, SecuritySeverity.HIGH,
     "chart allows privilege escalation by default",
     "set securityContext.allowPrivilegeEscalation=false"),
    (("securityContext", "runAsNonRoot"), False, SecuritySeverity.HIGH,
     "chart explicitly disables runAsNonRoot",
     "set securityContext.runAsNonRoot=true"),
    (("hostNetwork",), True, SecuritySeverity.HIGH,
     "chart defaults to hostNetwork: true",
     "remove hostNetwork or set it to false; it bypasses network namespacing"),
    (("hostPID",), True, SecuritySeverity.HIGH,
     "chart defaults to hostPID: true",
     "remove hostPID or set it to false"),
    (("service", "type"), "NodePort", SecuritySeverity.MEDIUM,
     "chart exposes the service as NodePort by default",
     "prefer ClusterIP with an Ingress, or an internal LoadBalancer"),
    (("service", "type"), "LoadBalancer", SecuritySeverity.MEDIUM,
     "chart provisions an external LoadBalancer by default",
     "confirm this is intended to be internet-reachable; prefer ClusterIP + Ingress otherwise"),
    (("rbac", "clusterWide"), True, SecuritySeverity.HIGH,
     "chart requests cluster-wide RBAC by default",
     "scope RBAC to a namespace Role/RoleBinding unless cluster scope is genuinely required"),
    (("rbac", "create"), True, SecuritySeverity.INFO,
     "chart creates its own RBAC objects",
     "review the generated Role/ClusterRole rules for wildcards"),
    (("networkPolicy", "enabled"), False, SecuritySeverity.MEDIUM,
     "chart ships with NetworkPolicy disabled",
     "enable networkPolicy so the workload is not reachable from every pod in the cluster"),
    (("ingress", "tls"), [], SecuritySeverity.MEDIUM,
     "chart's ingress has no TLS configuration",
     "configure ingress.tls so traffic is not served over plaintext HTTP"),
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def check_availability(run_shell) -> AvailabilityResult:
    result = run_shell(["helm", "version", "--short"], timeout=10)
    if result.get("ok"):
        return AvailabilityResult(
            ScannerAvailability.AVAILABLE,
            "helm binary present; `helm lint`/`helm template` rendering is possible",
        )
    return AvailabilityResult(ScannerAvailability.BLOCKED, _BLOCKED_REASON)


def describe(run_shell) -> ScannerDescriptor:
    return ScannerDescriptor(
        scanner_id=SCANNER_ID, capability="infra.helm_scan", category=CATEGORY,
        supported=SUPPORTED, tool=TOOL_NAME,
        findings_schema="SecurityFinding (security/models.py) - Phase 4 model reused, not forked",
        severity_levels=[s.value for s in SecuritySeverity],
        evidence_kind="values.yaml key path + insecure default value",
        remediation_supported=REMEDIATION_SUPPORTED, availability=check_availability(run_shell),
    )


def _get_path(data: dict, path: tuple[str, ...]):
    """Returns (found, value) for a nested key path - `found` distinguishes
    "key absent" from "key present and set to None/False", which several
    rules above depend on."""
    node = data
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return False, None
        node = node[key]
    return True, node


def _find_line(raw: str, path: tuple[str, ...]) -> int | None:
    """Best-effort line number for a values.yaml key path. PyYAML's plain
    loader discards positions, and pulling in a round-trip parser just for
    a line number isn't worth the dependency - so this walks the raw text
    by indentation. Returns None rather than guessing when the structure
    doesn't match, and `None` is handled everywhere downstream."""
    lines = raw.splitlines()
    depth = 0
    start = 0
    for key in path:
        found = None
        for i in range(start, len(lines)):
            stripped = lines[i].lstrip()
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(lines[i]) - len(stripped)
            if indent < depth * 2 and i > start:
                break
            if indent == depth * 2 and stripped.split(":")[0].strip() == key:
                found = i
                break
        if found is None:
            return None
        start, depth = found + 1, depth + 1
    return start  # 1-indexed line of the matched key


def scan(project_root: str, run_shell) -> SecurityScanRecord:
    """Always returns availability=BLOCKED in this environment (see the
    module docstring) while still surfacing real values-level findings.
    The two facts are reported together on purpose: partial real coverage
    plus an explicit statement of what did NOT run."""
    scanned_at = _now()
    availability = check_availability(run_shell)
    root = Path(project_root)

    # Skip vendored subcharts (Helm puts dependencies at
    # `<chart>/charts/<subchart>/Chart.yaml`): their values are overridden
    # by the parent chart, so scanning their defaults reports problems the
    # operator never actually gets.
    #
    # The grandparent must be named `charts` AND itself sit inside a real
    # chart (a directory containing Chart.yaml). Checking only the
    # directory name was a real bug caught by this phase's own end-to-end
    # test: the extremely common top-level `charts/myapp/Chart.yaml`
    # repository layout was silently skipped, so a whole chart went
    # unscanned while the scan still reported success.
    def _is_vendored_subchart(chart_dir: Path) -> bool:
        parent = chart_dir.parent
        return parent.name == "charts" and (parent.parent / "Chart.yaml").exists()

    charts = sorted(p.parent for p in root.rglob("Chart.yaml")
                     if ".git" not in p.parts and not _is_vendored_subchart(p.parent))
    if not charts:
        return SecurityScanRecord(
            scanner=SCANNER_ID, scanner_version="n/a", category=CATEGORY, scanned_at=scanned_at,
            target=project_root, availability=ScannerAvailability.NOT_APPLICABLE, exit_code=0,
            finding_count=0, findings=[],
            note="no Helm charts (Chart.yaml) found in this repository",
        )

    findings: list[SecurityFinding] = []
    parse_errors: list[str] = []
    for chart_dir in charts:
        values_path = chart_dir / "values.yaml"
        if not values_path.exists():
            continue
        rel = str(values_path.relative_to(root))
        try:
            raw = values_path.read_text()
            values = yaml.safe_load(raw) or {}
        except (yaml.YAMLError, UnicodeDecodeError, OSError) as e:
            # A malformed values.yaml is itself worth reporting, and must
            # never be silently swallowed into "no findings".
            parse_errors.append(f"{rel}: {e}")
            continue
        if not isinstance(values, dict):
            parse_errors.append(f"{rel}: values.yaml is not a mapping")
            continue

        for path, expected, severity, description, remediation in _VALUES_RULES:
            found, value = _get_path(values, path)
            if not found or value != expected:
                continue
            # `value != expected` uses equality deliberately: `True == 1`
            # in Python, but a values.yaml boolean and integer are distinct
            # enough in practice here, and an exact-match rule table is far
            # easier to audit than a set of predicates.
            key_path = ".".join(path)
            findings.append(SecurityFinding(
                id=f"helm-static:{key_path}:{rel}",
                scanner=SCANNER_ID, category=CATEGORY, severity=severity, confidence="medium",
                file=rel, line=_find_line(raw, path), resource=f"values.{key_path}",
                description=description,
                evidence=f"{rel}: values.{key_path} = {value!r} (chart default, before any "
                          f"operator override)",
                remediation=remediation, rule_id=f"HELM_VALUES_{key_path.upper().replace('.', '_')}",
                detected_at=scanned_at,
            ))

    note = _BLOCKED_REASON if availability.status == ScannerAvailability.BLOCKED else ""
    if parse_errors:
        note += f" | values.yaml parse errors: {'; '.join(parse_errors)[:400]}"
    return SecurityScanRecord(
        scanner=SCANNER_ID, scanner_version="static-values-analysis", category=CATEGORY,
        scanned_at=scanned_at, target=project_root, availability=availability.status,
        exit_code=0, finding_count=len(findings), findings=findings, note=note,
        raw_output_ref=f"{len(charts)} chart(s) inspected at values level; "
                       f"rendered-template analysis did NOT run",
    )
