"""Native Kubernetes exposure/secret/network scanner (Phase 5 Part 3).

Fills the specific gaps in checkov's bundled Kubernetes policy set for
items Part 3 names explicitly. Verified against the Phase 5 fixture: a
`Service` of `type: NodePort` with a `nodePort: 30080` drew exactly ONE
checkov finding (CKV_K8S_21, "default namespace") and nothing at all about
being node-exposed — so "insecure service exposure / NodePort / public
exposure", "missing NetworkPolicy", "plaintext secrets", and "insecure
ingress/TLS" would have gone unreported if this platform relied on checkov
alone. This module closes that gap with a real YAML parse, not a
heuristic over text.

It is a separate adapter (same Phase 4 contract) rather than a patch to
`checkov_k8s_scanner.py` so that each scanner has exactly one tool behind
it and one availability story: checkov's availability is "is the binary
present", this module's is "can we parse YAML in-process", and conflating
them would make a checkov outage silently take these checks down too.
"""
from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
from pathlib import Path

import yaml

from ...security.models import (
    AvailabilityResult, ScannerAvailability, ScannerDescriptor, SecurityCategory,
    SecurityFinding, SecurityScanRecord, SecuritySeverity,
)

SCANNER_ID = "k8s-native"
CATEGORY = SecurityCategory.KUBERNETES
SUPPORTED = ["*.yaml (Kubernetes manifests)", "*.yml"]
TOOL_NAME = "in-process YAML analysis"
REMEDIATION_SUPPORTED = False  # exposure/RBAC decisions need operator intent - Part 9

_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".terraform", ".venv", "venv"}

# Rules that need cluster-wide context (a NetworkPolicy anywhere in the
# repo) rather than per-document context.
AUTO_REMEDIABLE_RULES: set[str] = set()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def check_availability(run_shell) -> AvailabilityResult:
    return AvailabilityResult(
        ScannerAvailability.AVAILABLE,
        "in-process YAML analysis; needs no binary, no network, and no live cluster",
    )


def describe(run_shell) -> ScannerDescriptor:
    return ScannerDescriptor(
        scanner_id=SCANNER_ID, capability="infra.kubernetes_exposure_scan", category=CATEGORY,
        supported=SUPPORTED, tool=TOOL_NAME,
        findings_schema="SecurityFinding (security/models.py) - Phase 4 model reused, not forked",
        severity_levels=[s.value for s in SecuritySeverity],
        evidence_kind="kubernetes kind/name + offending field",
        remediation_supported=REMEDIATION_SUPPORTED, availability=check_availability(run_shell),
    )


def _load_documents(root: Path) -> tuple[list[tuple[str, dict]], list[str]]:
    """Returns ([(relative_path, document)], [parse_error]). A file that
    fails to parse is reported, never silently treated as clean."""
    documents: list[tuple[str, dict]] = []
    errors: list[str] = []
    for path in sorted(root.rglob("*")):
        if path.suffix.lower() not in (".yaml", ".yml") or not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        rel = str(path.relative_to(root))
        try:
            raw = path.read_text()
        except (UnicodeDecodeError, OSError) as e:
            errors.append(f"{rel}: {e}")
            continue
        # Helm templates are Go templates, not YAML - `{{ }}` will not
        # parse and must not be reported as a broken manifest.
        if "{{" in raw and "}}" in raw:
            continue
        try:
            for doc in yaml.safe_load_all(raw):
                if isinstance(doc, dict) and doc.get("kind") and doc.get("apiVersion"):
                    documents.append((rel, doc))
        except yaml.YAMLError as e:
            errors.append(f"{rel}: {type(e).__name__}: {str(e)[:120]}")
    return documents, errors


def _pod_spec(doc: dict) -> dict:
    """Extracts the pod spec from any workload kind (Pod, Deployment,
    StatefulSet, DaemonSet, Job, CronJob) - each nests it differently."""
    kind = doc.get("kind")
    spec = doc.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get(
            "spec") or {}
    return ((spec.get("template") or {}).get("spec")) or {}


def _looks_base64_plaintext(value: str) -> str | None:
    """Kubernetes `Secret.data` is base64, which is encoding, not
    encryption - a committed Secret is a committed credential. Returns a
    short description of what the decoded value looks like, and NEVER the
    value itself (Phase 4's "never print the secret" rule applies here
    identically)."""
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        text = decoded.decode()
    except UnicodeDecodeError:
        return f"{len(decoded)} bytes of binary data"
    return f"{len(text)} characters of decodable plaintext"


def scan(project_root: str, run_shell) -> SecurityScanRecord:
    scanned_at = _now()
    root = Path(project_root)
    documents, errors = _load_documents(root)

    if not documents:
        return SecurityScanRecord(
            scanner=SCANNER_ID, scanner_version=TOOL_NAME, category=CATEGORY,
            scanned_at=scanned_at, target=project_root,
            availability=ScannerAvailability.NOT_APPLICABLE, exit_code=0, finding_count=0,
            findings=[], note="no Kubernetes manifests found in this repository",
        )

    findings: list[SecurityFinding] = []
    has_network_policy = any(doc.get("kind") == "NetworkPolicy" for _, doc in documents)
    workload_kinds = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob",
                      "ReplicaSet"}

    def add(rule_id: str, severity: SecuritySeverity, rel: str, resource: str,
             description: str, evidence: str, remediation: str, confidence: str = "high") -> None:
        findings.append(SecurityFinding(
            id=f"k8s-native:{rule_id}:{rel}:{resource}", scanner=SCANNER_ID, category=CATEGORY,
            severity=severity, confidence=confidence, file=rel, line=None, resource=resource,
            description=description, evidence=evidence, remediation=remediation,
            rule_id=rule_id, detected_at=scanned_at,
        ))

    for rel, doc in documents:
        kind = doc.get("kind", "")
        name = (doc.get("metadata") or {}).get("name", "<unnamed>")
        namespace = (doc.get("metadata") or {}).get("namespace", "default")
        resource = f"{kind}.{namespace}.{name}"
        spec = doc.get("spec") or {}

        # ---- Service exposure (Part 3: NodePort / public exposure) ----
        if kind == "Service":
            service_type = spec.get("type", "ClusterIP")
            if service_type == "NodePort":
                node_ports = [str(p.get("nodePort")) for p in (spec.get("ports") or [])
                               if p.get("nodePort")]
                add("K8S_SERVICE_NODEPORT", SecuritySeverity.HIGH, rel, resource,
                    "Service is exposed on every node via NodePort",
                    f"Service {name} has type: NodePort"
                    + (f" (nodePort {', '.join(node_ports)})" if node_ports else "")
                    + "; this opens the port on every node's external interface, bypassing "
                      "Ingress-level auth/TLS",
                    "use type: ClusterIP behind an Ingress (or an internal LoadBalancer) unless "
                    "node-level exposure is explicitly required")
            elif service_type == "LoadBalancer":
                annotations = (doc.get("metadata") or {}).get("annotations") or {}
                internal = any("internal" in str(k).lower() or "internal" in str(v).lower()
                                for k, v in annotations.items())
                if not internal:
                    add("K8S_SERVICE_PUBLIC_LB", SecuritySeverity.MEDIUM, rel, resource,
                        "Service provisions an internet-facing LoadBalancer",
                        f"Service {name} has type: LoadBalancer with no internal-only annotation; "
                        f"this typically provisions a public cloud load balancer",
                        "annotate the Service as internal, or front it with an Ingress that "
                        "terminates TLS and enforces authentication", confidence="medium")

        # ---- Ingress TLS (Part 3: insecure ingress/TLS) ----
        if kind == "Ingress":
            tls = spec.get("tls")
            if not tls:
                add("K8S_INGRESS_NO_TLS", SecuritySeverity.HIGH, rel, resource,
                    "Ingress serves traffic without TLS",
                    f"Ingress {name} declares no `spec.tls` block, so traffic to its host(s) is "
                    f"served over plaintext HTTP",
                    "add a spec.tls entry referencing a TLS secret, and redirect HTTP to HTTPS")
            annotations = (doc.get("metadata") or {}).get("annotations") or {}
            for key, value in annotations.items():
                if "ssl-redirect" in str(key) and str(value).lower() == "false":
                    add("K8S_INGRESS_SSL_REDIRECT_DISABLED", SecuritySeverity.MEDIUM, rel, resource,
                        "Ingress explicitly disables the HTTPS redirect",
                        f"annotation {key}={value} allows plaintext HTTP to be served alongside "
                        f"HTTPS",
                        "remove the annotation or set it to true")

        # ---- Plaintext secrets (Part 3) ----
        if kind == "Secret":
            secret_type = doc.get("type", "Opaque")
            data = doc.get("data") or {}
            string_data = doc.get("stringData") or {}
            for key in string_data:
                add("K8S_SECRET_PLAINTEXT_STRINGDATA", SecuritySeverity.CRITICAL, rel,
                    f"{resource}.{key}",
                    "Secret contains a plaintext value committed to the repository",
                    f"Secret {name} sets stringData.{key} to a literal value (redacted); "
                    f"stringData is stored verbatim and this file is in version control",
                    "move the value into an external secret manager and reference it via an "
                    "operator (External Secrets/Sealed Secrets/CSI driver), then rotate the "
                    "exposed credential")
            for key, value in data.items():
                if not isinstance(value, str):
                    continue
                shape = _looks_base64_plaintext(value)
                if shape:
                    add("K8S_SECRET_COMMITTED", SecuritySeverity.CRITICAL, rel,
                        f"{resource}.{key}",
                        "Secret data is committed to the repository (base64 is encoding, not "
                        "encryption)",
                        f"Secret {name} ({secret_type}) carries data.{key} containing {shape} "
                        f"(value redacted); anyone with repository read access has this credential",
                        "move the value into an external secret manager and rotate the exposed "
                        "credential; base64 provides no confidentiality")

        # ---- Workload-level network exposure ----
        if kind in workload_kinds:
            pod_spec = _pod_spec(doc)
            for container in (pod_spec.get("containers") or []):
                for port in (container.get("ports") or []):
                    if port.get("hostPort"):
                        add("K8S_CONTAINER_HOSTPORT", SecuritySeverity.HIGH, rel,
                            f"{resource}.{container.get('name', '?')}",
                            "Container binds a hostPort, exposing it on the node directly",
                            f"container {container.get('name')} maps hostPort "
                            f"{port.get('hostPort')}; this bypasses Service/NetworkPolicy "
                            f"controls entirely",
                            "remove hostPort and expose the container through a Service")

    # ---- Missing NetworkPolicy (repository-wide, Part 3) ----
    if not has_network_policy:
        workload_docs = [(rel, doc) for rel, doc in documents if doc.get("kind") in workload_kinds]
        if workload_docs:
            rel, doc = workload_docs[0]
            namespaces = sorted({(d.get("metadata") or {}).get("namespace", "default")
                                  for _, d in workload_docs})
            add("K8S_NO_NETWORK_POLICY", SecuritySeverity.MEDIUM, rel,
                f"namespace({','.join(namespaces)})",
                "no NetworkPolicy is defined for the workloads in this repository",
                f"{len(workload_docs)} workload(s) across namespace(s) {', '.join(namespaces)} "
                f"and zero NetworkPolicy objects; without one, every pod in the cluster can reach "
                f"every other pod by default",
                "add a default-deny NetworkPolicy per namespace plus explicit allow rules for "
                "required traffic", confidence="medium")

    return SecurityScanRecord(
        scanner=SCANNER_ID, scanner_version=TOOL_NAME, category=CATEGORY, scanned_at=scanned_at,
        target=project_root, availability=ScannerAvailability.AVAILABLE, exit_code=0,
        finding_count=len(findings), findings=findings,
        note=("YAML parse errors: " + "; ".join(errors)[:400]) if errors else "",
        raw_output_ref=f"{len(documents)} Kubernetes document(s) parsed in-process",
    )
