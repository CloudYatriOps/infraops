"""Phase 5 infrastructure scanners.

Every module here conforms to the EXACT adapter contract defined by Phase
4's `security/scanners/base.py` (`check_availability`/`describe`/`scan`),
returns Phase 4's `SecurityScanRecord`/`SecurityFinding`, and is driven by
Phase 4's `security/scan_runner.py::run_security_scan()` through its
existing `scanners=` injection point. Part 3's "integrate with the
existing SecurityScanner framework rather than creating a duplicate
scanner architecture" is therefore satisfied structurally, not just by
convention - there is no second scanner runner, finding model, or
availability enum in Phase 5.

`INFRA_SCANNERS` is kept as its own tuple (rather than being appended to
Phase 4's `ALL_SCANNERS`) so that `security.discovery.discover_scanners()`
and every Phase 4 test continue to describe exactly the four original
categories, unchanged. Callers that want both sets pass
`ALL_SCANNERS + INFRA_SCANNERS` explicitly - see `infra/scan_runner.py`.
"""
from . import checkov_k8s_scanner, helm_scanner, k8s_native_scanner, terraform_deep_scanner

INFRA_SCANNERS = (checkov_k8s_scanner, k8s_native_scanner, terraform_deep_scanner, helm_scanner)

__all__ = ["checkov_k8s_scanner", "k8s_native_scanner", "terraform_deep_scanner", "helm_scanner",
           "INFRA_SCANNERS"]
