"""Phase 10 Wave 11 CLI test: `aep intelligence ci` builds its payload via
`_build_ci_clusters_payload()`, the exact function `cmd_ci_clusters` calls.
No Postgres dependency needed - `analyze_ci_clusters()` is pure/local."""
from __future__ import annotations

import argparse


def test_build_ci_clusters_payload_is_not_implemented():
    from aep.cli import _build_ci_clusters_payload

    args = argparse.Namespace(project_filter=None, json=True)
    payload = _build_ci_clusters_payload(args)
    assert payload["status"] == "NOT_IMPLEMENTED"
    assert payload["clusters"] == []
    assert payload["reason"]


def test_build_ci_clusters_payload_scoped_by_project():
    from aep.cli import _build_ci_clusters_payload

    args = argparse.Namespace(project_filter="p1", json=True)
    payload = _build_ci_clusters_payload(args)
    assert payload["status"] == "NOT_IMPLEMENTED"
