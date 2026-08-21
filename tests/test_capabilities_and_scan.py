"""Project capability detection and capability-routed scanning.

The behaviours pinned here are the ones that make `aep scan` honest:
detection from real evidence (never directory names), and the precise
distinction between SKIPPED (does not apply), UNAVAILABLE (applies, AEP
can't) and BLOCKED (applies, external precondition).
"""
from __future__ import annotations

import textwrap

from aep.capabilities import Capability, detect_project
from aep.scan import AnalyzerStatus, scan_project


def _write(root, rel, content=""):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content), encoding="utf-8")
    return path


def test_python_app_detected_from_marker_not_directory_name(tmp_path):
    repo = tmp_path / "totally-not-called-python"
    _write(repo, "pyproject.toml", "[project]\nname='x'\n")
    profile = detect_project(str(repo))
    assert profile.has(Capability.PYTHON)
    assert profile.has(Capability.APPLICATION)
    assert "pyproject.toml" in profile.evidence[Capability.PYTHON]


def test_directory_named_terraform_without_tf_files_is_not_terraform(tmp_path):
    """The anti-requirement: a name proves nothing."""
    repo = tmp_path / "repo"
    _write(repo, "terraform/README.md", "# we deleted the terraform\n")
    profile = detect_project(str(repo))
    assert not profile.has(Capability.TERRAFORM)
    assert not profile.has(Capability.INFRASTRUCTURE)


def test_terraform_detected_from_tf_file(tmp_path):
    repo = tmp_path / "repo"
    _write(repo, "infra/main.tf", 'provider "aws" {}\n')
    profile = detect_project(str(repo))
    assert profile.has(Capability.TERRAFORM)
    assert profile.has(Capability.INFRASTRUCTURE)


def test_multiple_capabilities_coexist(tmp_path):
    repo = tmp_path / "repo"
    _write(repo, "pyproject.toml", "[project]\nname='x'\n")
    _write(repo, "package.json", '{"name":"x"}')
    _write(repo, "infra/main.tf", 'provider "aws" {}\n')
    _write(repo, "Dockerfile", "FROM python:3.12\n")
    _write(repo, ".github/workflows/ci.yml", "on: push\njobs: {}\n")
    profile = detect_project(str(repo))
    for expected in (Capability.PYTHON, Capability.NODE, Capability.TERRAFORM,
                      Capability.CONTAINER, Capability.CI_CD,
                      Capability.APPLICATION, Capability.INFRASTRUCTURE):
        assert profile.has(expected), f"missing {expected}"


def test_empty_repo_is_unknown_not_a_false_capability(tmp_path):
    repo = tmp_path / "empty"
    repo.mkdir()
    profile = detect_project(str(repo))
    assert profile.has(Capability.UNKNOWN)


def test_scan_skips_inapplicable_analyzers_rather_than_calling_them_unavailable(tmp_path):
    """A pure Python app must not be told its Terraform scanning is broken."""
    repo = tmp_path / "pyapp"
    _write(repo, "pyproject.toml", "[project]\nname='x'\n")
    _write(repo, "app.py", "def f():\n    return 1\n")

    report = scan_project(str(repo))
    by_name = {r.name: r for r in report.results}

    assert by_name["IaC"].status is AnalyzerStatus.SKIPPED
    assert "no infrastructure-as-code" in by_name["IaC"].reason
    assert by_name["Containers"].status is AnalyzerStatus.SKIPPED
    # Never the wrong word for an inapplicable analyzer.
    assert by_name["IaC"].status is not AnalyzerStatus.UNAVAILABLE


def test_scan_detects_a_real_planted_secret_and_never_prints_the_value(tmp_path):
    repo = tmp_path / "leaky"
    _write(repo, "config.py", 'AWS_ACCESS_KEY_ID = "AKIAABCD1234EFGH5678"\n')

    report = scan_project(str(repo))
    secrets = next(r for r in report.results if r.name == "Secrets")

    assert secrets.status is AnalyzerStatus.FAIL
    assert secrets.finding_count == 1
    # The raw credential must never reach a finding field.
    blob = repr(report.to_dict())
    assert "AKIAABCD1234EFGH5678" not in blob


def test_secret_reference_is_not_reported_as_a_leaked_secret(tmp_path):
    """BUG-0022: `password = local.x` points AT a secret, it is not one.

    Flagging the secure pattern as a leak is a false positive that buries
    real findings; this repo-shaped case is exactly what surfaced it.
    """
    repo = tmp_path / "tfrepo"
    _write(repo, "main.tf", """\
        resource "x" "y" {
          password = local.db_admin_password
          token    = var.argocd_repo_pat
        }
        """)
    report = scan_project(str(repo))
    secrets = next(r for r in report.results if r.name == "Secrets")
    assert secrets.finding_count == 0, secrets.reason


def test_scan_is_read_only(tmp_path):
    """Scanning must not alter the repository in any way."""
    repo = tmp_path / "repo"
    _write(repo, "pyproject.toml", "[project]\nname='x'\n")
    _write(repo, "main.tf", 'provider "aws" {}\n')

    before = {p: p.read_bytes() for p in repo.rglob("*") if p.is_file()}
    scan_project(str(repo))
    after = {p: p.read_bytes() for p in repo.rglob("*") if p.is_file()}

    assert before.keys() == after.keys(), "scan added or removed files"
    assert before == after, "scan modified file contents"
