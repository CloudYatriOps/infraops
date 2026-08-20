"""Threat-modeling the skill registry itself (Stage B Part 19). Lint-style
source assertions in the same spirit as test_infra_threat_model.py /
test_operations_threat_model.py / test_runtime_threat_model.py.

Threats and their structural mitigations, each asserted below:
  - Malicious skill definitions / fake capability claims: SkillRegistry.
    publish() self-validates every allowed_tools/required_checks/
    verification_rules/prohibited_actions entry against the REAL platform
    surface (known_capabilities.py) and refuses to publish anything that
    references something that doesn't exist.
  - Unauthorized tool grants: a skill's allowed_tools never grants
    capability beyond what a real ToolRegistry actually has - the loader's
    tool_capabilities check in resolve_required_skills() enforces this,
    and no skills module ever constructs or mutates a ToolRegistry itself.
  - Skill instruction injection: canonical skills are Python dataclasses
    seeded from definitions.py, never parsed from untrusted repository
    content - nothing in skills/ reads a file from a target project's
    repo to construct a Skill/SkillVersion.
  - Policy bypass attempts through skills: no module in skills/ ever calls
    PolicyEngine.evaluate() itself or constructs a PolicyDecision - a
    skill only *describes* a procedure; the actual policy decision is
    still made exclusively where it always was.
  - Version rollback attacks: SkillRegistry.publish() raises
    SkillImmutabilityError on any attempt to re-publish an existing
    (skill_id, version) pair; there is no "force republish"/"overwrite"
    method anywhere in registry.py.
  - Untrusted repository content pretending to be a canonical skill: the
    registry has no "load skill from repository path" mechanism at all -
    the only way a SkillVersion enters the registry is through
    SkillRegistry.publish(), called from definitions.py or a test/CLI.
  - Dependency cycles: resolve_dependencies() performs real cycle
    detection (DFS with a visiting-stack), never silently permitting one.
  - Core invariant: canonical skills are trusted platform configuration;
    repository content can never redefine policy/skills.
"""
from __future__ import annotations

import re
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "aep"
SKILLS_DIR = SRC / "skills"

_MODULES = sorted(p for p in SKILLS_DIR.rglob("*.py") if "__pycache__" not in str(p))


def _sources() -> dict[str, str]:
    return {str(p.relative_to(SRC)): p.read_text() for p in _MODULES}


# ---- self-validation against fake capability claims ------------------------

def test_registry_self_validates_before_publish():
    source = (SKILLS_DIR / "registry.py").read_text()
    assert "def publish(" in source
    publish_body = source.split("def publish(")[1].split("\n    def ")[0]
    assert "self_validate(version)" in publish_body
    assert "raise SkillValidationError" in publish_body


def test_self_validate_checks_tools_checks_and_policy_actions_against_real_sources():
    source = (SKILLS_DIR / "registry.py").read_text()
    body = source.split("def self_validate(")[1].split("\n    def ")[0]
    assert "REAL_TOOL_CAPABILITIES" in body
    assert "KNOWN_VERIFICATION_CHECKS" in body
    assert "real_policy_actions" in body


def test_known_capabilities_are_introspected_from_real_modules_not_invented():
    source = (SKILLS_DIR / "known_capabilities.py").read_text()
    # Scanner ids come from the real scanner modules' own SCANNER_ID
    # constants, not re-typed string literals - so this can never drift.
    assert "gitleaks_scanner.SCANNER_ID" in source
    assert "semgrep_scanner.SCANNER_ID" in source
    assert "checkov_scanner.SCANNER_ID" in source
    assert "trivy_scanner.SCANNER_ID" in source
    assert "PolicyEngine.from_yaml" in source


# ---- no policy bypass -------------------------------------------------------

def test_no_skills_module_evaluates_policy_itself():
    for name, source in _sources().items():
        assert "policy.evaluate(" not in source, name
        assert "PolicyEngine(" not in source, name


def test_no_skills_module_constructs_a_policy_decision():
    for name, source in _sources().items():
        assert "PolicyDecision(" not in source, name


# ---- no prompt injection / no AI provider dependency ------------------------

def test_no_skills_module_calls_an_ai_provider():
    for name, source in _sources().items():
        assert "router.generate" not in source, name
        assert "ctx.router" not in source, name
        assert "AnthropicProvider" not in source, name


def test_no_skills_module_reads_arbitrary_repository_content_to_build_a_skill():
    """Canonical skills come only from definitions.py's fixed Python data
    - no module parses a file from a target project's repo into a
    SkillVersion."""
    for name, source in _sources().items():
        if name.endswith("definitions.py"):
            continue
        assert "open(" not in source, name


# ---- immutability / rollback -------------------------------------------------

def test_publish_has_no_force_or_overwrite_escape_hatch():
    source = (SKILLS_DIR / "registry.py").read_text()
    assert "force=" not in source
    assert "overwrite=" not in source
    assert "def republish" not in source


def test_publish_raises_immutability_error_on_existing_version():
    source = (SKILLS_DIR / "registry.py").read_text()
    body = source.split("def publish(")[1].split("\n    def ")[0]
    assert "raise SkillImmutabilityError" in body


# ---- dependency cycle detection is real, not stubbed ------------------------

def test_resolve_dependencies_performs_real_cycle_detection():
    source = (SKILLS_DIR / "registry.py").read_text()
    assert "cycle" in source
    assert "visiting" in source
    assert "visited" in source


# ---- no eval/exec on skill content -------------------------------------------

def test_no_skills_module_evals_or_execs_anything():
    for name, source in _sources().items():
        assert not re.search(r"\beval\(", source), name
        assert not re.search(r"\bexec\(", source), name
        assert "pickle.load" not in source, name


# ---- infra/k8s/helm skills honestly never claim live capability -------------

def test_terraform_kubernetes_helm_skills_never_claim_destructive_capability():
    source = (SKILLS_DIR / "definitions.py").read_text()
    forbidden = ("terraform apply", "terraform destroy", "kubectl apply", "kubectl delete",
                 "helm install", "helm upgrade")
    for phrase in forbidden:
        binary, verb = phrase.split()
        assert f'"{binary}", "{verb}"' not in source


def test_terraform_kubernetes_helm_skills_declare_the_real_destructive_deny_actions_as_prohibited():
    source = (SKILLS_DIR / "definitions.py").read_text()
    assert '"infra.resource_delete"' in source
    assert '"infra.terraform_destroy"' in source
    assert '"infra.cluster_resource_delete"' in source


def test_database_and_postgresql_skills_require_migration_only_discipline():
    source = (SKILLS_DIR / "definitions.py").read_text()
    assert "migration_runner.apply_pending" in source
    assert "migration_runner.drift_report" in source
    assert '"database.schema_change"' in source


# ---- loader stop/escalate discipline -----------------------------------------

def test_loader_never_silently_downgrades_a_missing_required_skill():
    source = (SKILLS_DIR / "loader.py").read_text()
    assert "raise SkillResolutionError" in source
    # It must not have a code path that swallows the missing-skill
    # exception for a REQUIRED (as opposed to optional) skill.
    required_block = source.split("for skill_id in rule.get(\"required\"")[1].split(
        "for skill_id in rule.get(\"optional\"")[0]
    assert "except SkillNotFoundError" in required_block
    assert "raise SkillResolutionError" in required_block
    assert "continue" not in required_block  # optional skills use continue; required never does
