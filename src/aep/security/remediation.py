"""Safe, narrow remediation logic for the three demonstrated real
categories (Phase 4 Part 4/5/6). Every function here is a targeted,
rule-specific transformer that verifies the exact source shape it expects
BEFORE touching anything - none of this "blindly modifies code based only
on scanner text" (the Phase 4 spec's explicit prohibition). Anything that
doesn't match a known-safe shape returns `None` (a plan that can't be
built) rather than guessing, so the caller (`SecurityAgent`) escalates it
to a human instead - the identical "no safe automated remediation ->
escalate" discipline `dependency/remediation.py` already uses for
version-ambiguous upgrades.

Container remediation (Part 7) has no functions here: Part 7 explicitly
says never auto-upgrade a base image without compatibility verification,
and trivy itself is BLOCKED in this sandbox (see
`scanners/trivy_scanner.py`), so there is nothing safe or verifiable to
automate yet.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .models import SecurityFinding
from .secret_manager import EnvVarSecretReference, SecretReferenceManager

# ---------------------------------------------------------------------
# Secret remediation (Part 4)
# ---------------------------------------------------------------------

# Values that look secret-shaped but are well-known placeholders/examples -
# never treated as "likely a real credential" requiring rotation. This list
# is deliberately short and specific (not a broad "contains the word test"
# heuristic, which would create false confidence in the other direction).
_KNOWN_PLACEHOLDER_VALUES = {
    "akiaiosfodnn7example",  # AWS's own documentation example access key
}
_PLACEHOLDER_MARKERS = ("example", "placeholder", "dummy", "fake", "xxxxxxxx", "changeme")


@dataclass
class CredentialAssessment:
    likely_real: bool
    reason: str


def assess_credential_likelihood(raw_value: str, surrounding_line: str = "") -> CredentialAssessment:
    """Part 4 step 1. Takes the raw value ONLY to classify it - the caller
    must never log or persist `raw_value` itself, only this assessment's
    `reason` (which is written to never quote the value back)."""
    lowered = raw_value.lower()
    if lowered in _KNOWN_PLACEHOLDER_VALUES:
        return CredentialAssessment(False, "matches a well-known public documentation example value")
    if any(marker in lowered for marker in _PLACEHOLDER_MARKERS) or \
            any(marker in surrounding_line.lower() for marker in _PLACEHOLDER_MARKERS):
        return CredentialAssessment(False, "value or surrounding line contains a placeholder marker "
                                            "(e.g. 'example'/'placeholder'/'dummy'/'fake')")
    if len(set(raw_value)) <= 2:
        return CredentialAssessment(False, "value has near-zero entropy (repeated character), "
                                            "not a real credential")
    return CredentialAssessment(True, "no placeholder marker found and the value has plausible "
                                       "credential entropy - treat as a real, exposed credential "
                                       "requiring rotation until an operator confirms otherwise")


@dataclass
class SecretRemediationPlan:
    finding_id: str
    file: str
    line: int
    var_name: str
    language: str
    reference_snippet: str
    original_line: str
    replacement_line: str
    needs_import: Optional[str]
    rotation_recommended: bool
    rotation_reason: str


def _language_for(file_path: str) -> str:
    if file_path.endswith(".py"):
        return "python"
    if file_path.endswith((".js", ".ts")):
        return "node"
    return "generic"


_ASSIGNMENT_RE = re.compile(r'^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*(#.*)?$')
_QUOTED_LITERAL_RE = re.compile(r'''["']([^"']{4,})["']''')


def plan_secret_remediation(finding: SecurityFinding, file_content: str,
                             secret_ref_manager: Optional[SecretReferenceManager] = None
                             ) -> Optional[SecretRemediationPlan]:
    """Part 4 steps 2-3-4: locate the exact literal, decide the reference
    shape, build the plan. `file_content` is the CURRENT content of
    `finding.file` (read by the caller through the existing capability-
    scoped filesystem tool, same as every other agent) - the raw secret
    value is read from it here, used only in-memory to build the
    replacement line, and never copied into the returned plan (only
    `original_line`/`replacement_line`, which by construction no longer
    contain it - see the assertion at the end)."""
    secret_ref_manager = secret_ref_manager or EnvVarSecretReference()
    if finding.line is None or finding.file is None:
        return None
    lines = file_content.splitlines()
    idx = finding.line - 1
    if idx < 0 or idx >= len(lines):
        return None
    original_line = lines[idx]

    m = _ASSIGNMENT_RE.match(original_line)
    if not m:
        # Not a simple `NAME = <literal>` assignment - outside the one
        # shape this remediator verifies as safe to auto-rewrite.
        return None
    indent, var_name, value_expr, _comment = m.groups()
    literal_match = _QUOTED_LITERAL_RE.search(value_expr)
    if not literal_match:
        return None
    raw_value = literal_match.group(1)

    assessment = assess_credential_likelihood(raw_value, original_line)

    language = _language_for(finding.file)
    env_var_name = secret_ref_manager.suggest_env_var_name(finding.file, finding.rule_id or var_name)
    # Prefer the variable's own name (already descriptive, e.g.
    # AWS_ACCESS_KEY_ID) over the generic rule-id-derived name when it's a
    # plausible constant name - keeps the remediated code readable.
    if re.fullmatch(r"[A-Z_][A-Z0-9_]*", var_name):
        env_var_name = var_name
    snippet = secret_ref_manager.reference_snippet(language, env_var_name)
    replacement_line = f"{indent}{var_name} = {snippet}"

    needs_import = "os" if language == "python" and "import os" not in file_content else None

    # `original_line` is kept only for a human-readable "what changed"
    # display (e.g. a PR body) - the raw literal is scrubbed out of it
    # before it ever goes into the plan, exactly like every other
    # evidence string in this codebase (redaction.py's `redact()`
    # discipline, applied manually here since this specific literal
    # isn't shaped like any of redaction.py's generic patterns).
    redacted_original_line = original_line.replace(raw_value, "[REDACTED]")

    plan = SecretRemediationPlan(
        finding_id=finding.id, file=finding.file, line=finding.line, var_name=var_name,
        language=language, reference_snippet=snippet, original_line=redacted_original_line,
        replacement_line=replacement_line, needs_import=needs_import,
        rotation_recommended=assessment.likely_real, rotation_reason=assessment.reason,
    )
    # Structural guarantee, not just a convention: the plan we hand back
    # can never contain the raw value anywhere, in any field.
    assert all(raw_value not in str(v) for v in vars(plan).values())
    return plan


def apply_secret_remediation_plan(file_content: str, plan: SecretRemediationPlan) -> str:
    lines = file_content.splitlines(keepends=True)
    idx = plan.line - 1
    newline = "\n" if lines[idx].endswith("\n") else ""
    lines[idx] = plan.replacement_line + newline
    content = "".join(lines)
    if plan.needs_import:
        content = f"import {plan.needs_import}\n" + content
    return content


def inspect_git_history_for_secret(run_shell, repo_path: str, file_path: str) -> dict:
    """Part 4 step 6, policy-gated by the caller (`SecurityAgent` evaluates
    `security.git_history_inspection` before calling this). Best-effort and
    honest about its limits: it only reports whether the file has more
    than one commit touching it (i.e. the secret may have existed in an
    earlier commit even after this remediation), never attempts to purge
    history (that's a separate, much more destructive operation this
    platform does not perform automatically)."""
    result = run_shell(["git", "log", "--oneline", "--", file_path], cwd=repo_path, timeout=15)
    commit_count = len((result.get("stdout") or "").strip().splitlines())
    if not result.get("ok"):
        return {"checked": False, "note": "git log failed; history not inspected"}
    if commit_count > 1:
        return {
            "checked": True,
            "note": f"{file_path} has {commit_count} prior commit(s) - the exposed value may "
                    f"still be recoverable from git history even after this fix; history rewrite "
                    f"was NOT performed automatically (destructive, requires human approval)",
        }
    return {"checked": True, "note": f"{file_path} has no prior history beyond this commit"}


# ---------------------------------------------------------------------
# SAST remediation (Part 5) - one narrow, verified-shape fixer
# ---------------------------------------------------------------------

@dataclass
class SastRemediationPlan:
    finding_id: str
    file: str
    line: int
    original_line: str
    replacement_line: str


# Matches EXACTLY `subprocess.run("<literal prefix>" + <var>, shell=True)`
# (optionally through `subprocess.call`/`Popen`) - the one shape this
# fixer knows how to safely rewrite into an argument list with
# shell=False. Anything else (an f-string, a bare variable, nested calls)
# is refused, not guessed at.
_SHELL_TRUE_RE = re.compile(
    r'^(?P<indent>\s*)subprocess\.(?P<call>run|call|Popen)\('
    r'["\'](?P<prefix>[^"\']*)["\']\s*\+\s*(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*shell\s*=\s*True\)'
    r'(?P<tail>.*)$'
)


def plan_sast_remediation(finding: SecurityFinding, file_content: str
                           ) -> Optional[SastRemediationPlan]:
    if finding.rule_id != "dangerous-subprocess-shell-true" or finding.line is None:
        return None
    lines = file_content.splitlines()
    idx = finding.line - 1
    if idx < 0 or idx >= len(lines):
        return None
    original_line = lines[idx]
    m = _SHELL_TRUE_RE.match(original_line)
    if not m:
        return None
    prefix_tokens = [tok for tok in m.group("prefix").split(" ") if tok]
    args_literal = ", ".join(repr(tok) for tok in prefix_tokens)
    replacement_line = (
        f'{m.group("indent")}subprocess.{m.group("call")}([{args_literal}, {m.group("var")}], '
        f'shell=False){m.group("tail")}'
    )
    return SastRemediationPlan(finding_id=finding.id, file=finding.file, line=finding.line,
                                original_line=original_line, replacement_line=replacement_line)


def apply_sast_remediation_plan(file_content: str, plan: SastRemediationPlan) -> str:
    lines = file_content.splitlines(keepends=True)
    idx = plan.line - 1
    newline = "\n" if lines[idx].endswith("\n") else ""
    lines[idx] = plan.replacement_line + newline
    return "".join(lines)


# ---------------------------------------------------------------------
# IaC remediation (Part 6) - one narrow, verified-shape fixer
# ---------------------------------------------------------------------

@dataclass
class IacRemediationPlan:
    finding_id: str
    file: str
    resource: str
    original_acl_line: str
    replacement_acl_line: str
    appended_block: str


_S3_ACL_RE = re.compile(r'^(\s*)acl\s*=\s*["\'](public-read|public-read-write)["\'](.*)$')

# Deliberately ONE specific check id, not "any finding whose resource is an
# S3 bucket" - a single misconfigured bucket trips several distinct
# checkov checks at once (missing public-access-block, missing event
# notifications, missing replication, ...), and this fixer only knows how
# to safely address the public-ACL one. Matching on resource type alone
# was a real bug caught during Phase 4's own end-to-end test: it built
# (and applied) the identical "add a public access block" plan once per
# S3-related finding, appending the same Terraform block N times.
_SUPPORTED_RULE_IDS = {"CKV2_AWS_6"}


def plan_iac_remediation(finding: SecurityFinding, file_content: str
                          ) -> Optional[IacRemediationPlan]:
    """Only handles checkov's public-S3-access-block finding (CKV2_AWS_6,
    surfaced against `acl = "public-read"`). Restricting an open
    security-group CIDR (the other finding this platform's checkov fixture
    also raises) is deliberately NOT auto-fixed here: picking a "correct"
    restricted CIDR range requires operator knowledge this platform
    doesn't have, so that finding is escalated instead (see
    SecurityAgent)."""
    if finding.rule_id not in _SUPPORTED_RULE_IDS:
        return None
    if finding.resource is None or "aws_s3_bucket" not in finding.resource:
        return None
    lines = file_content.splitlines()
    acl_idx = None
    for i, line in enumerate(lines):
        if _S3_ACL_RE.match(line):
            acl_idx = i
            break
    if acl_idx is None:
        return None
    m = _S3_ACL_RE.match(lines[acl_idx])
    indent, _old_acl, tail = m.groups()
    replacement_acl_line = f'{indent}acl    = "private"{tail}'
    resource_name = finding.resource.split(".", 1)[1] if "." in finding.resource else finding.resource
    appended_block = (
        f'\nresource "aws_s3_bucket_public_access_block" "{resource_name}_block" {{\n'
        f'  bucket                  = aws_s3_bucket.{resource_name}.id\n'
        f'  block_public_acls       = true\n'
        f'  block_public_policy     = true\n'
        f'  ignore_public_acls      = true\n'
        f'  restrict_public_buckets = true\n'
        f'}}\n'
    )
    return IacRemediationPlan(
        finding_id=finding.id, file=finding.file, resource=finding.resource,
        original_acl_line=lines[acl_idx], replacement_acl_line=replacement_acl_line,
        appended_block=appended_block,
    )


def apply_iac_remediation_plan(file_content: str, plan: IacRemediationPlan) -> str:
    content = file_content.replace(plan.original_acl_line, plan.replacement_acl_line)
    return content.rstrip("\n") + "\n" + plan.appended_block
