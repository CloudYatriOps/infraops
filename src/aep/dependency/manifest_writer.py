"""Applies a remediation plan's version bump to actual manifest file
content. Text/structure-level edits only - the downstream run_tests +
rescan steps are what prove the bump is actually correct, not this
function's confidence. Plans are passed as plain dicts (the same shape
`RemediationPlan.to_dict()` produces and Task.payload stores), so this
module has no dependency on the dataclass itself.
"""
from __future__ import annotations

import json
import re

from .models import Ecosystem


def apply_plan(manifest_content: str, ecosystem: Ecosystem, plan: dict) -> str:
    if ecosystem == Ecosystem.PYTHON:
        return _apply_requirements_txt(manifest_content, plan)
    if ecosystem == Ecosystem.NODE:
        return _apply_package_json(manifest_content, plan)
    raise NotImplementedError(f"manifest writing not implemented for ecosystem {ecosystem}")


def _apply_requirements_txt(content: str, plan: dict) -> str:
    package, from_version, to_version = plan["package"], plan["from_version"], plan["to_version"]
    pattern = re.compile(
        rf"^(\s*{re.escape(package)}\s*==\s*){re.escape(from_version)}(\s*(?:#.*)?)$",
        re.IGNORECASE | re.MULTILINE,
    )
    new_content, count = pattern.subn(rf"\g<1>{to_version}\g<2>", content)
    if count == 0:
        raise ValueError(f"could not find a pinned '{package}=={from_version}' line to rewrite "
                          f"in the manifest")
    return new_content


def _apply_package_json(content: str, plan: dict) -> str:
    package, to_version = plan["package"], plan["to_version"]
    data = json.loads(content)
    changed = False
    for section in ("dependencies", "devDependencies"):
        deps = data.get(section) or {}
        if package in deps:
            deps[package] = to_version
            changed = True
    if not changed:
        raise ValueError(f"package '{package}' not found in package.json dependencies")
    return json.dumps(data, indent=2) + "\n"
