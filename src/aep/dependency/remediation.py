"""Remediation planning: pick the smallest safe fixed version per package,
never a blind jump to "latest" (Phase 3 Part A #6/#7). Ambiguous or unsafe
cases (no published fix, unparseable version strings) are surfaced as
`safe=False` with a reason, never silently upgraded - the caller
(DependencyCVEAgent) turns these into an explicit human-escalation task
rather than proceeding.
"""
from __future__ import annotations

from collections import defaultdict

from packaging.version import InvalidVersion, Version

from .models import RemediationPlan, VulnerabilityFinding


def _try_version(v: str):
    try:
        return Version(v)
    except InvalidVersion:
        return None


def plan_remediations(findings: list[VulnerabilityFinding]) -> list[RemediationPlan]:
    """One plan per (ecosystem, manifest_path, package): the smallest
    version that resolves every finding reported against that package in a
    single upgrade."""
    grouped: dict[tuple, list[VulnerabilityFinding]] = defaultdict(list)
    for f in findings:
        grouped[(f.ecosystem, f.manifest_path, f.package)].append(f)

    plans: list[RemediationPlan] = []
    for (ecosystem, manifest_path, package), group in grouped.items():
        installed = group[0].installed_version
        finding_ids = [g.id for g in group]

        if any(not g.fixed_versions for g in group):
            plans.append(RemediationPlan(
                package=package, ecosystem=ecosystem, manifest_path=manifest_path,
                from_version=installed, to_version=None, finding_ids=finding_ids,
                safe=False, major_version_bump=False,
                reason="at least one reported vulnerability for this package has no published "
                       "fixed version yet; upgrading would not resolve it, so no automatic "
                       "remediation is safe here",
            ))
            continue

        per_finding_minimums = []
        unparseable = False
        for g in group:
            parsed = [(pv, v) for v in g.fixed_versions for pv in [_try_version(v)] if pv is not None]
            if not parsed:
                unparseable = True
                break
            parsed.sort(key=lambda pair: pair[0])
            per_finding_minimums.append(parsed[0])

        if unparseable:
            plans.append(RemediationPlan(
                package=package, ecosystem=ecosystem, manifest_path=manifest_path,
                from_version=installed, to_version=None, finding_ids=finding_ids,
                safe=False, major_version_bump=False,
                reason="fixed-version string(s) reported by the scanner could not be parsed as "
                       "versions; refusing to guess at a safe target",
            ))
            continue

        # The version that satisfies every finding at once is the LARGEST
        # of each finding's own minimal fix - that's still the smallest
        # single upgrade that clears all of them together, not "latest".
        target_version, target_str = max(per_finding_minimums, key=lambda pair: pair[0])
        installed_parsed = _try_version(installed)
        major_bump = (installed_parsed is not None
                      and target_version.release[:1] != installed_parsed.release[:1])

        plans.append(RemediationPlan(
            package=package, ecosystem=ecosystem, manifest_path=manifest_path,
            from_version=installed, to_version=target_str, finding_ids=finding_ids,
            safe=True, major_version_bump=major_bump,
            reason=f"smallest version resolving {finding_ids} is {target_str} "
                   f"(installed: {installed})",
        ))
    return plans
