#!/usr/bin/env python3
"""CI gate: runs `aep security .` and fails the build ONLY on a finding not
already present in `.github/security-baseline.json` - i.e. a genuinely new,
unreviewed finding. Never disables AEP's own secret/IaC detection (that
still runs in full and every finding is printed); this only decides what
makes the CI job red versus what's a documented, already-verified fixture
(see security-baseline.json's own `_readme` field for the full reasoning).

Not a change to AEP's product code - this script and its baseline live
entirely under .github/ and are CI configuration, the same role a
gitleaks/detect-secrets baseline file plays in other projects.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE_PATH = Path(__file__).resolve().parent / "security-baseline.json"


def _key(file_: str, rule: str, line) -> tuple:
    return (file_.replace("\\", "/"), rule, str(line))


def main() -> int:
    baseline = json.loads(BASELINE_PATH.read_text())
    known = {_key(f["file"], f["rule"], f["line"]) for f in baseline["findings"]}

    proc = subprocess.run(
        [sys.executable, "-m", "aep.cli", "security", str(REPO_ROOT), "--json"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if proc.returncode != 0:
        print("`aep security` itself failed to run:", proc.stderr, file=sys.stderr)
        return 1

    report = json.loads(proc.stdout)
    all_findings = [f for a in report["analyzers"] for f in a["findings"]]
    new_findings = [f for f in all_findings
                    if _key(f["file"], f["rule"], f["line"]) not in known]

    print(f"{len(all_findings)} total finding(s), {len(known)} baseline entries, "
          f"{len(new_findings)} not in baseline.")
    if new_findings:
        print("\nNEW / UNREVIEWED finding(s) - not in .github/security-baseline.json:")
        for f in new_findings:
            print(f"  [{f['severity']}] {f['file']}:{f['line']} ({f['rule']}) - {f['description']}")
        print("\nIf this is a real secret: remove it and rotate the credential "
              "immediately, do not just delete this line from history.")
        print("If this is a legitimate new fixture/example: add it to "
              ".github/security-baseline.json after confirming by hand it is "
              "not a real secret.")
        return 1

    print("No new findings outside the reviewed baseline.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
