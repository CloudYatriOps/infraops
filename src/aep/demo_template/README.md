# src/aep/demo_template

A disposable fixture project used only by `aep demo run` (see
`src/aep/demo.py`) and `tests/test_end_to_end_demo.py`-style scenarios.
It is copied into a fresh temp directory and turned into a real git repo
at demo time - this directory itself is never git-committed-to or
mutated in place.

Contents, by design:
- `app.py` - one intentional bug (`add()` subtracts instead of adding).
- `test_app.py` - a real pytest that fails until the bug is fixed.
- `config.py` - a placeholder, obviously-fake AWS-key-shaped string used
  to exercise the security-scan-blocks-the-graph path. Not a real secret.

This is a generic fixture, not modeled on any specific product (e.g. not
KarCrew/Kubedoctor/KAI-specific) - it exists purely to give the AEP demo
flow a real filesystem/git/security-scanner target to operate on.
