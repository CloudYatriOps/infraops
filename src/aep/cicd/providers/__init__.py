"""CI provider adapters. `base.py` is the provider-agnostic contract;
`github_actions.py` is the one fully-implemented provider; `registry.py`
lists GitLab CI/Jenkins/generic as architecturally supported but NOT
implemented, the same "implement the architecture, fully implement one
provider" discipline `infra/cloud/` uses for cloud adapters."""
