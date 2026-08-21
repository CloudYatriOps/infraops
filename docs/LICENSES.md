# Licensing

AEP's own source (`src/aep/`) is **MIT** — see [`LICENSE`](../LICENSE).

## Why MIT is compatible

A public PyPI wheel/sdist ships plain, readable `.py` source (verified:
`unzip -l`/`tarfile` shows every module as an uncompiled `.py` file, not
bytecode-only) — a public PyPI release of AEP is therefore effectively
open-source regardless of the license text, since anyone can already read
the implementation. MIT makes that formally explicit and imposes the
fewest restrictions on reuse, which fits a local-first developer tool
meant to be inspected and trusted.

None of AEP's dependencies are GPL/AGPL (which would require AEP's own
source to adopt a compatible copyleft license to redistribute). The two
LGPL-licensed *optional* security scanners (`semgrep`, `checkov`) are
invoked as separate subprocess binaries — `src/aep/security/scanners/
semgrep_scanner.py`/`checkov_scanner.py` call `run_shell(["semgrep", ...])`
/`run_shell(["checkov", ...])`, never `import semgrep`/`import checkov`
into AEP's own process — which is separate-process invocation, not
linking, and does not trigger LGPL's obligations on the calling program
(the same relationship AEP already has with `git`, `gitleaks`, `trivy`:
external CLI tools it shells out to, never links against).

## Dependency / license table

| Component | License | Bundled? | Affects AEP's license? | Notes |
|---|---|---|---|---|
| AEP itself | MIT | — | — | This repository. |
| `pgserver` | Apache-2.0 | Yes (core dep) | No | Wraps and manages the bundled PostgreSQL binary. |
| PostgreSQL (bundled by `pgserver`) | PostgreSQL License (permissive, OSI-approved) | Yes (via `pgserver`'s binary distribution) | No | The actual database engine `pgserver` runs. |
| `pgvector` (Python client) | MIT | Yes (core dep) | No | Python client for the `vector` extension. |
| pgvector (Postgres extension, bundled by `pgserver`) | MIT/Apache-2.0 dual | Yes (via `pgserver`'s binary distribution) | No | The C extension itself, upstream project. |
| `psycopg2-binary` | LGPL with exceptions | Yes (core dep) | No | Explicit psycopg license exception permits dynamic linking without copyleft propagation; also invoked as a library, not statically linked into a derivative binary. |
| `PyYAML` | MIT | Yes (core dep) | No | |
| `packaging` | Apache-2.0 OR BSD-2-Clause | Yes (core dep) | No | Dual-licensed, take either. |
| `platformdirs` | MIT | Yes (transitive, via `pgserver`) | No | |
| `fasteners` | Apache-2.0 | Yes (transitive, via `pgserver`) | No | |
| `psutil` | BSD-3-Clause | Yes (transitive, via `pgserver`) | No | |
| `pytest` | MIT | Yes (core dep — the CEO demo runs a real `pytest` against the demo fixture) | No | |
| `flask` | BSD-3-Clause | Optional (`api` extra) | No | |
| `boto3` | Apache-2.0 | Optional (`infra` extra) | No | |
| `bc-python-hcl2` | MIT | Optional (`infra` extra) | No | Real Terraform HCL2 parsing. |
| `kubernetes-validate` | Apache-2.0 | Optional (`infra` extra) | No | |
| `cyclonedx-python-lib` | Apache-2.0 | Optional (`sbom` extra) | No | |
| `requests` | Apache-2.0 | Optional (`github` extra) | No | |
| `pip-audit` | Apache-2.0 | Optional (`dependency-scanning` extra) | No | |
| `anthropic` (SDK) | MIT | Optional (`anthropic` extra) | No | AEP has no dependency on this for core function — see Providers screen; using it is entirely opt-in. |
| `semgrep` | LGPL-2.1 | Optional (`sast` extra), invoked as external subprocess binary | No (see above) | Never imported into AEP's process. |
| `checkov` | Apache-2.0 | Optional (`iac` extra) | No | |
| `gitleaks` (auto-detected if present, never required) | MIT | No — external binary, not a Python dependency at all | No | AEP's own built-in secret scanner (`security/scanners/builtin_secret_scanner.py`) works without it; `gitleaks` only adds more rules when already installed on the host. |
| `trivy` (referenced for container scanning) | Apache-2.0 | No — external binary; container scanning is `BLOCKED` in this product (needs registry/network access AEP does not provide) | No | |

No component in this table is GPL or AGPL. No bundled runtime artifact
(the PostgreSQL binary, the pgvector extension) carries a copyleft
license. MIT for AEP's own source is not blocked by anything above.
