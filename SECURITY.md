# Security Policy

AEP is a local-first tool: it runs on your own machine, scans repositories
you point it at, and stores its data in a local, loopback-only PostgreSQL
instance. There is no AEP-hosted service that holds your data.

## Reporting a vulnerability

Please report suspected security issues privately using
[GitHub's private vulnerability reporting](https://github.com/CloudYatriOps/infraops/security/advisories/new)
for this repository, rather than opening a public issue.

Include, if possible:

- A description of the issue and its potential impact.
- Steps to reproduce (a minimal example is ideal).
- The AEP version (`aep --version`) and OS.

**Do not include real credentials, tokens, or other secrets in a report** -
describe the class of data at risk rather than pasting an actual value,
even your own.

## Response expectations

This project is maintained by a small team. We aim to acknowledge a report
within a reasonable time and will keep the reporter updated as the issue is
investigated, but we cannot commit to a fixed SLA. Confirmed vulnerabilities
will be fixed and disclosed via a new release and a `BUGFIX.md` entry.

## Supported versions

The latest release on [PyPI](https://pypi.org/project/aep-platform/) is the
only version that receives security fixes. There is no long-term-support
branch at this time.

## Scope

In scope: AEP's own source (`src/aep/`, `ui/`) as shipped in this
repository and on PyPI as `aep-platform`.

Out of scope: vulnerabilities in third-party dependencies (report those
upstream) unless AEP's use of them creates an additional, AEP-specific
issue; and the local machine's own OS/network security, which is outside
AEP's control by design (AEP binds to loopback only and never requires
elevated privileges).
