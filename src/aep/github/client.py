"""A real GitHub REST API (v3) client.

This speaks the actual documented endpoints (https://docs.github.com/en/rest)
with the actual request/response shapes GitHub uses - method, path, params,
JSON body, and status-code semantics all match the real API, so pointing
this at a real token and repo works unmodified. What's swappable for tests
is only the `transport` - the function that actually sends bytes over the
wire - so the exact same client code is exercised whether the transport is
`requests` talking to api.github.com or an in-memory fake used in tests
(ARCHITECTURE.md §7's provider-abstraction pattern applied to HTTP).

The token is never accepted as a stored value: `token_provider` is a
zero-argument callable resolved fresh on every request (see secrets.py),
and no exception message or return value here ever includes it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import quote

DEFAULT_BASE_URL = "https://api.github.com"
DEFAULT_API_VERSION = "2022-11-28"
DEFAULT_TIMEOUT = 15


class GitHubError(RuntimeError):
    def __init__(self, message: str, status_code: Optional[int] = None,
                 endpoint: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.endpoint = endpoint


class GitHubAuthError(GitHubError):
    """401/403 that is not a rate limit - bad or insufficiently-scoped token."""


class GitHubRateLimitError(GitHubError):
    """403 with X-RateLimit-Remaining: 0 - transient, worth retrying with backoff."""


class GitHubNotFoundError(GitHubError):
    """404 - repo/PR/branch/etc. does not exist or token can't see it."""


class GitHubValidationError(GitHubError):
    """422 - request was rejected (e.g. PR already exists for this head/base)."""


@dataclass
class HttpResponse:
    """Minimal response shape the client depends on - deliberately small so
    a test fake only has to implement four fields, not a full `requests`
    Response."""
    status_code: int
    json_body: Any = None
    text: str = ""
    headers: dict = field(default_factory=dict)

    def json(self) -> Any:
        return self.json_body


Transport = Callable[..., HttpResponse]


def _seg(value: str) -> str:
    """Percent-encode a value used as a single URL path segment - branch
    names routinely contain '/' (e.g. 'aep/fix-1234'), which would otherwise
    silently corrupt the path structure of ref-based endpoints like
    /commits/{ref}/check-runs. Caught by Phase 2's CI-monitor end-to-end
    test, which uses a real slash-containing branch name."""
    return quote(value, safe="")


def _requests_transport(method: str, url: str, headers: dict,
                         params: Optional[dict], json_body: Optional[dict],
                         timeout: int) -> HttpResponse:
    import requests  # imported lazily so the fake-transport test path never needs it installed-behavior verified

    resp = requests.request(method, url, headers=headers, params=params,
                             json=json_body, timeout=timeout)
    try:
        parsed = resp.json() if resp.text else None
    except ValueError:
        parsed = None
    return HttpResponse(status_code=resp.status_code, json_body=parsed,
                         text=resp.text, headers=dict(resp.headers))


class GitHubClient:
    def __init__(self, token_provider: Callable[[], str],
                 base_url: str = DEFAULT_BASE_URL,
                 transport: Optional[Transport] = None,
                 timeout: int = DEFAULT_TIMEOUT,
                 user_agent: str = "aep-platform"):
        self._token_provider = token_provider
        self._base_url = base_url.rstrip("/")
        self._transport = transport or _requests_transport
        self._timeout = timeout
        self._user_agent = user_agent

    # ---- core request plumbing ---------------------------------------
    def _request(self, method: str, path: str, params: Optional[dict] = None,
                 json_body: Optional[dict] = None) -> Any:
        url = f"{self._base_url}{path}"
        token = self._token_provider()
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": DEFAULT_API_VERSION,
            "User-Agent": self._user_agent,
        }
        del token  # never referenced again in this frame after building headers
        try:
            resp = self._transport(method, url, headers=headers, params=params,
                                    json_body=json_body, timeout=self._timeout)
        except Exception as e:  # noqa: BLE001 - network/transport failure, classified upstream
            raise GitHubError(f"network error calling GitHub API {method} {path}: {e}",
                               endpoint=path) from e

        return self._raise_for_status(resp, method, path)

    def _raise_for_status(self, resp: HttpResponse, method: str, path: str) -> Any:
        status = resp.status_code
        if status == 401:
            raise GitHubAuthError(f"GitHub auth failed (401) on {method} {path}", status, path)
        if status == 403:
            remaining = resp.headers.get("X-RateLimit-Remaining")
            if remaining == "0":
                raise GitHubRateLimitError(f"GitHub rate limit exceeded on {method} {path}",
                                            status, path)
            raise GitHubAuthError(f"GitHub access forbidden (403) on {method} {path} "
                                   f"(check token scopes/permissions)", status, path)
        if status == 404:
            raise GitHubNotFoundError(f"GitHub resource not found (404) on {method} {path}",
                                       status, path)
        if status == 422:
            raise GitHubValidationError(
                f"GitHub rejected the request (422) on {method} {path}: {resp.text[:300]}",
                status, path)
        if status == 429 or status >= 500:
            raise GitHubError(f"GitHub transient error ({status}) on {method} {path}",
                               status, path)
        if not (200 <= status < 300):
            raise GitHubError(f"unexpected GitHub response ({status}) on {method} {path}: "
                               f"{resp.text[:300]}", status, path)
        return resp.json()

    # ---- repository discovery -----------------------------------------
    def get_repo(self, owner: str, repo: str) -> dict:
        return self._request("GET", f"/repos/{owner}/{repo}")

    # ---- branches -------------------------------------------------------
    def list_branches(self, owner: str, repo: str) -> list:
        return self._request("GET", f"/repos/{owner}/{repo}/branches")

    def get_branch(self, owner: str, repo: str, branch: str) -> dict:
        return self._request("GET", f"/repos/{owner}/{repo}/branches/{_seg(branch)}")

    # ---- commits --------------------------------------------------------
    def list_commits(self, owner: str, repo: str, sha: Optional[str] = None,
                      path: Optional[str] = None) -> list:
        params = {}
        if sha:
            params["sha"] = sha
        if path:
            params["path"] = path
        return self._request("GET", f"/repos/{owner}/{repo}/commits", params=params or None)

    def get_commit(self, owner: str, repo: str, sha: str) -> dict:
        return self._request("GET", f"/repos/{owner}/{repo}/commits/{_seg(sha)}")

    # ---- pull requests ----------------------------------------------------
    def list_pull_requests(self, owner: str, repo: str, state: str = "open",
                            head: Optional[str] = None, base: Optional[str] = None) -> list:
        params = {"state": state}
        if head:
            params["head"] = head
        if base:
            params["base"] = base
        return self._request("GET", f"/repos/{owner}/{repo}/pulls", params=params)

    def get_pull_request(self, owner: str, repo: str, number: int) -> dict:
        return self._request("GET", f"/repos/{owner}/{repo}/pulls/{number}")

    def create_pull_request(self, owner: str, repo: str, title: str, head: str,
                             base: str, body: str = "") -> dict:
        return self._request("POST", f"/repos/{owner}/{repo}/pulls",
                              json_body={"title": title, "head": head, "base": base, "body": body})

    def update_pull_request(self, owner: str, repo: str, number: int, **fields) -> dict:
        return self._request("PATCH", f"/repos/{owner}/{repo}/pulls/{number}", json_body=fields)

    def list_pr_files(self, owner: str, repo: str, number: int) -> list:
        return self._request("GET", f"/repos/{owner}/{repo}/pulls/{number}/files")

    # ---- PR/issue comments (PRs are issues in the GitHub API) ---------
    def create_issue_comment(self, owner: str, repo: str, number: int, body: str) -> dict:
        return self._request("POST", f"/repos/{owner}/{repo}/issues/{number}/comments",
                              json_body={"body": body})

    def list_issue_comments(self, owner: str, repo: str, number: int) -> list:
        return self._request("GET", f"/repos/{owner}/{repo}/issues/{number}/comments")

    # ---- PR checks / status --------------------------------------------
    def get_combined_status(self, owner: str, repo: str, ref: str) -> dict:
        return self._request("GET", f"/repos/{owner}/{repo}/commits/{_seg(ref)}/status")

    def list_check_runs(self, owner: str, repo: str, ref: str) -> dict:
        return self._request("GET", f"/repos/{owner}/{repo}/commits/{_seg(ref)}/check-runs")

    # ---- issues ------------------------------------------------------------
    def list_issues(self, owner: str, repo: str, state: str = "open") -> list:
        return self._request("GET", f"/repos/{owner}/{repo}/issues", params={"state": state})

    def create_issue(self, owner: str, repo: str, title: str, body: str = "") -> dict:
        return self._request("POST", f"/repos/{owner}/{repo}/issues",
                              json_body={"title": title, "body": body})

    # ---- workflow / CI run status ----------------------------------------
    def list_workflow_runs(self, owner: str, repo: str, branch: Optional[str] = None) -> dict:
        params = {"branch": branch} if branch else None
        return self._request("GET", f"/repos/{owner}/{repo}/actions/runs", params=params)

    def get_workflow_run(self, owner: str, repo: str, run_id: int) -> dict:
        return self._request("GET", f"/repos/{owner}/{repo}/actions/runs/{run_id}")

    def list_workflow_run_jobs(self, owner: str, repo: str, run_id: int) -> dict:
        return self._request("GET", f"/repos/{owner}/{repo}/actions/runs/{run_id}/jobs")
