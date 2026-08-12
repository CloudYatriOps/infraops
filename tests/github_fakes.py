"""A small, stateful in-memory fake of the GitHub REST API surface this
platform uses, for the end-to-end CI-loop test. Routes are matched the same
way the real API is documented (method + path template); everything else
(the GitHubClient, the tools, the agents) is the real code under test."""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Optional
from urllib.parse import unquote

from aep.github.client import HttpResponse


class FakeGitHubTransport:
    def __init__(self):
        self._prs: dict[tuple, list[dict]] = defaultdict(list)
        self._comments: dict[tuple, list[dict]] = defaultdict(list)
        self._next_pr_number = 1
        self._poll_count: dict[tuple, int] = defaultdict(int)
        self.requests_log: list[tuple] = []  # (method, path) - used to assert the token never leaks

    # ---- CI state helpers (test-facing) --------------------------------
    def _ci_state(self, count: int) -> str:
        if count <= 1:
            return "pending"
        if count == 2:
            return "failing"
        return "success"

    # ---- transport entrypoint ------------------------------------------
    def __call__(self, method: str, url: str, headers: dict, params: Optional[dict],
                  json_body: Optional[dict], timeout: int) -> HttpResponse:
        assert "Authorization" in headers
        path = url.split("api.github.com", 1)[1] if "api.github.com" in url else url
        self.requests_log.append((method, path))

        m = re.match(r"^/repos/([^/]+)/([^/]+)/pulls$", path)
        if m and method == "GET":
            return self._list_pulls(m.group(1), m.group(2), params or {})
        if m and method == "POST":
            return self._create_pull(m.group(1), m.group(2), json_body or {})

        m = re.match(r"^/repos/([^/]+)/([^/]+)/pulls/(\d+)$", path)
        if m and method == "PATCH":
            return self._update_pull(m.group(1), m.group(2), int(m.group(3)), json_body or {})
        if m and method == "GET":
            return self._get_pull(m.group(1), m.group(2), int(m.group(3)))

        m = re.match(r"^/repos/([^/]+)/([^/]+)/issues/(\d+)/comments$", path)
        if m and method == "POST":
            return self._create_comment(m.group(1), m.group(2), int(m.group(3)), json_body or {})

        m = re.match(r"^/repos/([^/]+)/([^/]+)/commits/([^/]+)/check-runs$", path)
        if m and method == "GET":
            return self._check_runs(m.group(1), m.group(2), unquote(m.group(3)))

        m = re.match(r"^/repos/([^/]+)/([^/]+)/actions/runs$", path)
        if m and method == "GET":
            return self._workflow_runs(m.group(1), m.group(2), (params or {}).get("branch"))

        m = re.match(r"^/repos/([^/]+)/([^/]+)/actions/runs/(\d+)/jobs$", path)
        if m and method == "GET":
            return self._workflow_jobs(m.group(1), m.group(2), int(m.group(3)))

        m = re.match(r"^/repos/([^/]+)/([^/]+)$", path)
        if m and method == "GET":
            return HttpResponse(200, {"full_name": f"{m.group(1)}/{m.group(2)}", "default_branch": "main"})

        return HttpResponse(404, {"message": "not found in fake transport"}, text='{"message": "not found"}')

    # ---- pulls -----------------------------------------------------------
    def _list_pulls(self, owner, repo, params):
        prs = self._prs[(owner, repo)]
        head = params.get("head")
        results = prs
        if head:
            branch = head.split(":")[-1]
            results = [pr for pr in results if pr["head"]["ref"] == branch]
        state = params.get("state", "open")
        if state != "all":
            results = [pr for pr in results if pr["state"] == state]
        return HttpResponse(200, results)

    def _create_pull(self, owner, repo, body):
        number = self._next_pr_number
        self._next_pr_number += 1
        pr = {
            "number": number, "title": body.get("title"), "body": body.get("body"),
            "state": "open",
            "head": {"ref": body["head"]}, "base": {"ref": body["base"]},
            "html_url": f"https://github.com/{owner}/{repo}/pull/{number}",
        }
        self._prs[(owner, repo)].append(pr)
        return HttpResponse(201, pr)

    def _update_pull(self, owner, repo, number, fields):
        for pr in self._prs[(owner, repo)]:
            if pr["number"] == number:
                pr.update({k: v for k, v in fields.items() if k in ("title", "body", "state")})
                return HttpResponse(200, pr)
        return HttpResponse(404, {"message": "PR not found"}, text='{"message":"not found"}')

    def _get_pull(self, owner, repo, number):
        for pr in self._prs[(owner, repo)]:
            if pr["number"] == number:
                return HttpResponse(200, pr)
        return HttpResponse(404, {"message": "PR not found"}, text='{"message":"not found"}')

    def _create_comment(self, owner, repo, number, body):
        comment = {"id": len(self._comments[(owner, repo, number)]) + 1, "body": body.get("body")}
        self._comments[(owner, repo, number)].append(comment)
        return HttpResponse(201, comment)

    # ---- checks / workflow runs (CI state machine) -----------------------
    def _check_runs(self, owner, repo, ref):
        key = (owner, repo, ref)
        self._poll_count[key] += 1
        state = self._ci_state(self._poll_count[key])
        if state == "pending":
            runs = [{"name": "unit-tests", "status": "in_progress", "conclusion": None, "output": {}}]
        elif state == "failing":
            runs = [{"name": "lint", "status": "completed", "conclusion": "failure",
                     "output": {"summary": "flake8 found an issue", "text": "app.py:1: missing docstring"}},
                    {"name": "unit-tests", "status": "completed", "conclusion": "success", "output": {}}]
        else:
            runs = [{"name": "lint", "status": "completed", "conclusion": "success", "output": {}},
                    {"name": "unit-tests", "status": "completed", "conclusion": "success", "output": {}}]
        return HttpResponse(200, {"total_count": len(runs), "check_runs": runs})

    def _workflow_runs(self, owner, repo, branch):
        key = (owner, repo, branch)
        count = self._poll_count.get(key, 1)
        run_id = 9000 + count
        return HttpResponse(200, {"total_count": 1, "workflow_runs": [
            {"id": run_id, "name": "CI", "head_branch": branch, "status": "completed"},
        ]})

    def _workflow_jobs(self, owner, repo, run_id):
        count = run_id - 9000
        state = self._ci_state(count)
        if state == "failing":
            jobs = [{"name": "lint", "conclusion": "failure",
                     "steps": [{"name": "Run flake8", "conclusion": "failure"}]}]
        elif state == "success":
            jobs = [{"name": "lint", "conclusion": "success",
                     "steps": [{"name": "Run flake8", "conclusion": "success"}]}]
        else:
            jobs = [{"name": "lint", "conclusion": None,
                     "steps": [{"name": "Run flake8", "conclusion": None}]}]
        return HttpResponse(200, {"jobs": jobs})
