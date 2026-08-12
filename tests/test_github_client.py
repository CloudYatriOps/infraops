import pytest

from aep.github.client import (
    GitHubAuthError, GitHubClient, GitHubNotFoundError, GitHubRateLimitError,
    GitHubValidationError, GitHubError, HttpResponse,
)


def _client(transport, token="test-token"):
    return GitHubClient(token_provider=lambda: token, transport=transport)


def test_get_repo_calls_correct_endpoint_and_parses_response():
    calls = []

    def transport(method, url, headers, params, json_body, timeout):
        calls.append((method, url, headers, params, json_body))
        return HttpResponse(200, {"full_name": "acme/widgets"})

    client = _client(transport)
    result = client.get_repo("acme", "widgets")

    assert result == {"full_name": "acme/widgets"}
    method, url, headers, params, json_body = calls[0]
    assert method == "GET"
    assert url == "https://api.github.com/repos/acme/widgets"
    assert headers["Authorization"] == "Bearer test-token"
    assert headers["Accept"] == "application/vnd.github+json"


def test_create_pull_request_sends_correct_body():
    captured = {}

    def transport(method, url, headers, params, json_body, timeout):
        captured.update(method=method, url=url, json_body=json_body)
        return HttpResponse(201, {"number": 7, "html_url": "https://github.com/acme/widgets/pull/7"})

    client = _client(transport)
    result = client.create_pull_request("acme", "widgets", title="Fix bug", head="aep/fix-1",
                                         base="main", body="details")

    assert captured["method"] == "POST"
    assert captured["url"].endswith("/repos/acme/widgets/pulls")
    assert captured["json_body"] == {"title": "Fix bug", "head": "aep/fix-1", "base": "main", "body": "details"}
    assert result["number"] == 7


def test_list_pull_requests_passes_filter_params():
    captured = {}

    def transport(method, url, headers, params, json_body, timeout):
        captured["params"] = params
        return HttpResponse(200, [])

    client = _client(transport)
    client.list_pull_requests("acme", "widgets", state="open", head="acme:aep/fix-1")
    assert captured["params"] == {"state": "open", "head": "acme:aep/fix-1"}


def test_token_never_appears_in_request_body_or_url():
    def transport(method, url, headers, params, json_body, timeout):
        assert "super-secret-token" not in url
        assert not (json_body and "super-secret-token" in str(json_body))
        return HttpResponse(200, {})

    client = _client(transport, token="super-secret-token")
    client.get_repo("acme", "widgets")  # only assertion is inside transport


@pytest.mark.parametrize("status,expected_exc", [
    (401, GitHubAuthError),
    (404, GitHubNotFoundError),
    (422, GitHubValidationError),
    (500, GitHubError),
])
def test_error_status_codes_raise_specific_exceptions(status, expected_exc):
    def transport(method, url, headers, params, json_body, timeout):
        return HttpResponse(status, {"message": "boom"}, text='{"message": "boom"}')

    client = _client(transport)
    with pytest.raises(expected_exc):
        client.get_repo("acme", "widgets")


def test_403_with_rate_limit_header_raises_rate_limit_error():
    def transport(method, url, headers, params, json_body, timeout):
        return HttpResponse(403, {"message": "rate limited"}, headers={"X-RateLimit-Remaining": "0"})

    client = _client(transport)
    with pytest.raises(GitHubRateLimitError):
        client.get_repo("acme", "widgets")


def test_403_without_rate_limit_header_raises_auth_error():
    def transport(method, url, headers, params, json_body, timeout):
        return HttpResponse(403, {"message": "forbidden"}, headers={"X-RateLimit-Remaining": "42"})

    client = _client(transport)
    with pytest.raises(GitHubAuthError):
        client.get_repo("acme", "widgets")


def test_network_error_wrapped_as_github_error():
    def transport(method, url, headers, params, json_body, timeout):
        raise ConnectionError("dns failure")

    client = _client(transport)
    with pytest.raises(GitHubError):
        client.get_repo("acme", "widgets")


def test_list_check_runs_and_workflow_jobs_real_endpoints():
    def transport(method, url, headers, params, json_body, timeout):
        if url.endswith("/commits/main/check-runs"):
            return HttpResponse(200, {"check_runs": [{"name": "ci", "conclusion": "success"}]})
        if url.endswith("/actions/runs/42/jobs"):
            return HttpResponse(200, {"jobs": [{"name": "build", "conclusion": "success"}]})
        raise AssertionError(f"unexpected url {url}")

    client = _client(transport)
    checks = client.list_check_runs("acme", "widgets", "main")
    jobs = client.list_workflow_run_jobs("acme", "widgets", 42)
    assert checks["check_runs"][0]["name"] == "ci"
    assert jobs["jobs"][0]["name"] == "build"
