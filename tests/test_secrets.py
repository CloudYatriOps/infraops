import pytest

from aep.secrets import EnvSecretManager, SecretNotFoundError, StaticSecretManager


def test_env_secret_manager_resolves_by_convention(monkeypatch):
    monkeypatch.setenv("AEP_SECRET_GITHUB_TOKEN", "ghp_" + "x" * 30)
    mgr = EnvSecretManager()
    assert mgr.has("github_token") is True
    assert mgr.get("github_token") == "ghp_" + "x" * 30


def test_env_secret_manager_raises_when_missing(monkeypatch):
    monkeypatch.delenv("AEP_SECRET_MISSING_ONE", raising=False)
    mgr = EnvSecretManager()
    assert mgr.has("missing_one") is False
    with pytest.raises(SecretNotFoundError):
        mgr.get("missing_one")


def test_static_secret_manager_for_tests():
    mgr = StaticSecretManager({"github_token": "test-token-123"})
    assert mgr.get("github_token") == "test-token-123"
    with pytest.raises(SecretNotFoundError):
        mgr.get("nonexistent")
