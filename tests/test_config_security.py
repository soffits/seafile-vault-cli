import re

import httpx
import pytest

from seafile_vault_cli.client import Config, ConfigError, LinkSecurityError, PathSecurityError, SeafileVaultClient, redact_secret


def test_config_from_env_defaults_to_read_only_and_parses_limits(monkeypatch):
    monkeypatch.setenv("SEAFILE_SERVER_URL", "https://seafile.example.com/")
    monkeypatch.setenv("SEAFILE_REPO_TOKEN", "super-secret-token")
    for name in [
        "SEAFILE_PERMISSION_MODE",
        "SEAFILE_MAX_READ_SIZE",
        "SEAFILE_MAX_WRITE_SIZE",
        "SEAFILE_UPLOAD_TIMEOUT",
        "SEAFILE_UPLOAD_CHUNK_SIZE",
        "SEAFILE_UPLOAD_DIRECT_IP",
    ]:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SEAFILE_REQUEST_TIMEOUT", "12.5")
    cfg = Config.from_env()
    assert cfg.server_url == "https://seafile.example.com"
    assert cfg.repo_token == "super-secret-token"
    assert cfg.permission_mode == "read_only"
    assert cfg.max_read_size == 1024 * 1024
    assert cfg.max_write_size == 10 * 1024 * 1024
    assert cfg.request_timeout == 12.5
    assert cfg.upload_timeout == 3600
    assert cfg.upload_chunk_size == 64 * 1024 * 1024


def test_config_from_env_parses_read_write_and_direct_ip(monkeypatch):
    monkeypatch.setenv("SEAFILE_SERVER_URL", "https://seafile.example.com")
    monkeypatch.setenv("SEAFILE_REPO_TOKEN", "super-secret-token")
    monkeypatch.setenv("SEAFILE_PERMISSION_MODE", "read_write")
    monkeypatch.setenv("SEAFILE_UPLOAD_DIRECT_IP", "203.0.113.10")
    cfg = Config.from_env()
    assert cfg.permission_mode == "read_write"
    assert cfg.upload_direct_ip == "203.0.113.10"


def test_config_from_env_canonicalizes_ipv6_direct_ip(monkeypatch):
    monkeypatch.setenv("SEAFILE_SERVER_URL", "https://seafile.example.com")
    monkeypatch.setenv("SEAFILE_REPO_TOKEN", "super-secret-token")
    monkeypatch.setenv("SEAFILE_UPLOAD_DIRECT_IP", "2001:0db8:0000:0000:0000:0000:0000:0001")
    cfg = Config.from_env()
    assert cfg.upload_direct_ip == "2001:db8::1"


def test_config_from_env_parses_upload_timeout(monkeypatch):
    monkeypatch.setenv("SEAFILE_SERVER_URL", "https://seafile.example.com")
    monkeypatch.setenv("SEAFILE_REPO_TOKEN", "super-secret-token")
    monkeypatch.setenv("SEAFILE_UPLOAD_TIMEOUT", "600.5")
    cfg = Config.from_env()
    assert cfg.upload_timeout == 600.5


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("12345", 12345),
        ("32MiB", 32 * 1024 * 1024),
        ("64 MiB", 64 * 1024 * 1024),
        ("64MB", 64 * 1000 * 1000),
        ("1 kb", 1000),
        ("2KIB", 2 * 1024),
        ("3 b", 3),
    ],
)
def test_config_from_env_parses_upload_chunk_size(monkeypatch, value, expected):
    monkeypatch.setenv("SEAFILE_SERVER_URL", "https://seafile.example.com")
    monkeypatch.setenv("SEAFILE_REPO_TOKEN", "super-secret-token")
    monkeypatch.setenv("SEAFILE_UPLOAD_CHUNK_SIZE", value)
    cfg = Config.from_env()
    assert cfg.upload_chunk_size == expected


@pytest.mark.parametrize("value", ["0", "-1", "+1", "1.5MiB", "true", "[]", "64XB", "64 Mi B", "90000001", "1GiB"])
def test_config_rejects_invalid_upload_chunk_size(monkeypatch, value):
    monkeypatch.setenv("SEAFILE_SERVER_URL", "https://seafile.example.com")
    monkeypatch.setenv("SEAFILE_REPO_TOKEN", "super-secret-token")
    monkeypatch.setenv("SEAFILE_UPLOAD_CHUNK_SIZE", value)
    with pytest.raises(ConfigError):
        Config.from_env()


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf"])
def test_config_rejects_non_positive_or_non_finite_upload_timeout(monkeypatch, value):
    monkeypatch.setenv("SEAFILE_SERVER_URL", "https://seafile.example.com")
    monkeypatch.setenv("SEAFILE_REPO_TOKEN", "super-secret-token")
    monkeypatch.setenv("SEAFILE_UPLOAD_TIMEOUT", value)
    with pytest.raises(ConfigError):
        Config.from_env()


@pytest.mark.parametrize(
    "bad_path",
    ["", "relative.txt", "../x", "/../x", "/a/../b", "/a//b", "/a/./b", "/a/\x00b", "/a/\x1fb", "/a/\x7fb"],
)
def test_unsafe_paths_are_rejected(bad_path):
    client = SeafileVaultClient("https://seafile.example.com", "secret")
    with pytest.raises(PathSecurityError):
        client.validate_vault_path(bad_path)


@pytest.mark.parametrize(
    ("input_path", "expected"),
    [
        ("/", "/"),
        ("/a", "/a"),
        ("/a/b.txt", "/a/b.txt"),
        ("/space name/file.md", "/space name/file.md"),
        ("/unicode/雪.txt", "/unicode/雪.txt"),
    ],
)
def test_safe_absolute_posix_paths_are_accepted(input_path, expected):
    client = SeafileVaultClient("https://seafile.example.com", "secret")
    assert client.validate_vault_path(input_path) == expected


@pytest.mark.parametrize("bad_name", ["bad\x00name", "bad\x1fname", "bad\x7fname"])
def test_name_segments_reject_ascii_control_characters(bad_name):
    client = SeafileVaultClient("https://seafile.example.com", "secret", permission_mode="read_write")
    with pytest.raises(PathSecurityError):
        client.rename_path("/folder/old.txt", bad_name)


def test_name_segments_allow_unicode():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"success": True})

    client = SeafileVaultClient(
        "https://seafile.example.com",
        "secret",
        permission_mode="read_write",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    client.rename_path("/folder/old.txt", "雪.txt")
    assert requests


def test_redact_secret_removes_token_from_error_text():
    text = "Authorization failed for super-secret-token at https://example"
    assert "super-secret-token" not in redact_secret(text, "super-secret-token")
    assert "[REDACTED]" in redact_secret(text, "super-secret-token")


def test_client_exception_redacts_token(httpx_mock_transport):
    client, _requests = httpx_mock_transport(status_code=500, json_body={"error": "super-secret-token failed"})
    with pytest.raises(Exception) as exc:
        client.get_repo_info()
    assert "super-secret-token" not in str(exc.value)


def test_download_link_must_be_http_or_https_same_origin():
    client = SeafileVaultClient("https://seafile.example.com", "secret")
    assert client.validate_download_url("https://seafile.example.com/d/abc") == "https://seafile.example.com/d/abc"
    for bad_url in [
        "file:///etc/passwd",
        "http://127.0.0.1:8080/metadata",
        "https://evil.example.net/file",
        "http://seafile.example.com/file",
        "https://seafile.example.com:8443/file",
        "https://user:pass@seafile.example.com/file",
    ]:
        with pytest.raises(LinkSecurityError):
            client.validate_download_url(bad_url)


def test_same_origin_comparison_normalizes_default_ports():
    https_client = SeafileVaultClient("https://seafile.example.com", "secret")
    assert https_client.validate_download_url("https://seafile.example.com:443/d/abc") == "https://seafile.example.com:443/d/abc"
    http_client = SeafileVaultClient("http://seafile.example.com", "secret")
    assert http_client.validate_download_url("http://seafile.example.com:80/d/abc") == "http://seafile.example.com:80/d/abc"
    explicit_client = SeafileVaultClient("https://seafile.example.com:443", "secret")
    assert explicit_client.validate_download_url("https://seafile.example.com/d/abc") == "https://seafile.example.com/d/abc"
    with pytest.raises(LinkSecurityError):
        https_client.validate_download_url("https://seafile.example.com:444/d/abc")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"repo_token": ""},
        {"repo_token": "   "},
        {"max_read_size": 0},
        {"max_read_size": 1.5},
        {"max_write_size": -1},
        {"max_write_size": True},
        {"timeout": 0},
        {"timeout": float("inf")},
        {"upload_timeout": -1},
        {"upload_timeout": float("nan")},
        {"upload_chunk_size": 0},
        {"upload_chunk_size": 90_000_001},
        {"upload_chunk_size": "64MiB"},
        {"permission_mode": "invalid"},
        {"upload_direct_ip": "not-an-ip"},
    ],
)
def test_client_constructor_arguments_fail_closed(kwargs):
    params = {"repo_token": "secret"} | kwargs
    with pytest.raises(ConfigError):
        SeafileVaultClient("https://seafile.example.com", **params)


def test_owned_http_client_uses_supplied_request_timeout():
    client = SeafileVaultClient("https://seafile.example.com", "secret", timeout=12.5)
    try:
        assert client.http.timeout == httpx.Timeout(12.5)
    finally:
        client.close()


def test_skill_frontmatter_is_hermes_compatible():
    skill = open("SKILL.md", encoding="utf-8").read()
    assert skill.startswith("---\n")
    frontmatter = skill.split("---\n", 2)[1]
    assert "name: seafile-vault-cli" in frontmatter
    assert re.search(r"description: Use when ", frontmatter)
    assert "author: Sakina" in frontmatter
    assert "license: AGPL-3.0" in frontmatter
    assert "metadata:" in frontmatter
    assert "hermes:" in frontmatter
    assert "tags:" in frontmatter
