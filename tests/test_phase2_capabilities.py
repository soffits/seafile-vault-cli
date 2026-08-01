import io
import json
import os
import stat

import httpx
import pytest

from seafile_vault_cli.client import (
    MAX_THUMBNAIL_BYTES,
    CapabilityError,
    Config,
    ConfigError,
    LinkSecurityError,
    LocalFileError,
    PermissionMode,
    PermissionModeError,
    SeafileVaultClient,
    SeafileVaultError,
    SizeLimitError,
    validate_commit_id,
)

TEST_REPO_ID = "11111111-2222-3333-4444-555555555555"
OTHER_REPO_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
COMMIT_ID = "0123456789abcdef0123456789abcdef01234567"


def _client(handler, *, account_token="account-secret", permission_mode=PermissionMode.READ_WRITE):
    return SeafileVaultClient(
        "https://seafile.example.com",
        "repo-secret",
        account_token=account_token,
        permission_mode=permission_mode,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def test_optional_account_token_config_and_launcher_allowlist(tmp_path, monkeypatch):
    from seafile_vault_cli import library_launcher

    monkeypatch.setenv("SEAFILE_SERVER_URL", "https://seafile.example.com")
    monkeypatch.setenv("SEAFILE_REPO_TOKEN", "repo-secret")
    monkeypatch.delenv("SEAFILE_ACCOUNT_TOKEN", raising=False)
    assert Config.from_env().account_token is None

    monkeypatch.setenv("SEAFILE_ACCOUNT_TOKEN", "account-secret")
    assert Config.from_env().account_token == "account-secret"
    monkeypatch.setenv("SEAFILE_ACCOUNT_TOKEN", "")
    with pytest.raises(ConfigError):
        Config.from_env()

    config_dir = tmp_path / "libraries"
    config_dir.mkdir(mode=0o700)
    profile = config_dir / "docs.env"
    profile.write_text(
        "SEAFILE_SERVER_URL=https://seafile.example.com\nSEAFILE_REPO_TOKEN=repo-secret\nSEAFILE_ACCOUNT_TOKEN=account-secret\n",
        encoding="utf-8",
    )
    profile.chmod(0o600)
    seen = []

    def fake_main(argv):
        seen.append((argv, os.environ.get("SEAFILE_ACCOUNT_TOKEN")))
        return 0

    monkeypatch.setenv("SEAFILE_LIBRARY_CONFIG_DIR", str(config_dir))
    monkeypatch.setattr(library_launcher.cli, "main", fake_main)
    assert library_launcher.main(["docs", "repo-info"]) == 0
    assert seen == [(["repo-info"], "account-secret")]


def test_account_and_repo_headers_are_isolated_and_history_scrubs_repo_ids():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        assert request.url.path == f"/api/v2.1/repos/{TEST_REPO_ID}/history/"
        assert request.url.params["page"] == "2"
        assert request.url.params["per_page"] == "3"
        return httpx.Response(200, json={"repo_id": TEST_REPO_ID, "commits": [{"repo_id": TEST_REPO_ID, "commit_id": COMMIT_ID}]})

    result = _client(handler).library_history(page=2, per_page=3)

    assert requests[0].headers["authorization"] == "Bearer repo-secret"
    assert requests[1].headers["authorization"] == "Token account-secret"
    assert "repo_id" not in json.dumps(result)
    assert result == {"commits": [{"commit_id": COMMIT_ID}]}


def test_file_history_cursor_and_account_absence_error():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        assert request.url.path == f"/api/v2.1/repos/{TEST_REPO_ID}/file/history/"
        assert request.url.params["path"] == "/docs/note.txt"
        assert request.url.params["commit_id"] == COMMIT_ID
        return httpx.Response(200, json={"history": []})

    assert _client(handler).file_history("/docs/note.txt", cursor=COMMIT_ID) == {"history": []}
    assert [request.headers["authorization"] for request in requests] == ["Bearer repo-secret", "Token account-secret"]

    no_account = _client(lambda request: httpx.Response(200, json={"repo_id": TEST_REPO_ID}), account_token=None)
    with pytest.raises(CapabilityError, match="SEAFILE_ACCOUNT_TOKEN"):
        no_account.library_history()


def test_restore_uses_repo_token_payload_without_account_and_obeys_read_only():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"repo_id": TEST_REPO_ID, "success": True})

    client = _client(handler, account_token=None)
    result = client.restore_file("/docs/note.txt", commit_id=COMMIT_ID)

    assert requests[0].url.path == "/api/v2.1/via-repo-token/file/"
    assert requests[0].headers["authorization"] == "Bearer repo-secret"
    assert json.loads(requests[0].content) == {"operation": "revert", "commit_id": COMMIT_ID}
    assert "repo_id" not in json.dumps(result)
    assert result["type"] == "file"

    read_only = _client(handler, account_token=None, permission_mode=PermissionMode.READ_ONLY)
    with pytest.raises(PermissionModeError):
        read_only.restore_directory("/docs", commit_id=COMMIT_ID)
    with pytest.raises(ConfigError):
        validate_commit_id("not-a-commit")


def test_share_lifecycle_filters_current_repo_payloads_and_rejects_cross_library_revoke():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.method == "GET" and request.url.path == "/api/v2.1/share-links/":
            return httpx.Response(
                200,
                json={
                    "share_links": [
                        {"repo_id": TEST_REPO_ID, "token": "keep-token", "link": "https://seafile.example.com/d/public", "path": "/docs"},
                        {"repo_id": OTHER_REPO_ID, "token": "other-token", "link": "https://seafile.example.com/d/other"},
                    ]
                },
            )
        if request.method == "POST" and request.url.path == "/api/v2.1/share-links/":
            payload = json.loads(request.content)
            assert payload == {
                "repo_id": TEST_REPO_ID,
                "path": "/docs/note.txt",
                "expire_days": 7,
                "permissions": {"can_view": True, "can_download": False},
                "password": "secret-password",
            }
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID, "token": "new-token", "link": "https://seafile.example.com/d/new"})
        if request.method == "DELETE":
            assert request.url.path == "/api/v2.1/share-links/keep-token/"
            return httpx.Response(200, json={"success": True})
        raise AssertionError(str(request.url))

    client = _client(handler)
    listed = client.list_share_links()
    assert listed == {"count": 1, "links": [{"link": "https://seafile.example.com/d/public", "path": "/docs"}]}
    created = client.create_share_link("/docs/note.txt", permission="view-only", password="secret-password")
    assert created == {"link": "https://seafile.example.com/d/new"}
    assert client.revoke_share_link("keep-token") == {"revoked": True, "server_result": {"success": True}}
    with pytest.raises(CapabilityError):
        client.revoke_share_link("other-token")
    assert all(request.headers["authorization"] in {"Bearer repo-secret", "Token account-secret"} for request in requests)


def test_share_create_and_revoke_require_read_write_but_list_is_read_only():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == "/api/v2.1/share-links/":
            return httpx.Response(200, json={"share_links": [{"repo_id": TEST_REPO_ID, "token": "keep-token", "link": "https://seafile.example.com/d/public"}]})
        return httpx.Response(200, json={"success": True})

    read_only = _client(handler, permission_mode=PermissionMode.READ_ONLY)
    assert read_only.list_share_links() == {"count": 1, "links": [{"link": "https://seafile.example.com/d/public"}]}
    with pytest.raises(PermissionModeError):
        read_only.create_share_link("/docs/note.txt")
    with pytest.raises(PermissionModeError):
        read_only.revoke_share_link("keep-token")


def test_share_links_are_same_origin_and_password_is_redacted_from_errors():
    def foreign_link(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        return httpx.Response(
            200,
            json={"share_links": [{"repo_id": TEST_REPO_ID, "token": "t", "link": "https://evil.example.net/d/t"}]},
        )

    with pytest.raises(LinkSecurityError, match="host must match"):
        _client(foreign_link).list_share_links()

    password = "do-not-echo-this-password"

    def echoed_password(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        return httpx.Response(400, text=f"invalid password: {password}")

    with pytest.raises(SeafileVaultError) as exc_info:
        _client(echoed_password).create_share_link("/docs/note.txt", password=password)
    assert password not in str(exc_info.value)
    assert "[REDACTED]" in str(exc_info.value)


@pytest.mark.parametrize("expire_days", [0, 31])
def test_share_expiry_is_finite_and_bounded(expire_days):
    client = SeafileVaultClient(
        "https://seafile.example.com",
        "repo-secret",
        account_token="account-secret",
        permission_mode=PermissionMode.READ_WRITE,
    )
    with pytest.raises(ConfigError):
        client.create_share_link("/docs", expire_days=expire_days)


def test_cli_grouped_parsers_and_stdin_secret_handling(monkeypatch, capsys):
    from seafile_vault_cli import cli

    parser = cli.build_parser()
    assert parser.parse_args(["history", "library", "--page", "2"]).page == 2
    assert parser.parse_args(["restore", "file", "/a.txt", "--commit", COMMIT_ID, "--confirm"]).restore_command == "file"
    assert parser.parse_args(["share", "create", "/a.txt", "--confirm-public"]).expire_days == 7
    assert parser.parse_args(["thumbnail", "/a.png", "a.png", "--size", "128"]).size == 128
    with pytest.raises(SystemExit):
        parser.parse_args(["share", "create", "/a.txt"])
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "usage"

    calls = []

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def create_share_link(self, path, *, expire_days, permission, password):
            calls.append((path, expire_days, permission, password))
            return {"link": "https://seafile.example.com/d/new"}

    monkeypatch.setattr(cli.SeafileVaultClient, "from_env", lambda: FakeClient())
    monkeypatch.setattr("sys.stdin", io.StringIO("pw\n"))
    assert cli.main(["share", "create", "/a.txt", "--password-stdin", "--confirm-public"]) == 0
    assert calls == [("/a.txt", 7, "view-download", "pw")]

    monkeypatch.setattr("sys.stdin", io.StringIO("\n"))
    assert cli.main(["share", "create", "/a.txt", "--password-stdin", "--confirm-public"]) == 3
    assert "non-empty" in json.loads(capsys.readouterr().err)["error"]["message"]


def test_thumbnail_download_uses_account_api_and_0600_output(tmp_path):
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == f"/api2/repos/{TEST_REPO_ID}/thumbnail/":
            assert request.url.params["p"] == "/docs/image.png"
            assert request.url.params["size"] == "128"
            return httpx.Response(200, content=b"\x89PNG", headers={"content-type": "image/png", "content-length": "4"})
        raise AssertionError(str(request.url))

    dest = tmp_path / "thumb.png"
    result = _client(handler).download_thumbnail_path("/docs/image.png", dest, size=128)

    assert dest.read_bytes() == b"\x89PNG"
    assert stat.S_IMODE(dest.stat().st_mode) == 0o600
    assert result == {
        "remote_path": "/docs/image.png",
        "local_path": os.fspath(dest),
        "byte_count": 4,
        "content_type": "image/png",
        "requested_size": 128,
    }
    assert requests[0].headers["authorization"] == "Bearer repo-secret"
    assert requests[1].headers["authorization"] == "Token account-secret"
    assert "api2/repos" not in json.dumps(result)


def test_thumbnail_fails_before_network_without_account_token(tmp_path):
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        raise AssertionError("no request should be made")

    client = SeafileVaultClient(
        "https://seafile.example.com",
        "repo-secret",
        account_token=None,
        permission_mode=PermissionMode.READ_ONLY,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    dest = tmp_path / "missing-token.png"
    with pytest.raises(CapabilityError, match="SEAFILE_ACCOUNT_TOKEN"):
        client.download_thumbnail_path("/docs/image.png", dest)
    assert requests == []
    assert not dest.exists()


def test_thumbnail_rejects_redirects_html_size_truncation_and_symlink(tmp_path):
    def client_for_thumbnail(thumbnail_response: httpx.Response):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
                return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
            assert request.url.path == f"/api2/repos/{TEST_REPO_ID}/thumbnail/"
            return thumbnail_response

        return _client(handler)

    with pytest.raises(LinkSecurityError):
        client_for_thumbnail(httpx.Response(302, headers={"location": "https://evil.example.net/thumbnail/x"})).download_thumbnail_path(
            "/docs/image.png", tmp_path / "redir.png"
        )

    with pytest.raises(CapabilityError, match="HTML"):
        client_for_thumbnail(httpx.Response(200, content=b"<html>", headers={"content-type": "text/html"})).download_thumbnail_path(
            "/docs/image.png", tmp_path / "html.png"
        )

    with pytest.raises(SizeLimitError):
        client_for_thumbnail(
            httpx.Response(200, headers={"content-type": "image/png", "content-length": str(MAX_THUMBNAIL_BYTES + 1)})
        ).download_thumbnail_path(
            "/docs/image.png",
            tmp_path / "large.png",
        )

    with pytest.raises(SeafileVaultError, match="length did not match"):
        client_for_thumbnail(
            httpx.Response(200, content=b"ok", headers={"content-type": "image/png", "content-length": "10"})
        ).download_thumbnail_path(
            "/docs/image.png",
            tmp_path / "truncated.png",
        )

    existing = tmp_path / "existing.png"
    existing.write_bytes(b"old")
    link = tmp_path / "link.png"
    link.symlink_to(existing)
    with pytest.raises(LocalFileError):
        client_for_thumbnail(httpx.Response(200, content=b"ok", headers={"content-type": "image/png"})).download_thumbnail_path(
            "/docs/image.png", link, overwrite=True
        )
    assert existing.read_bytes() == b"old"
