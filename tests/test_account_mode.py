import json
from urllib.parse import parse_qs

import httpx
import pytest

from seafile_vault_cli.client import (
    Config,
    ConfigError,
    PermissionMode,
    PermissionModeError,
    RemoteNotFoundError,
    SeafileVaultClient,
    SeafileVaultError,
)

REPO_ID = "11111111-2222-3333-4444-555555555555"
ACCOUNT_TOKEN = "account-secret-token"
SERVER = "https://seafile.example.com"
REPO = f"{SERVER}/api/v2.1/repos/{REPO_ID}"


def _client(handler, *, mode=PermissionMode.READ_WRITE, **kwargs):
    return SeafileVaultClient(
        SERVER,
        account_token=ACCOUNT_TOKEN,
        repo_id=REPO_ID,
        permission_mode=mode,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        **kwargs,
    )


def _recording(response_for):
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return response_for(request)

    return handler, requests


def _body(request: httpx.Request):
    return json.loads(request.content)


def _query(request: httpx.Request):
    return {key: values[0] for key, values in parse_qs(request.url.query.decode()).items()}


def test_account_mode_sends_token_header_to_user_api():
    full = {"repo_id": REPO_ID, "repo_name": "Lib", "owner_email": "x@y", "size": 1}
    handler, requests = _recording(lambda r: httpx.Response(200, json=full))
    info = _client(handler).get_repo_info()
    assert info == {"repo_id": REPO_ID, "repo_name": "Lib", "size": 1}
    assert str(requests[0].url) == f"{REPO}/"
    assert requests[0].headers["Authorization"] == f"Token {ACCOUNT_TOKEN}"


def test_list_directory_uses_user_api_parameters_and_iso_mtimes():
    payload = {
        "dirent_list": [
            {"type": "file", "name": "a.txt", "mtime": 1794196701, "size": 3},
            {"type": "dir", "name": "d", "mtime": "kept"},
        ]
    }
    handler, requests = _recording(lambda r: httpx.Response(200, json=payload))
    data = _client(handler).list_directory("/docs", recursive=True, type_filter="f")
    assert requests[0].url.path == f"/api/v2.1/repos/{REPO_ID}/dir/"
    assert _query(requests[0]) == {"p": "/docs", "recursive": "1", "t": "f"}
    assert data["dirent_list"][0]["mtime"] == "2026-11-09T03:58:21+00:00"
    assert data["dirent_list"][1]["mtime"] == "kept"


def test_stat_and_missing_file_use_file_endpoint():
    def respond(request):
        if _query(request)["p"] == "/missing":
            return httpx.Response(404, json={"error_msg": "nope"})
        return httpx.Response(200, json={"size": 12, "obj_name": "a"})

    handler, requests = _recording(respond)
    client = _client(handler)
    assert client.stat_file("/a")["size"] == 12
    assert requests[0].url.path == f"/api/v2.1/repos/{REPO_ID}/file/"
    with pytest.raises(RemoteNotFoundError):
        client.stat_file("/missing")


def test_download_link_uses_reuse_flag_on_api2_file_endpoint():
    def respond(request):
        if request.url.path.endswith("/file/"):
            return httpx.Response(200, json=f"{SERVER}/seafhttp/files/tok/a.txt")
        return httpx.Response(200, content=b"hello", headers={"content-length": "5"})

    handler, requests = _recording(respond)
    assert _client(handler).read_file_bytes("/a.txt") == b"hello"
    assert requests[0].url.path == f"/api2/repos/{REPO_ID}/file/"
    assert _query(requests[0]) == {"p": "/a.txt", "reuse": "1"}
    assert "Authorization" not in requests[1].headers


def test_upload_link_uses_api2_and_replace_flag():
    handler, requests = _recording(lambda r: httpx.Response(200, json=f"{SERVER}/seafhttp/upload-api/tok"))
    link = _client(handler)._get_upload_link("/dir", overwrite=True)
    assert link.endswith("/upload-api/tok")
    assert requests[0].url.path == f"/api2/repos/{REPO_ID}/upload-link/"
    assert _query(requests[0]) == {"p": "/dir", "replace": "1"}


def test_upload_writes_bytes_through_upload_link():
    def respond(request):
        if request.url.path.endswith("/upload-link/"):
            return httpx.Response(200, json=f"{SERVER}/seafhttp/upload-api/tok")
        if "upload-api" in request.url.path:
            return httpx.Response(200, json=[{"name": "n.txt", "size": 2}])
        return httpx.Response(200, json={"size": 2})

    handler, requests = _recording(respond)
    _client(handler).upload_file_bytes("/n.txt", b"hi")
    assert any("upload-api" in r.url.path for r in requests)


def test_file_operations_carry_destination_repo():
    handler, requests = _recording(lambda r: httpx.Response(200, json={"obj_name": "f (1)", "type": "file"}))
    client = _client(handler)
    client.copy_file("/a", "/b")
    client.move_path("/a", "/b")
    client.rename_path("/a", "z")
    copy_body, move_body, rename_body = (_body(r) for r in requests)
    assert copy_body == {"operation": "copy", "dst_repo": REPO_ID, "dst_dir": "/b"}
    assert move_body == {"operation": "move", "dst_repo": REPO_ID, "dst_dir": "/b"}
    assert rename_body == {"operation": "rename", "newname": "z"}
    assert all(r.url.path == f"/api/v2.1/repos/{REPO_ID}/file/" for r in requests)


def test_directory_move_and_copy_use_batch_endpoints():
    handler, requests = _recording(lambda r: httpx.Response(200, json={"success": True}))
    client = _client(handler)
    client.move_path("/a/dir", "/b", is_directory=True)
    client.copy_directory("/a/dir", "/b")
    move, copy = requests
    assert move.url.path == "/api/v2.1/repos/sync-batch-move-item/"
    assert copy.url.path == "/api/v2.1/repos/sync-batch-copy-item/"
    expected = {"src_repo_id": REPO_ID, "src_parent_dir": "/a", "src_dirents": ["dir"], "dst_repo_id": REPO_ID, "dst_parent_dir": "/b"}
    assert _body(move) == expected
    assert _body(copy) == expected


def test_mkdir_delete_lock_and_restore_use_path_key_p():
    handler, requests = _recording(
        lambda r: httpx.Response(200, json={"dirent_list": []} if r.method == "GET" else {"obj_name": "d", "success": True})
    )
    client = _client(handler)
    client.create_directory("/d")
    client.delete_path("/d", recursive=True)
    client.lock_file("/f", 60)
    client.restore_file("/f", commit_id="0" * 40)
    mkdir_listing, mkdir, delete, lock, restore = requests
    assert mkdir.method == "POST" and _query(mkdir) == {"p": "/d"} and _body(mkdir) == {"operation": "mkdir"}
    assert delete.method == "DELETE" and _query(delete) == {"p": "/d"} and delete.url.path.endswith("/dir/")
    assert lock.method == "PUT" and _query(lock) == {"p": "/f"} and _body(lock)["operation"] == "lock"
    assert _body(restore) == {"operation": "revert", "commit_id": "0" * 40}
    assert _query(mkdir_listing) == {"p": "/"}


def test_metadata_routes_live_under_the_repo():
    handler, requests = _recording(lambda r: httpx.Response(200, json={"views": []}))
    _client(handler).metadata_views_list()
    assert str(requests[0].url) == f"{REPO}/metadata/views/"
    assert requests[0].headers["Authorization"] == f"Token {ACCOUNT_TOKEN}"


def test_history_and_shares_use_configured_repo_without_repo_info_call():
    def respond(request):
        if request.url.path.endswith("/share-links/"):
            return httpx.Response(200, json=[{"repo_id": REPO_ID, "token": "t", "link": f"{SERVER}/d/t/"}])
        return httpx.Response(200, json={"data": []})

    handler, requests = _recording(respond)
    client = _client(handler)
    client.library_history()
    assert client.list_share_links()["count"] == 1
    assert all("/repos/" not in r.url.path or REPO_ID in r.url.path for r in requests)


def test_read_only_mode_still_blocks_writes():
    handler, requests = _recording(lambda r: httpx.Response(200, json={}))
    client = _client(handler, mode=PermissionMode.READ_ONLY)
    with pytest.raises(PermissionModeError):
        client.delete_path("/a")
    with pytest.raises(PermissionModeError):
        client.write_text_file("/a.txt", "x")
    assert requests == []


def test_errors_redact_the_account_token():
    handler, _ = _recording(lambda r: httpx.Response(500, text=f"boom {ACCOUNT_TOKEN}"))
    with pytest.raises(SeafileVaultError) as exc:
        _client(handler).list_directory("/")
    assert ACCOUNT_TOKEN not in str(exc.value)


def test_resume_probe_uses_account_token():
    handler, requests = _recording(lambda r: httpx.Response(200, json={"uploadedBytes": 4}))
    uploaded = _client(handler)._get_uploaded_bytes(repo_id=REPO_ID, parent="/", name="f", total=10)
    assert uploaded == 4
    assert requests[0].headers["Authorization"] == f"Token {ACCOUNT_TOKEN}"


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"repo_id": REPO_ID},
        {"account_token": ACCOUNT_TOKEN},
        {"repo_id": "not-a-uuid", "account_token": ACCOUNT_TOKEN},
        {"repo_token": "r", "repo_id": REPO_ID, "account_token": ACCOUNT_TOKEN},
    ],
)
def test_client_requires_exactly_one_library_credential(kwargs):
    with pytest.raises(ConfigError):
        SeafileVaultClient(SERVER, **kwargs)


def _env(monkeypatch, **values):
    for key in list(__import__("os").environ):
        if key.startswith("SEAFILE_"):
            monkeypatch.delenv(key)
    for key, value in values.items():
        monkeypatch.setenv(key, value)


def test_config_account_mode_from_env_with_token_file(monkeypatch, tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text(f"{ACCOUNT_TOKEN}\n")
    _env(monkeypatch, SEAFILE_SERVER_URL=SERVER, SEAFILE_REPO_ID=REPO_ID, SEAFILE_ACCOUNT_TOKEN_FILE=str(token_file))
    cfg = Config.from_env()
    assert cfg.repo_id == REPO_ID and cfg.repo_token is None and cfg.account_token == ACCOUNT_TOKEN
    client = SeafileVaultClient.from_env()
    assert client.backend.headers["Authorization"] == f"Token {ACCOUNT_TOKEN}"


@pytest.mark.parametrize(
    "values",
    [
        {"SEAFILE_REPO_ID": REPO_ID},
        {"SEAFILE_REPO_ID": REPO_ID, "SEAFILE_REPO_TOKEN": "r", "SEAFILE_ACCOUNT_TOKEN": "a"},
        {},
    ],
)
def test_config_rejects_ambiguous_or_incomplete_credentials(monkeypatch, values):
    _env(monkeypatch, SEAFILE_SERVER_URL=SERVER, **values)
    with pytest.raises(ConfigError):
        Config.from_env()


def test_repo_token_mode_is_unchanged(monkeypatch):
    _env(monkeypatch, SEAFILE_SERVER_URL=SERVER, SEAFILE_REPO_TOKEN="r")
    client = SeafileVaultClient.from_env()
    assert client.backend.url("dir/") == f"{SERVER}/api/v2.1/via-repo-token/dir/"
    assert client.backend.path_key == "path"
