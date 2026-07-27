import base64
import json
import os
import stat
import subprocess
from pathlib import Path
from urllib.parse import unquote

import httpx
import pytest

import seafile_vault_cli.client as client_module
from seafile_vault_cli.client import (
    BoundedFileReader,
    ConfigError,
    LinkSecurityError,
    LocalFileError,
    PathSecurityError,
    PermissionMode,
    PermissionModeError,
    RemoteNotFoundError,
    SeafileVaultClient,
    SeafileVaultError,
    SizeLimitError,
)

TEST_REPO_ID = "11111111-2222-3333-4444-555555555555"


def _chunked_client(handler, *, chunk_size=4, max_write_size=200 * 1024 * 1024):
    return SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        permission_mode=PermissionMode.READ_WRITE,
        max_write_size=max_write_size,
        upload_chunk_size=chunk_size,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def test_get_repo_info_uses_via_repo_token_and_bearer_header(httpx_mock_transport):
    client, requests = httpx_mock_transport(json_body={"repo_name": "Vault"})
    assert client.get_repo_info() == {"repo_name": "Vault"}
    req = requests[0]
    assert req.method == "GET"
    assert str(req.url) == "https://seafile.example.com/api/v2.1/via-repo-token/repo-info/"
    assert req.headers["Authorization"] == "Bearer super-secret-token"


def test_read_only_mode_allows_reads_and_blocks_writes(httpx_mock_transport):
    client, requests = httpx_mock_transport(json_body=[], permission_mode=PermissionMode.READ_ONLY)
    assert client.list_directory("/") == []
    with pytest.raises(PermissionModeError):
        client.create_directory("/new")
    with pytest.raises(PermissionModeError):
        client.rename_path("/old", "new")
    with pytest.raises(PermissionModeError):
        client.move_path("/old", "/archive")
    with pytest.raises(PermissionModeError):
        client.delete_path("/old")
    with pytest.raises(PermissionModeError):
        client.write_text_file("/file.txt", "hello")
    assert len(requests) == 1


def test_programmatic_upload_chunk_size_remains_integer_only():
    client = SeafileVaultClient("https://seafile.example.com", "secret", permission_mode=PermissionMode.READ_WRITE)
    with pytest.raises(ConfigError):
        client.upload_file_path("missing.bin", "/folder/missing.bin", chunk_size="64MiB")


def test_list_directory_calls_dir_endpoint_with_path(httpx_mock_transport):
    client, requests = httpx_mock_transport(json_body=[{"name": "notes", "type": "dir"}])
    assert client.list_directory("/") == [{"name": "notes", "type": "dir"}]
    assert requests[0].url.path == "/api/v2.1/via-repo-token/dir/"
    assert requests[0].url.params["path"] == "/"


def test_download_link_calls_endpoint(httpx_mock_transport):
    client, requests = httpx_mock_transport(json_body="https://seafile.example.com/download/link")
    assert client.get_download_link("/note.txt") == "https://seafile.example.com/download/link"
    assert requests[0].url.path == "/api/v2.1/via-repo-token/download-link/"
    assert requests[0].url.params["path"] == "/note.txt"


def test_stat_file_calls_file_endpoint_and_not_found_is_error(httpx_mock_transport):
    client, requests = httpx_mock_transport(json_body={"name": "note.txt", "size": 5})
    assert client.stat_file("/note.txt") == {"name": "note.txt", "size": 5}
    assert requests[0].url.path == "/api/v2.1/via-repo-token/file/"
    assert requests[0].url.params["path"] == "/note.txt"

    missing, _ = httpx_mock_transport(status_code=404, json_body={"detail": "missing"})
    with pytest.raises(RemoteNotFoundError):
        missing.stat_file("/missing.txt")
    with pytest.raises(PathSecurityError):
        client.stat_file("/")


def test_download_file_path_streams_to_0600_temp_and_returns_hash(tmp_path):
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/api/v2.1/via-repo-token/download-link/":
            return httpx.Response(200, json="https://seafile.example.com/file-secret")
        return httpx.Response(200, content=b"hello", headers={"content-length": "5"})

    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        max_read_size=5,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    dest = tmp_path / "note.txt"
    result = client.download_file_path("/note.txt", dest)
    assert dest.read_bytes() == b"hello"
    assert stat.S_IMODE(dest.stat().st_mode) == 0o600
    assert result == {
        "remote_path": "/note.txt",
        "local_name": "note.txt",
        "size": 5,
        "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        "overwrite": False,
    }
    assert str(requests[1].url) == "https://seafile.example.com/file-secret"


def test_download_file_path_handles_partial_os_write(tmp_path, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/download-link/":
            return httpx.Response(200, json="https://seafile.example.com/file")
        return httpx.Response(200, content=b"abcdef", headers={"content-length": "6"})

    original_write = os.write
    writes = []

    def partial_write(fd, data):
        chunk = bytes(data[:2])
        written = original_write(fd, chunk)
        writes.append(written)
        return written

    monkeypatch.setattr("seafile_vault_cli.client.os.write", partial_write)
    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    dest = tmp_path / "note.txt"
    result = client.download_file_path("/note.txt", dest)
    assert dest.read_bytes() == b"abcdef"
    assert result["size"] == 6
    assert result["sha256"] == "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721"
    assert writes == [2, 2, 2]


def test_download_file_path_zero_os_write_fails_without_publish(tmp_path, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/download-link/":
            return httpx.Response(200, json="https://seafile.example.com/file")
        return httpx.Response(200, content=b"abc")

    monkeypatch.setattr("seafile_vault_cli.client.os.write", lambda _fd, _data: 0)
    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(LocalFileError, match="no progress"):
        client.download_file_path("/note.txt", tmp_path / "note.txt")
    assert not (tmp_path / "note.txt").exists()


def test_download_file_path_overwrite_replaces_regular_file(tmp_path):
    dest = tmp_path / "note.txt"
    dest.write_text("old", encoding="utf-8")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/download-link/":
            return httpx.Response(200, json="https://seafile.example.com/file")
        return httpx.Response(200, content=b"new", headers={"content-length": "3"})

    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert client.download_file_path("/note.txt", dest, overwrite=True)["overwrite"] is True
    assert dest.read_bytes() == b"new"


def test_download_file_path_rejects_bad_destinations(tmp_path):
    client = SeafileVaultClient("https://seafile.example.com", "super-secret-token")
    with pytest.raises(LocalFileError):
        client.download_file_path("/note.txt", tmp_path / "missing" / "note.txt")
    with pytest.raises(LocalFileError, match="file name"):
        client.download_file_path("/note.txt", "/")
    with pytest.raises(LocalFileError):
        client.download_file_path("/note.txt", tmp_path)
    dest = tmp_path / "exists.txt"
    dest.write_text("old", encoding="utf-8")
    with pytest.raises(LocalFileError):
        client.download_file_path("/note.txt", dest)
    link = tmp_path / "link.txt"
    link.symlink_to(dest)
    with pytest.raises(LocalFileError):
        client.download_file_path("/note.txt", link, overwrite=True)


def test_download_file_path_rejects_special_destination_with_overwrite(tmp_path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    client = SeafileVaultClient("https://seafile.example.com", "super-secret-token")
    with pytest.raises(LocalFileError):
        client.download_file_path("/note.txt", fifo, overwrite=True)


def test_download_file_path_closes_parent_fd_on_destination_validation_failure(tmp_path, monkeypatch):
    dest = tmp_path / "exists.txt"
    dest.write_text("old", encoding="utf-8")
    original_close = os.close
    closed_parent_fds = []

    def close_spy(fd):
        try:
            target = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            target = None
        if target is not None and Path(target) == tmp_path:
            closed_parent_fds.append(fd)
        original_close(fd)

    monkeypatch.setattr(client_module.os, "close", close_spy)
    client = SeafileVaultClient("https://seafile.example.com", "super-secret-token")

    with pytest.raises(LocalFileError, match="already exists"):
        client.download_file_path("/note.txt", dest)

    assert len(closed_parent_fds) == 1


def test_download_file_path_size_limit_content_length_leaves_existing_file(tmp_path):
    dest = tmp_path / "note.txt"
    dest.write_bytes(b"old")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/download-link/":
            return httpx.Response(200, json="https://seafile.example.com/file")
        return httpx.Response(200, content=b"toolarge", headers={"content-length": "8"})

    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        max_read_size=7,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(SizeLimitError):
        client.download_file_path("/note.txt", dest, overwrite=True)
    assert dest.read_bytes() == b"old"
    assert list(tmp_path.glob("*.tmp")) == []


def test_download_file_path_negative_content_length_fails_and_cleans_temp(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/download-link/":
            return httpx.Response(200, json="https://seafile.example.com/file")
        return httpx.Response(200, content=b"abc", headers={"content-length": "-1"})

    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(SeafileVaultError, match="negative"):
        client.download_file_path("/note.txt", tmp_path / "note.txt")
    assert not (tmp_path / "note.txt").exists()
    assert list(tmp_path.glob("*.tmp")) == []


def test_download_file_path_size_limit_without_content_length_cleans_temp(tmp_path):
    class ChunkStream(httpx.SyncByteStream):
        def __iter__(self):
            yield b"abc"
            yield b"def"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/download-link/":
            return httpx.Response(200, json="https://seafile.example.com/file")
        return httpx.Response(200, stream=ChunkStream())

    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        max_read_size=5,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(SizeLimitError):
        client.download_file_path("/note.txt", tmp_path / "note.txt")
    assert not (tmp_path / "note.txt").exists()
    assert list(tmp_path.glob("*.tmp")) == []


def test_download_file_path_truncated_response_fails_without_corruption(tmp_path):
    dest = tmp_path / "note.txt"
    dest.write_bytes(b"old")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/download-link/":
            return httpx.Response(200, json="https://seafile.example.com/file")
        return httpx.Response(200, content=b"new", headers={"content-length": "4"})

    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(SeafileVaultError, match="content-length"):
        client.download_file_path("/note.txt", dest, overwrite=True)
    assert dest.read_bytes() == b"old"


def test_download_file_path_http_error_redacts_link(tmp_path):
    link = "https://seafile.example.com/download/secret-token"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/download-link/":
            return httpx.Response(200, json=link)
        return httpx.Response(500, text=f"failed {link}")

    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(SeafileVaultError) as exc:
        client.download_file_path("/note.txt", tmp_path / "note.txt")
    assert "secret-token" not in str(exc.value)
    assert link not in str(exc.value)


def test_download_file_path_streaming_http_error_does_not_read_or_leak_body(tmp_path):
    link = "https://seafile.example.com/download/secret-token"

    class ErrorStream(httpx.SyncByteStream):
        def __iter__(self):
            yield f"failed {link}".encode()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/download-link/":
            return httpx.Response(200, json=link)
        return httpx.Response(500, stream=ErrorStream())

    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(SeafileVaultError) as exc:
        client.download_file_path("/note.txt", tmp_path / "note.txt")
    assert str(exc.value) == "Seafile download HTTP 500"
    assert "secret-token" not in str(exc.value)
    assert link not in str(exc.value)


def test_download_file_path_missing_remote_raises_remote_not_found(tmp_path, monkeypatch):
    original_close = os.close
    closed_parent_fds = []

    def close_spy(fd):
        try:
            target = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            target = None
        if target is not None and Path(target) == tmp_path:
            closed_parent_fds.append(fd)
        original_close(fd)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v2.1/via-repo-token/download-link/"
        return httpx.Response(404, json={"detail": "missing"})

    monkeypatch.setattr(client_module.os, "close", close_spy)
    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(RemoteNotFoundError, match="/missing.txt"):
        client.download_file_path("/missing.txt", tmp_path / "missing.txt")
    assert len(closed_parent_fds) == 1


def test_read_text_bytes_and_base64_use_download_link_and_enforce_size():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/api/v2.1/via-repo-token/download-link/":
            return httpx.Response(200, json="https://seafile.example.com/file")
        assert str(request.url) == "https://seafile.example.com/file"
        return httpx.Response(200, content=b"hello", headers={"content-length": "5"})

    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        max_read_size=5,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert client.read_text_file("/note.txt") == "hello"
    assert client.read_file_bytes("/note.txt") == b"hello"
    assert client.read_file_base64("/note.txt") == base64.b64encode(b"hello").decode("ascii")
    assert len(requests) == 6


def test_read_text_file_rejects_too_large_content_length():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/download-link/":
            return httpx.Response(200, json="https://seafile.example.com/file")
        return httpx.Response(200, content=b"too large", headers={"content-length": "9"})

    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        max_read_size=8,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(SizeLimitError):
        client.read_text_file("/note.txt")


def test_read_file_bytes_rejects_negative_content_length():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/download-link/":
            return httpx.Response(200, json="https://seafile.example.com/file")
        return httpx.Response(200, content=b"abc", headers={"content-length": "-1"})

    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(SeafileVaultError, match="negative"):
        client.read_file_bytes("/note.txt")


def test_read_file_bytes_streams_and_aborts_without_content_length():
    class ChunkStream(httpx.SyncByteStream):
        def __init__(self):
            self.sent = 0

        def __iter__(self):
            for chunk in [b"abc", b"def", b"ghi"]:
                self.sent += 1
                yield chunk

    stream = ChunkStream()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/download-link/":
            return httpx.Response(200, json="https://seafile.example.com/file")
        return httpx.Response(200, stream=stream)

    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        max_read_size=5,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(SizeLimitError):
        client.read_file_bytes("/note.txt")
    assert stream.sent == 2


def test_create_directory_checks_parent_before_mkdir():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "GET":
            return httpx.Response(200, json=[])
        return httpx.Response(200, json={"success": True, "obj_name": "new"})

    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        permission_mode=PermissionMode.READ_WRITE,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert client.create_directory("/new") == {"success": True, "obj_name": "new"}
    assert requests[0].method == "GET"
    assert requests[0].url.params["path"] == "/"
    assert requests[1].method == "POST"
    assert requests[1].url.path == "/api/v2.1/via-repo-token/dir/"
    assert requests[1].url.params["path"] == "/new"
    assert json.loads(requests[1].content) == {"operation": "mkdir"}


def test_create_directory_rejects_existing_exact_name_file_or_dir():
    for entry in ({"name": "new", "type": "dir"}, {"name": "new", "type": "file"}):
        requests = []

        def handler(request: httpx.Request, entry=entry, requests=requests) -> httpx.Response:
            requests.append(request)
            return httpx.Response(200, json=[entry])

        client = SeafileVaultClient(
            "https://seafile.example.com",
            "super-secret-token",
            permission_mode=PermissionMode.READ_WRITE,
            http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        )
        with pytest.raises(SeafileVaultError, match="already exists"):
            client.create_directory("/new")
        assert len(requests) == 1


def test_create_directory_rejects_auto_rename_response_and_attempts_cleanup():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "GET":
            return httpx.Response(200, json={"dirent_list": []})
        if request.method == "DELETE":
            return httpx.Response(200, json="success")
        return httpx.Response(200, json={"obj_name": "Housing (1)"})

    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        permission_mode=PermissionMode.READ_WRITE,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(SeafileVaultError, match="different name"):
        client.create_directory("/Household/Housing")
    assert requests[-1].method == "DELETE"
    assert requests[-1].url.params["path"] == "/Household/Housing (1)"


@pytest.mark.parametrize("json_body", [{}, {"obj_name": None}, {"success": True}, []])
def test_create_directory_rejects_missing_or_invalid_response_name_without_cleanup(json_body):
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "GET":
            return httpx.Response(200, json=[])
        return httpx.Response(200, json=json_body)

    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        permission_mode=PermissionMode.READ_WRITE,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(SeafileVaultError, match="obj_name|object"):
        client.create_directory("/new")
    assert [request.method for request in requests] == ["GET", "POST"]


def test_create_directory_parents_walks_missing_levels_and_skips_existing_dirs():
    listings = {
        "/": [{"name": "a", "type": "dir"}],
        "/a": [],
        "/a/b": [],
    }
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "GET":
            return httpx.Response(200, json=listings.get(request.url.params["path"], []))
        return httpx.Response(200, json={"obj_name": request.url.params["path"].rpartition("/")[2]})

    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        permission_mode=PermissionMode.READ_WRITE,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert client.create_directory("/a/b/c", parents=True) == {"path": "/a/b/c", "created": ["/a/b", "/a/b/c"], "skipped": ["/a"]}
    assert [request.url.params["path"] for request in requests if request.method == "POST"] == ["/a/b", "/a/b/c"]


def test_create_directory_parents_rejects_file_collision_read_only_and_root(httpx_mock_transport):
    client, _ = httpx_mock_transport(json_body=[{"name": "a", "type": "file"}], permission_mode=PermissionMode.READ_WRITE)
    with pytest.raises(SeafileVaultError, match="not a directory"):
        client.create_directory("/a/b", parents=True)
    read_only, _ = httpx_mock_transport(json_body=[] , permission_mode=PermissionMode.READ_ONLY)
    with pytest.raises(PermissionModeError):
        read_only.create_directory("/a", parents=True)
    with pytest.raises(PathSecurityError):
        client.create_directory("/", parents=True)


def test_create_directory_parents_existing_path_creates_no_duplicates():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"dirent_list": [{"obj_name": "a", "obj_type": "dir"}]})

    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        permission_mode=PermissionMode.READ_WRITE,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert client.create_directory("/a", parents=True) == {"path": "/a", "created": [], "skipped": ["/a"]}
    assert all(request.method == "GET" for request in requests)


def test_upload_text_default_non_overwrite_same_origin(httpx_mock_transport):
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            assert request.url.params["path"] == "/folder"
            assert request.url.params["replace"] == "0"
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        body = request.read().decode("utf-8", errors="ignore")
        assert "parent_dir" in body and "/folder" in body
        assert "replace" in body and "0" in body
        return httpx.Response(200, json=[{"name": "file.txt"}])

    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        permission_mode=PermissionMode.READ_WRITE,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert client.write_text_file("/folder/file.txt", "hello", overwrite=False) == [{"name": "file.txt"}]
    assert len(requests) == 2


def test_upload_text_treats_malformed_success_response_as_success():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        return httpx.Response(200, content=b"{} invalid-json")

    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        permission_mode=PermissionMode.READ_WRITE,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    assert client.write_text_file("/folder/file.txt", "hello", overwrite=False) == {"response_text": "{} invalid-json"}
    assert len(requests) == 2


def test_upload_file_bytes_uses_upload_timeout():
    timeouts = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        timeouts.append(request.extensions["timeout"])
        return httpx.Response(200, json={"success": True})

    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        permission_mode=PermissionMode.READ_WRITE,
        upload_timeout=44,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert client.upload_file_bytes("/folder/file.txt", b"hello") == {"success": True}
    assert timeouts == [{"connect": 44, "read": 44, "write": 44, "pool": 44}]


def test_upload_base64_enforces_max_write_size(httpx_mock_transport):
    client, _ = httpx_mock_transport(json_body={})
    client.max_write_size = 3
    with pytest.raises(SizeLimitError):
        client.upload_file_base64("/x.bin", base64.b64encode(b"1234").decode(), overwrite=False)


def test_upload_file_path_default_non_overwrite(tmp_path):
    local = tmp_path / "local.txt"
    local.write_text("hello", encoding="utf-8")
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            assert request.url.params["path"] == "/folder"
            assert request.url.params["replace"] == "0"
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        body = request.read().decode("utf-8", errors="ignore")
        assert 'name="replace"' in body and "0" in body
        assert 'filename="remote.txt"' in body
        return httpx.Response(200, json=[{"name": "remote.txt"}])

    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        permission_mode=PermissionMode.READ_WRITE,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    result = client.upload_file_path(local, "/folder/remote.txt")
    assert result["overwrite"] is False
    assert result["remote_path"] == "/folder/remote.txt"
    assert result["remote_name"] == "remote.txt"
    assert result["size"] == 5
    assert "local_path" not in result
    assert "direct_ip" not in result
    assert result["upload_mode"] == "single"
    assert len(requests) == 2


def test_upload_file_path_auto_uses_chunked_above_threshold_exact_ranges(tmp_path):
    total = 101 * 1024 * 1024
    local = tmp_path / "large.bin"
    with open(local, "wb") as handle:
        handle.truncate(total)
    uploads = []
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == f"/api/v2.1/repos/{TEST_REPO_ID}/file-uploaded-bytes/":
            return httpx.Response(200, json={"uploadedBytes": 0})
        if request.url.path == "/api/v2.1/via-repo-token/file/":
            return httpx.Response(200, json={"name": "large.bin", "size": total})
        body = request.read()
        uploads.append((request, body))
        return httpx.Response(200, json=[{"name": "large.bin"}] if len(uploads) == 2 else {"success": True})

    client = _chunked_client(handler, chunk_size=64 * 1024 * 1024)
    result = client.upload_file_path(local, "/folder/large.bin")

    assert result["upload_mode"] == "chunked"
    assert result["chunk_size"] == 64 * 1024 * 1024
    assert result["chunks_sent"] == 2
    assert result["resumed_from"] == 0
    assert result["resume_supported"] is True
    assert [upload[0].headers["Content-Range"] for upload in uploads] == [
        f"bytes 0-{64 * 1024 * 1024 - 1}/{total}",
        f"bytes {64 * 1024 * 1024}-{total - 1}/{total}",
    ]
    assert all(int(upload[0].headers["Content-Length"]) == len(upload[1]) for upload in uploads)
    assert all("super-secret-token" not in json.dumps(result) for _ in [None])


def test_upload_file_path_forced_single_above_threshold(tmp_path):
    local = tmp_path / "large.bin"
    local.write_bytes(b"12345")
    uploads = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        uploads.append(request)
        request.read()
        return httpx.Response(200, json={"success": True})

    client = _chunked_client(handler, chunk_size=4)
    result = client.upload_file_path(local, "/folder/large.bin", upload_mode="single")
    assert result["upload_mode"] == "single"
    assert len(uploads) == 1


def test_upload_file_path_malformed_success_text_redacts_tokens_from_result_and_cli_serialization(tmp_path):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abc")
    upload_link = "https://seafile.example.com/upload-api/secret-upload-token?sig=secret"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json=upload_link)
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == f"/api/v2.1/repos/{TEST_REPO_ID}/file-uploaded-bytes/":
            return httpx.Response(200, json={"uploadedBytes": 0})
        if request.url.path == "/api/v2.1/via-repo-token/file/":
            return httpx.Response(200, json={"name": "data.bin", "size": 3})
        request.read()
        return httpx.Response(200, text=f"stored with super-secret-token at {upload_link}")

    result = _chunked_client(handler, chunk_size=10).upload_file_path(local, "/folder/data.bin", upload_mode="chunked")
    serialized = json.dumps({"ok": True, "data": result}, sort_keys=True, separators=(",", ":"))
    assert "super-secret-token" not in result["final_result"]["response"]["response_text"]
    assert upload_link not in result["final_result"]["response"]["response_text"]
    assert "secret-upload-token" not in serialized
    assert upload_link not in serialized
    assert os.fspath(local) not in serialized


def test_upload_file_path_nested_success_json_redacts_tokens_from_result_and_cli_serialization(tmp_path):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abc")
    upload_link = "https://seafile.example.com/upload-api/secret-upload-token?sig=secret"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json=upload_link)
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == f"/api/v2.1/repos/{TEST_REPO_ID}/file-uploaded-bytes/":
            return httpx.Response(200, json={"uploadedBytes": 0})
        if request.url.path == "/api/v2.1/via-repo-token/file/":
            return httpx.Response(200, json={"name": "data.bin", "size": 3})
        request.read()
        return httpx.Response(
            200,
            json={
                "name": "data.bin",
                "details": [
                    {"message": f"token super-secret-token link {upload_link}"},
                    f"plain string {upload_link} super-secret-token",
                ],
                "download_url": upload_link,
                "repoToken": "super-secret-token",
                "nested": {"authorization": f"Bearer super-secret-token via {upload_link}"},
            },
        )

    result = _chunked_client(handler, chunk_size=10).upload_file_path(local, "/folder/data.bin", upload_mode="chunked")
    serialized = json.dumps({"ok": True, "data": result}, sort_keys=True, separators=(",", ":"))
    assert result["final_result"]["response"]["details"][0]["message"] == "token [REDACTED] link [REDACTED]"
    assert result["final_result"]["response"]["details"][1] == "plain string [REDACTED] [REDACTED]"
    assert "super-secret-token" not in serialized
    assert "secret-upload-token" not in serialized
    assert upload_link not in serialized
    assert os.fspath(local) not in serialized


def test_upload_file_path_forced_chunked_small_and_no_resume(tmp_path):
    local = tmp_path / "small.bin"
    local.write_bytes(b"abc")
    paths = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == "/api/v2.1/via-repo-token/file/":
            return httpx.Response(200, json={"name": "small.bin", "size": 3})
        request.read()
        return httpx.Response(200, json={"success": True})

    client = _chunked_client(handler, chunk_size=4)
    result = client.upload_file_path(local, "/folder/small.bin", upload_mode="chunked", resume=False)
    assert result["upload_mode"] == "chunked"
    assert result["resumed_from"] == 0
    assert result["resume_supported"] is False
    assert "/api/v2.1/repos/" not in "\n".join(paths)


def test_upload_file_path_chunked_unsupported_resume_falls_back_to_zero(tmp_path):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abcdef")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == f"/api/v2.1/repos/{TEST_REPO_ID}/file-uploaded-bytes/":
            return httpx.Response(404, json={"detail": "not found"})
        if request.url.path == "/api/v2.1/via-repo-token/file/":
            return httpx.Response(200, json={"name": "data.bin", "size": 6})
        request.read()
        return httpx.Response(200, json={"success": True})

    result = _chunked_client(handler, chunk_size=10).upload_file_path(local, "/folder/data.bin", upload_mode="chunked")
    assert result["resumed_from"] == 0
    assert result["resume_supported"] is False


def test_upload_file_path_chunked_resume_offset_seeks_descriptor(tmp_path):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abcdef")
    uploaded_body = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == f"/api/v2.1/repos/{TEST_REPO_ID}/file-uploaded-bytes/":
            return httpx.Response(200, json={"uploadedBytes": 3})
        if request.url.path == "/api/v2.1/via-repo-token/file/":
            return httpx.Response(200, json={"name": "data.bin", "size": 6})
        uploaded_body["range"] = request.headers["Content-Range"]
        uploaded_body["body"] = request.read()
        return httpx.Response(200, json={"success": True})

    result = _chunked_client(handler, chunk_size=10).upload_file_path(local, "/folder/data.bin", upload_mode="chunked")
    assert result["resumed_from"] == 3
    assert uploaded_body["range"] == "bytes 3-5/6"
    assert b"def" in uploaded_body["body"]
    assert b"abc" not in uploaded_body["body"]


def test_upload_file_path_chunked_resume_offset_out_of_range(tmp_path):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abc")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        return httpx.Response(200, json={"uploadedBytes": 4})

    with pytest.raises(Exception, match="outside local file size"):
        _chunked_client(handler).upload_file_path(local, "/folder/data.bin", upload_mode="chunked")


def test_upload_file_path_chunked_intermediate_response_must_be_success(tmp_path):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abcdef")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == f"/api/v2.1/repos/{TEST_REPO_ID}/file-uploaded-bytes/":
            return httpx.Response(200, json={"uploadedBytes": 0})
        request.read()
        return httpx.Response(200, json={"success": False})

    with pytest.raises(Exception, match="intermediate chunk response"):
        _chunked_client(handler, chunk_size=3).upload_file_path(local, "/folder/data.bin", upload_mode="chunked")


def test_upload_file_path_chunked_retries_transient_and_reconciles_offset(tmp_path, monkeypatch):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abcdef")
    upload_attempts = 0
    resume_values = iter([0, 3])
    monkeypatch.setattr("seafile_vault_cli.client.time.sleep", lambda _seconds: None)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal upload_attempts
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == f"/api/v2.1/repos/{TEST_REPO_ID}/file-uploaded-bytes/":
            return httpx.Response(200, json={"uploadedBytes": next(resume_values)})
        if request.url.path == "/api/v2.1/via-repo-token/file/":
            return httpx.Response(200, json={"name": "data.bin", "size": 6})
        upload_attempts += 1
        request.read()
        if upload_attempts == 1:
            return httpx.Response(500, json={"error": "temporary"})
        return httpx.Response(200, json={"success": True})

    result = _chunked_client(handler, chunk_size=3).upload_file_path(local, "/folder/data.bin", upload_mode="chunked")
    assert upload_attempts == 2
    assert result["chunks_sent"] == 1


def test_upload_file_path_chunked_does_not_retry_4xx(tmp_path, monkeypatch):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abc")
    upload_attempts = 0
    sleeps = []
    monkeypatch.setattr("seafile_vault_cli.client.time.sleep", lambda seconds: sleeps.append(seconds))

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal upload_attempts
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == f"/api/v2.1/repos/{TEST_REPO_ID}/file-uploaded-bytes/":
            return httpx.Response(200, json={"uploadedBytes": 0})
        upload_attempts += 1
        return httpx.Response(409, json={"error": "exists"})

    with pytest.raises(Exception, match="409"):
        _chunked_client(handler, chunk_size=3).upload_file_path(local, "/folder/data.bin", upload_mode="chunked")
    assert upload_attempts == 1
    assert sleeps == []


def test_upload_file_path_chunked_detects_retry_offset_regression(tmp_path, monkeypatch):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abcdef")
    resume_values = iter([3, 2])
    monkeypatch.setattr("seafile_vault_cli.client.time.sleep", lambda _seconds: None)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == f"/api/v2.1/repos/{TEST_REPO_ID}/file-uploaded-bytes/":
            return httpx.Response(200, json={"uploadedBytes": next(resume_values)})
        if request.url.path == "/api/v2.1/via-repo-token/file/":
            return httpx.Response(404, json={"detail": "missing"})
        return httpx.Response(500, json={"error": "temporary"})

    with pytest.raises(Exception, match="regression"):
        _chunked_client(handler, chunk_size=3).upload_file_path(local, "/folder/data.bin", upload_mode="chunked")


def test_upload_file_path_chunked_redacts_upload_link_from_error(tmp_path):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abc")
    upload_link = "https://seafile.example.com/upload-api/secret-upload-token"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json=upload_link)
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == f"/api/v2.1/repos/{TEST_REPO_ID}/file-uploaded-bytes/":
            return httpx.Response(200, json={"uploadedBytes": 0})
        return httpx.Response(500, text=f"failed at {upload_link}")

    with pytest.raises(Exception) as exc:
        _chunked_client(handler, chunk_size=3).upload_file_path(local, "/folder/data.bin", upload_mode="chunked")
    assert "secret-upload-token" not in str(exc.value)


def test_upload_file_path_chunked_unicode_special_filename_header(tmp_path):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abc")
    upload_headers = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == f"/api/v2.1/repos/{TEST_REPO_ID}/file-uploaded-bytes/":
            return httpx.Response(200, json={"uploadedBytes": 0})
        if request.url.path == "/api/v2.1/via-repo-token/file/":
            return httpx.Response(200, json={"name": '雪 quote".txt', "size": 3})
        upload_headers.update(request.headers)
        body = request.read()
        assert 'filename="雪 quote\\".txt"'.encode() in body
        return httpx.Response(200, json={"success": True})

    _chunked_client(handler, chunk_size=10).upload_file_path(local, '/folder/雪 quote".txt', upload_mode="chunked")
    assert upload_headers["content-disposition"] == 'attachment; filename="%E9%9B%AA%20quote%22.txt"'
    assert unquote("%E9%9B%AA%20quote%22.txt") == '雪 quote".txt'


def test_upload_file_path_chunked_filename_header_escapes_uri_literals_once(tmp_path):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abc")
    upload_headers = {}
    remote_name = 'literal%2F%0A"back\\semi;.txt'

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == f"/api/v2.1/repos/{TEST_REPO_ID}/file-uploaded-bytes/":
            return httpx.Response(200, json={"uploadedBytes": 0})
        if request.url.path == "/api/v2.1/via-repo-token/file/":
            return httpx.Response(200, json={"name": remote_name, "size": 3})
        upload_headers.update(request.headers)
        request.read()
        return httpx.Response(200, json={"success": True})

    _chunked_client(handler, chunk_size=10).upload_file_path(local, f"/folder/{remote_name}", upload_mode="chunked")
    header = upload_headers["content-disposition"]
    assert header.startswith('attachment; filename="')
    assert header.endswith('"')
    encoded = header.removeprefix('attachment; filename="').removesuffix('"')
    assert unquote(encoded) == remote_name
    assert "%252F" in encoded
    assert "%250A" in encoded
    assert "%22" in encoded
    assert "%5C" in encoded
    assert "%3B" in encoded
    assert "filename*=" not in header


def test_upload_file_path_forced_chunked_empty_routes_single(tmp_path):
    local = tmp_path / "empty.bin"
    local.write_bytes(b"")
    uploads = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        uploads.append(request)
        request.read()
        return httpx.Response(200, json={"success": True})

    result = _chunked_client(handler, chunk_size=1).upload_file_path(local, "/folder/empty.bin", upload_mode="chunked")
    assert result["upload_mode"] == "single"
    assert len(uploads) == 1


def test_upload_file_path_chunked_resume_complete_verifies_remote_size(tmp_path):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abcdef")
    uploads = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == f"/api/v2.1/repos/{TEST_REPO_ID}/file-uploaded-bytes/":
            return httpx.Response(200, json={"uploadedBytes": 6})
        if request.url.path == "/api/v2.1/via-repo-token/file/":
            return httpx.Response(200, json={"name": "data.bin", "size": 6})
        uploads.append(request)
        return httpx.Response(500)

    result = _chunked_client(handler, chunk_size=3).upload_file_path(local, "/folder/data.bin", upload_mode="chunked")
    assert result["chunks_sent"] == 0
    assert uploads == []


def test_upload_file_path_chunked_resume_complete_missing_resends_final_chunk(tmp_path):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abcdef")
    uploads = []
    file_checks = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal file_checks
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == f"/api/v2.1/repos/{TEST_REPO_ID}/file-uploaded-bytes/":
            return httpx.Response(200, json={"uploadedBytes": 6})
        if request.url.path == "/api/v2.1/via-repo-token/file/":
            file_checks += 1
            if file_checks == 1:
                return httpx.Response(404, json={"detail": "missing"})
            return httpx.Response(200, json={"name": "data.bin", "size": 6})
        uploads.append((request.headers["Content-Range"], request.read()))
        return httpx.Response(200, json={"success": True})

    result = _chunked_client(handler, chunk_size=3).upload_file_path(local, "/folder/data.bin", upload_mode="chunked")
    assert result["chunks_sent"] == 1
    assert uploads[0][0] == "bytes 3-5/6"
    assert b"def" in uploads[0][1]
    assert b"abc" not in uploads[0][1]


def test_upload_file_path_chunked_resume_complete_wrong_size_fails_closed(tmp_path):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abcdef")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == f"/api/v2.1/repos/{TEST_REPO_ID}/file-uploaded-bytes/":
            return httpx.Response(200, json={"uploadedBytes": 6})
        if request.url.path == "/api/v2.1/via-repo-token/file/":
            return httpx.Response(200, json={"name": "data.bin", "size": 5})
        return httpx.Response(500)

    with pytest.raises(Exception, match="size did not match"):
        _chunked_client(handler, chunk_size=3).upload_file_path(local, "/folder/data.bin", upload_mode="chunked")


def test_upload_file_path_chunked_lost_final_response_committed_no_duplicate(tmp_path, monkeypatch):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abcdef")
    upload_attempts = 0
    monkeypatch.setattr("seafile_vault_cli.client.time.sleep", lambda _seconds: None)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal upload_attempts
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == f"/api/v2.1/repos/{TEST_REPO_ID}/file-uploaded-bytes/":
            return httpx.Response(200, json={"uploadedBytes": 3})
        if request.url.path == "/api/v2.1/via-repo-token/file/":
            return httpx.Response(200, json={"name": "data.bin", "size": 6})
        upload_attempts += 1
        request.read()
        return httpx.Response(502, json={"error": "lost response"})

    result = _chunked_client(handler, chunk_size=3).upload_file_path(local, "/folder/data.bin", upload_mode="chunked")
    assert upload_attempts == 1
    assert result["chunks_sent"] == 1


def test_upload_file_path_chunked_final_attempt_lost_response_but_final_file_committed_succeeds(tmp_path, monkeypatch):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abc")
    upload_attempts = 0
    file_checks = 0
    monkeypatch.setattr("seafile_vault_cli.client.time.sleep", lambda _seconds: None)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal file_checks, upload_attempts
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == f"/api/v2.1/repos/{TEST_REPO_ID}/file-uploaded-bytes/":
            return httpx.Response(200, json={"uploadedBytes": 0})
        if request.url.path == "/api/v2.1/via-repo-token/file/":
            file_checks += 1
            if file_checks < 3:
                return httpx.Response(404, json={"detail": "missing"})
            return httpx.Response(200, json={"name": "data.bin", "size": 3})
        upload_attempts += 1
        request.read()
        return httpx.Response(502, json={"error": "lost response"})

    result = _chunked_client(handler, chunk_size=3).upload_file_path(local, "/folder/data.bin", upload_mode="chunked")
    assert upload_attempts == 3
    assert file_checks == 3
    assert result["chunks_sent"] == 1


def test_upload_file_path_chunked_final_intermediate_attempt_offset_advanced_is_honored(tmp_path, monkeypatch):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abcdef")
    upload_attempts = []
    resume_values = iter([0, 0, 0, 3])
    monkeypatch.setattr("seafile_vault_cli.client.time.sleep", lambda _seconds: None)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == f"/api/v2.1/repos/{TEST_REPO_ID}/file-uploaded-bytes/":
            return httpx.Response(200, json={"uploadedBytes": next(resume_values)})
        if request.url.path == "/api/v2.1/via-repo-token/file/":
            return httpx.Response(200, json={"name": "data.bin", "size": 6})
        upload_attempts.append(request.headers["Content-Range"])
        request.read()
        if len(upload_attempts) <= 3:
            return httpx.Response(502, json={"error": "lost response"})
        return httpx.Response(200, json=[{"name": "data.bin", "size": 6}])

    result = _chunked_client(handler, chunk_size=3).upload_file_path(local, "/folder/data.bin", upload_mode="chunked")
    assert upload_attempts == ["bytes 0-2/6", "bytes 0-2/6", "bytes 0-2/6", "bytes 3-5/6"]
    assert result["chunks_sent"] == 1


def test_upload_file_path_chunked_full_temp_not_finalized_retries_final_chunk(tmp_path, monkeypatch):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abcdef")
    upload_attempts = 0
    file_checks = 0
    monkeypatch.setattr("seafile_vault_cli.client.time.sleep", lambda _seconds: None)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal file_checks, upload_attempts
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == f"/api/v2.1/repos/{TEST_REPO_ID}/file-uploaded-bytes/":
            return httpx.Response(200, json={"uploadedBytes": 6 if upload_attempts else 3})
        if request.url.path == "/api/v2.1/via-repo-token/file/":
            file_checks += 1
            if file_checks == 1:
                return httpx.Response(404, json={"detail": "not finalized"})
            return httpx.Response(200, json={"name": "data.bin", "size": 6})
        upload_attempts += 1
        request.read()
        if upload_attempts == 1:
            return httpx.Response(502, json={"error": "lost response"})
        return httpx.Response(200, json={"success": True})

    result = _chunked_client(handler, chunk_size=3).upload_file_path(local, "/folder/data.bin", upload_mode="chunked")
    assert upload_attempts == 2
    assert result["chunks_sent"] == 1


def test_upload_file_path_chunked_final_verification_missing_fails(tmp_path, monkeypatch):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abc")
    monkeypatch.setattr("seafile_vault_cli.client.time.sleep", lambda _seconds: None)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == f"/api/v2.1/repos/{TEST_REPO_ID}/file-uploaded-bytes/":
            return httpx.Response(200, json={"uploadedBytes": 0})
        if request.url.path == "/api/v2.1/via-repo-token/file/":
            return httpx.Response(404, json={"detail": "missing"})
        request.read()
        return httpx.Response(200, json={"success": True})

    with pytest.raises(Exception, match="not visible"):
        _chunked_client(handler, chunk_size=3).upload_file_path(local, "/folder/data.bin", upload_mode="chunked")


def test_upload_file_path_chunked_final_verification_mismatch_fails(tmp_path):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abc")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == f"/api/v2.1/repos/{TEST_REPO_ID}/file-uploaded-bytes/":
            return httpx.Response(200, json={"uploadedBytes": 0})
        if request.url.path == "/api/v2.1/via-repo-token/file/":
            return httpx.Response(200, json={"name": "data.bin", "size": 2})
        request.read()
        return httpx.Response(200, json={"success": True})

    with pytest.raises(Exception, match="size did not match"):
        _chunked_client(handler, chunk_size=3).upload_file_path(local, "/folder/data.bin", upload_mode="chunked")


def test_upload_file_path_chunked_rejects_multipart_body_at_runtime_cap(tmp_path, monkeypatch):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abc")
    monkeypatch.setattr(client_module, "MAX_MULTIPART_REQUEST_BODY_SIZE", 10)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == f"/api/v2.1/repos/{TEST_REPO_ID}/file-uploaded-bytes/":
            return httpx.Response(200, json={"uploadedBytes": 0})
        return httpx.Response(500)

    client = _chunked_client(handler, chunk_size=3, max_write_size=200_000_000)
    with pytest.raises(ConfigError, match="multipart request body"):
        client.upload_file_path(local, "/folder/data.bin", upload_mode="chunked")


def test_upload_file_path_chunked_rejects_malformed_repo_id(tmp_path):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abc")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": "../bad"})
        return httpx.Response(500)

    with pytest.raises(Exception, match="repo_id"):
        _chunked_client(handler, chunk_size=3).upload_file_path(local, "/folder/data.bin", upload_mode="chunked")


@pytest.mark.parametrize("status_code", [401, 403, 404, 405, 501])
def test_upload_file_path_chunked_resume_unsupported_statuses_fall_back(tmp_path, status_code):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abc")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == f"/api/v2.1/repos/{TEST_REPO_ID}/file-uploaded-bytes/":
            return httpx.Response(status_code, json={"detail": "unsupported"})
        if request.url.path == "/api/v2.1/via-repo-token/file/":
            return httpx.Response(200, json={"name": "data.bin", "size": 3})
        request.read()
        return httpx.Response(200, json={"success": True})

    result = _chunked_client(handler, chunk_size=3).upload_file_path(local, "/folder/data.bin", upload_mode="chunked")
    assert result["resume_supported"] is False


def test_upload_file_path_chunked_resume_invalid_json_raises(tmp_path):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abc")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        if request.url.path == "/api/v2.1/via-repo-token/repo-info/":
            return httpx.Response(200, json={"repo_id": TEST_REPO_ID})
        if request.url.path == f"/api/v2.1/repos/{TEST_REPO_ID}/file-uploaded-bytes/":
            return httpx.Response(200, text="not json")
        return httpx.Response(500)

    with pytest.raises(Exception, match="valid JSON"):
        _chunked_client(handler, chunk_size=3).upload_file_path(local, "/folder/data.bin", upload_mode="chunked")


def test_upload_file_path_chunked_direct_combination_rejected_before_network(tmp_path):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abc")
    requests = []
    client = _chunked_client(lambda request: requests.append(request) or httpx.Response(500))
    with pytest.raises(ConfigError):
        client.upload_file_path(local, "/folder/data.bin", upload_mode="chunked", direct_ip="203.0.113.10")
    assert requests == []


def test_empty_file_auto_uses_single_request(tmp_path):
    local = tmp_path / "empty.bin"
    local.write_bytes(b"")
    uploads = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        uploads.append(request)
        request.read()
        return httpx.Response(200, json={"success": True})

    result = _chunked_client(handler, chunk_size=1).upload_file_path(local, "/folder/empty.bin")
    assert result["upload_mode"] == "single"
    assert len(uploads) == 1


def test_bounded_file_reader_never_reads_past_limit(tmp_path, monkeypatch):
    local = tmp_path / "data.bin"
    local.write_bytes(b"abcdef")
    fd = os.open(local, os.O_RDONLY)
    read_sizes = []
    original_read = os.read

    def fake_read(read_fd, size):
        read_sizes.append(size)
        return original_read(read_fd, size)

    monkeypatch.setattr("seafile_vault_cli.client.os.read", fake_read)
    try:
        reader = BoundedFileReader(fd, 3, block_size=2)
        assert reader.read(100) == b"ab"
        assert reader.read(100) == b"c"
        assert reader.read(100) == b""
        assert original_read(fd, 10) == b"def"
    finally:
        os.close(fd)
    assert read_sizes == [2, 1]


def test_upload_file_path_overwrite_sets_replace(tmp_path):
    local = tmp_path / "local.txt"
    local.write_text("hello", encoding="utf-8")
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            assert request.url.params["replace"] == "1"
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        body = request.read().decode("utf-8", errors="ignore")
        assert 'name="replace"' in body and "1" in body
        return httpx.Response(200, json={"success": True})

    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        permission_mode=PermissionMode.READ_WRITE,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert client.upload_file_path(local, "/folder/remote.txt", overwrite=True)["overwrite"] is True
    assert len(requests) == 2


def test_upload_file_path_size_preflight_happens_before_link_request(tmp_path):
    local = tmp_path / "large.bin"
    local.write_bytes(b"1234")
    requests = []
    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        permission_mode=PermissionMode.READ_WRITE,
        max_write_size=3,
        http_client=httpx.Client(transport=httpx.MockTransport(lambda request: requests.append(request) or httpx.Response(500))),
    )
    with pytest.raises(SizeLimitError):
        client.upload_file_path(local, "/folder/large.bin")
    assert requests == []


def test_upload_file_path_requires_regular_file(tmp_path):
    client = SeafileVaultClient("https://seafile.example.com", "super-secret-token", permission_mode=PermissionMode.READ_WRITE)
    with pytest.raises(LocalFileError):
        client.upload_file_path(tmp_path, "/folder/dir")
    with pytest.raises(LocalFileError):
        client.upload_file_path(tmp_path / "missing.txt", "/folder/missing.txt")


def test_upload_file_path_opens_once_and_reuses_descriptor(tmp_path, monkeypatch):
    local = tmp_path / "stream.bin"
    local.write_bytes(b"streamed")
    opened = {"count": 0}
    original_os_open = os.open

    def fake_open(path, flags, mode=0o777, *, dir_fd=None):
        if os.fspath(path) == os.fspath(local):
            opened["count"] += 1
            if hasattr(os, "O_NOFOLLOW"):
                assert flags & os.O_NOFOLLOW
        return original_os_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr("seafile_vault_cli.client.os.open", fake_open)
    monkeypatch.setattr(type(local), "open", lambda *args, **kwargs: pytest.fail("Path.open must not be used"))

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2.1/via-repo-token/upload-link/":
            return httpx.Response(200, json="https://seafile.example.com/upload-api/token")
        request.read()
        return httpx.Response(200, json={"success": True})

    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        permission_mode=PermissionMode.READ_WRITE,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    client.upload_file_path(local, "/folder/stream.bin")
    assert opened["count"] == 1


def test_upload_file_path_rejects_final_symlink(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("hello", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    client = SeafileVaultClient("https://seafile.example.com", "super-secret-token", permission_mode=PermissionMode.READ_WRITE)
    with pytest.raises(LocalFileError):
        client.upload_file_path(link, "/folder/link.txt")


def test_upload_file_path_direct_ip_validation(tmp_path):
    local = tmp_path / "local.txt"
    local.write_text("hello", encoding="utf-8")
    client = SeafileVaultClient("https://seafile.example.com", "super-secret-token", permission_mode=PermissionMode.READ_WRITE)
    with pytest.raises(ConfigError):
        client.upload_file_path(local, "/folder/local.txt", direct_ip="not-an-ip")


def test_upload_file_path_direct_ip_uses_curl_config_without_secret_argv(tmp_path, monkeypatch):
    local = tmp_path / "local.txt"
    local.write_text("hello", encoding="utf-8")
    upload_link = "https://seafile.example.com/upload-api/secret-upload-token?sig=secret"
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v2.1/via-repo-token/upload-link/"
        return httpx.Response(200, json=upload_link)

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["input"] = kwargs["input"]
        captured["pass_fds"] = kwargs["pass_fds"]
        captured["timeout"] = kwargs["timeout"]
        return subprocess.CompletedProcess(argv, 0, stdout='[{"name":"local.txt"}]\n200', stderr="")

    monkeypatch.setattr("seafile_vault_cli.client.subprocess.run", fake_run)
    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        permission_mode=PermissionMode.READ_WRITE,
        upload_timeout=99,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    result = client.upload_file_path(local, "/folder/remote.txt", direct_ip="203.0.113.10")
    assert result["direct_origin"] is True
    assert upload_link not in captured["argv"]
    assert "super-secret-token" not in " ".join(captured["argv"])
    assert 'resolve = "seafile.example.com:443:203.0.113.10"' in captured["input"]
    assert f'url = "{upload_link}"' in captured["input"]
    assert "max-time = \"99\"" in captured["input"]
    assert "connect-timeout = \"30.0\"" in captured["input"]
    assert "file=@/proc/self/fd/" in captured["input"]
    assert 'filename=\\"remote.txt\\"' in captured["input"]
    assert len(captured["pass_fds"]) == 1
    assert captured["timeout"] == 104


def test_upload_file_path_direct_quotes_curl_filename_modifiers(tmp_path, monkeypatch):
    local = tmp_path / "local.txt"
    local.write_text("hello", encoding="utf-8")
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json="https://seafile.example.com/upload-api/token")

    def fake_run(argv, **kwargs):
        captured["input"] = kwargs["input"]
        return subprocess.CompletedProcess(argv, 0, stdout='[{"name":"ok"}]\n200', stderr="")

    monkeypatch.setattr("seafile_vault_cli.client.subprocess.run", fake_run)
    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        permission_mode=PermissionMode.READ_WRITE,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    client.upload_file_path(local, '/folder/semi;comma,quote"slash\\.txt', direct_ip="203.0.113.10")
    assert 'filename=\\"semi;comma,quote\\\\\\"slash\\\\\\\\.txt\\"' in captured["input"]
    assert ";type=" not in captured["input"]


def test_upload_file_path_direct_ipv6_resolve_entry(tmp_path, monkeypatch):
    local = tmp_path / "local.txt"
    local.write_text("hello", encoding="utf-8")
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json="https://seafile.example.com/upload-api/token")

    def fake_run(argv, **kwargs):
        captured["input"] = kwargs["input"]
        return subprocess.CompletedProcess(argv, 0, stdout='[{"name":"ok"}]\n200', stderr="")

    monkeypatch.setattr("seafile_vault_cli.client.subprocess.run", fake_run)
    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        permission_mode=PermissionMode.READ_WRITE,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    client.upload_file_path(local, "/folder/remote.txt", direct_ip="2001:db8::1")
    assert 'resolve = "seafile.example.com:443:[2001:db8::1]"' in captured["input"]


def test_upload_file_path_direct_error_redacts_token_url(tmp_path, monkeypatch):
    local = tmp_path / "local.txt"
    local.write_text("hello", encoding="utf-8")
    upload_link = "https://seafile.example.com/upload-api/secret-upload-token"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=upload_link)

    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 22, stdout=f"failed {upload_link}\n500", stderr=f"curl saw {upload_link}")

    monkeypatch.setattr("seafile_vault_cli.client.subprocess.run", fake_run)
    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        permission_mode=PermissionMode.READ_WRITE,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(Exception) as exc:
        client.upload_file_path(local, "/folder/remote.txt", direct_ip="203.0.113.10")
    assert upload_link not in str(exc.value)
    assert "secret-upload-token" not in str(exc.value)


def test_upload_link_must_match_configured_origin(tmp_path):
    local = tmp_path / "local.txt"
    local.write_text("hello", encoding="utf-8")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json="https://evil.example.net/upload-api/token")

    client = SeafileVaultClient(
        "https://seafile.example.com",
        "super-secret-token",
        permission_mode=PermissionMode.READ_WRITE,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(LinkSecurityError):
        client.upload_file_path(local, "/folder/remote.txt")


def test_rename_move_delete_preserve_endpoint_behavior(httpx_mock_transport):
    client, requests = httpx_mock_transport(json_body="success")
    assert client.rename_path("/folder/old.txt", "new.txt") == "success"
    assert requests[-1].method == "POST"
    assert requests[-1].url.path == "/api/v2.1/via-repo-token/file/"
    assert json.loads(requests[-1].content) == {"operation": "rename", "newname": "new.txt"}
    assert client.rename_path("/folder/old", "new", is_directory=True) == "success"
    assert requests[-1].url.path == "/api/v2.1/via-repo-token/dir/"
    assert client.move_path("/folder/old.txt", "/archive") == "success"
    assert requests[-1].url.path == "/api/v2.1/via-repo-token/file/"
    assert json.loads(requests[-1].content) == {"operation": "move", "dst_dir": "/archive"}
    assert client.move_path("/folder/old", "/archive", is_directory=True) == "success"
    assert requests[-1].url.path == "/api/v2.1/via-repo-token/move-dir/"
    assert json.loads(requests[-1].content) == {
        "src_parent_dir": "/folder",
        "src_dirent_name": "old",
        "dst_parent_dir": "/archive",
    }
    assert client.delete_path("/folder/old.txt") == "success"
    assert requests[-1].method == "DELETE"
    assert requests[-1].url.path == "/api/v2.1/via-repo-token/file/"
    assert client.delete_path("/folder", recursive=True) == "success"
    assert requests[-1].url.path == "/api/v2.1/via-repo-token/dir/"


@pytest.mark.parametrize("operation", ["rename", "move", "delete"])
def test_mutating_path_operations_reject_root(operation, httpx_mock_transport):
    client, _ = httpx_mock_transport(json_body="success")
    with pytest.raises(PathSecurityError):
        if operation == "rename":
            client.rename_path("/", "new")
        elif operation == "move":
            client.move_path("/", "/archive")
        else:
            client.delete_path("/")


@pytest.mark.parametrize("bad_name", ["", ".", "..", "nested/name", "a//b", "bad\x00name", "bad\x1fname", "bad\x7fname"])
def test_rename_path_rejects_unsafe_new_names(bad_name, httpx_mock_transport):
    client, _ = httpx_mock_transport(json_body="success")
    with pytest.raises(PathSecurityError):
        client.rename_path("/folder/old.txt", bad_name)
