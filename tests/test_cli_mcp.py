import inspect
import json
import os
import subprocess
import sys
import types
from datetime import UTC, datetime

import pytest


def test_cli_help_and_version_do_not_require_token():
    help_result = subprocess.run(
        [sys.executable, "-m", "seafile_vault_cli.cli", "--help"],
        cwd=os.getcwd(),
        text=True,
        capture_output=True,
        check=False,
    )
    assert help_result.returncode == 0
    assert "seafile-vault" in help_result.stdout
    assert "repo-info" in help_result.stdout
    assert "upload" in help_result.stdout
    assert "download" in help_result.stdout
    assert "stat" in help_result.stdout
    version_result = subprocess.run(
        [sys.executable, "-m", "seafile_vault_cli.cli", "--version"],
        cwd=os.getcwd(),
        text=True,
        capture_output=True,
        check=False,
    )
    assert version_result.returncode == 0
    assert "Seafile Vault CLI" in version_result.stdout


def test_cli_usage_errors_are_deterministic_json():
    result = subprocess.run(
        [sys.executable, "-m", "seafile_vault_cli.cli"],
        cwd=os.getcwd(),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert result.stdout == ""
    assert json.loads(result.stderr) == {
        "error": {"code": "usage", "message": "the following arguments are required: command"},
        "ok": False,
    }


def test_cli_rename_and_move_support_dir_selector():
    from seafile_vault_cli.cli import build_parser

    rename_args = build_parser().parse_args(["rename", "/old", "new", "--dir"])
    assert rename_args.dir is True
    move_args = build_parser().parse_args(["move", "/old", "/archive", "--dir"])
    assert move_args.dir is True


def test_cli_copy_lock_and_locks_parsers():
    from seafile_vault_cli.cli import build_parser

    copy_args = build_parser().parse_args(["copy", "/source.txt", "/archive"])
    assert copy_args.command == "copy"
    assert copy_args.source == "/source.txt"
    assert copy_args.destination_directory == "/archive"
    lock_args = build_parser().parse_args(["lock", "/source.txt", "--expires", "120"])
    assert lock_args.command == "lock"
    assert lock_args.expires == 120
    locks_args = build_parser().parse_args(["locks", "--prune"])
    assert locks_args.command == "locks"
    assert locks_args.prune is True


@pytest.mark.parametrize("value", ["0", "-1", "86401"])
def test_cli_lock_parser_rejects_invalid_expires(capsys, value):
    from seafile_vault_cli.cli import build_parser

    with pytest.raises(SystemExit) as excinfo:
        build_parser().parse_args(["lock", "/source.txt", "--expires", value])
    assert excinfo.value.code == 2
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "usage"


def test_cli_list_parser_accepts_recursive_type_and_compact():
    from seafile_vault_cli.cli import build_parser

    args = build_parser().parse_args(["list", "/docs", "--recursive", "--type", "file", "--compact"])
    assert args.command == "list"
    assert args.path == "/docs"
    assert args.recursive is True
    assert args.type == "file"
    assert args.compact is True


def test_cli_search_parser_accepts_safe_glob_options():
    from seafile_vault_cli.cli import build_parser

    args = build_parser().parse_args(["search", "/docs", "--name", "*.md", "--type", "file", "--max-results", "5", "--case-sensitive"])
    assert args.command == "search"
    assert args.path == "/docs"
    assert args.name == "*.md"
    assert args.type == "file"
    assert args.max_results == 5
    assert args.case_sensitive is True


def test_cli_download_stat_and_mkdir_parsers():
    from seafile_vault_cli.cli import build_parser

    download = build_parser().parse_args(["download", "/remote.txt", "local.txt", "--overwrite"])
    assert download.command == "download"
    assert download.remote_path == "/remote.txt"
    assert download.local_file == "local.txt"
    assert download.overwrite is True
    stat_args = build_parser().parse_args(["stat", "/remote.txt"])
    assert stat_args.command == "stat"
    assert stat_args.path == "/remote.txt"
    mkdir = build_parser().parse_args(["mkdir", "/a/b", "--parents"])
    assert mkdir.parents is True


def test_cli_upload_parser_defaults_to_no_overwrite():
    from seafile_vault_cli.cli import build_parser

    args = build_parser().parse_args(["upload", "local.txt", "/folder/remote.txt"])
    assert args.command == "upload"
    assert args.local_file == "local.txt"
    assert args.remote_path == "/folder/remote.txt"
    assert args.overwrite is False
    assert args.direct_ip is None
    assert args.chunked is False
    assert args.single_request is False
    assert args.chunk_size is None
    assert args.no_resume is False


def test_cli_upload_parser_accepts_overwrite_direct_ip_and_chunk_options():
    from seafile_vault_cli.cli import build_parser

    args = build_parser().parse_args(
        ["upload", "local.txt", "/folder/remote.txt", "--overwrite", "--direct-ip", "203.0.113.10", "--chunk-size", "123", "--no-resume"]
    )
    assert args.overwrite is True
    assert args.direct_ip == "203.0.113.10"
    assert args.chunk_size == 123
    assert args.no_resume is True


def test_cli_upload_parser_accepts_human_readable_chunk_size():
    from seafile_vault_cli.cli import build_parser

    parser = build_parser()
    cases = [
        ("67108864", 67_108_864),
        ("32MiB", 32 * 1024 * 1024),
        ("64 MiB", 64 * 1024 * 1024),
        ("64MB", 64 * 1000 * 1000),
        ("1 kb", 1000),
        ("2KIB", 2 * 1024),
        ("3 b", 3),
    ]
    for value, expected in cases:
        args = parser.parse_args(["upload", "local.txt", "/folder/remote.txt", "--chunk-size", value])
        assert args.chunk_size == expected


def test_cli_upload_parser_rejects_mutually_exclusive_modes(capsys):
    from seafile_vault_cli.cli import build_parser

    try:
        build_parser().parse_args(["upload", "local.txt", "/folder/remote.txt", "--chunked", "--single-request"])
    except SystemExit as exc:
        assert exc.code == 2
    else:  # pragma: no cover
        raise AssertionError("expected parser failure")
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "usage"


@pytest.mark.parametrize("value", ["0", "-1", "+1", "1.5MiB", "true", "[]", "64XB", "64 Mi B", "90000001", "1GiB"])
def test_cli_upload_parser_rejects_invalid_chunk_size(capsys, value):
    from seafile_vault_cli.cli import build_parser

    try:
        build_parser().parse_args(["upload", "local.txt", "/folder/remote.txt", "--chunk-size", value])
    except SystemExit as exc:
        assert exc.code == 2
    else:  # pragma: no cover
        raise AssertionError("expected parser failure")
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "usage"


def test_cli_json_success_envelope(monkeypatch, capsys):
    from seafile_vault_cli import cli

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def upload_file_path(self, local_file, remote_path, *, overwrite, direct_ip, upload_mode, chunk_size, resume):
            assert (local_file, remote_path, overwrite, direct_ip, upload_mode, chunk_size, resume) == (
                "local.txt",
                "/folder/remote.txt",
                False,
                None,
                "auto",
                None,
                True,
            )
            return {"remote_path": remote_path, "upload_mode": upload_mode}

    monkeypatch.setattr(cli.SeafileVaultClient, "from_env", lambda: FakeClient())
    assert cli.main(["upload", "local.txt", "/folder/remote.txt"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {"ok": True, "data": {"remote_path": "/folder/remote.txt", "upload_mode": "auto"}}


def test_cli_list_passes_options_and_compacts_metadata(monkeypatch, capsys):
    from seafile_vault_cli import cli

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def list_directory(self, path, *, recursive, type_filter):
            assert (path, recursive, type_filter) == ("/docs", True, "f")
            return {
                "repo_id": "secret-repo",
                "dirent_list": [
                    {
                        "name": "a.txt",
                        "type": "file",
                        "size": 3,
                        "mtime": 123,
                        "modifier_email": "person@example.com",
                        "lock_owner": "person@example.com",
                        "id": "internal",
                    }
                ],
            }

    monkeypatch.setattr(cli.SeafileVaultClient, "from_env", lambda: FakeClient())
    assert cli.main(["list", "/docs", "--recursive", "--type", "file", "--compact"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "ok": True,
        "data": {"path": "/docs", "count": 1, "entries": [{"name": "a.txt", "type": "file", "size": 3, "mtime": 123}]},
    }


def test_cli_compact_list_preserves_zero_mtime_and_rejects_malformed_shape(monkeypatch, capsys):
    from seafile_vault_cli import cli

    class FakeClient:
        def __init__(self, result):
            self.result = result

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def list_directory(self, path, *, recursive, type_filter):
            return self.result

    monkeypatch.setattr(cli.SeafileVaultClient, "from_env", lambda: FakeClient({"dirent_list": [{"name": "epoch.txt", "mtime": 0}]}))
    assert cli.main(["list", "/docs", "--compact"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["data"]["entries"] == [{"name": "epoch.txt", "mtime": 0}]

    monkeypatch.setattr(cli.SeafileVaultClient, "from_env", lambda: FakeClient({"dirent_list": {}}))
    assert cli.main(["list", "/docs", "--compact"]) == 6
    payload = json.loads(capsys.readouterr().err)
    assert payload["error"]["code"] == "seafilevault"
    assert "not a list" in payload["error"]["message"]


def test_cli_search_matches_case_type_and_normalizes_full_paths(monkeypatch, capsys):
    from seafile_vault_cli import cli

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def validate_vault_path(self, path):
            assert path == "/docs"
            return path

        def list_directory(self, path, *, recursive, type_filter):
            assert (path, recursive, type_filter) == ("/docs", True, "f")
            return {
                "repo_id": "secret-repo",
                "dirent_list": [
                    {
                        "name": "Note.md",
                        "type": "file",
                        "size": 7,
                        "mtime": 0,
                        "parent_dir": "/docs/sub/",
                        "modifier_email": "x@example.com",
                    },
                    {"name": "note.MD", "type": "file", "size": 8, "path": "/docs/note.MD", "lock_owner": "x@example.com"},
                    {"name": "notes", "type": "dir", "parent_dir": "/docs"},
                    {"name": "image.png", "type": "file", "parent_dir": "/docs"},
                ],
            }

    monkeypatch.setattr(cli.SeafileVaultClient, "from_env", lambda: FakeClient())
    assert cli.main(["search", "/docs", "--name", "*.md", "--type", "file"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "ok": True,
        "data": {
            "path": "/docs",
            "pattern": "*.md",
            "count": 2,
            "results": [
                {"path": "/docs/sub/Note.md", "name": "Note.md", "type": "file", "size": 7, "mtime": 0},
                {"path": "/docs/note.MD", "name": "note.MD", "type": "file", "size": 8},
            ],
        },
    }

    assert cli.main(["search", "/docs", "--name", "*.md", "--type", "file", "--case-sensitive"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert [item["name"] for item in payload["data"]["results"]] == ["Note.md"]


def test_cli_search_rejects_max_result_truncation_and_malformed_shapes(monkeypatch, capsys):
    from seafile_vault_cli import cli

    class FakeClient:
        def __init__(self, result):
            self.result = result

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def validate_vault_path(self, path):
            return path

        def list_directory(self, path, *, recursive, type_filter):
            return self.result

    monkeypatch.setattr(cli.SeafileVaultClient, "from_env", lambda: FakeClient([{"name": "a.txt"}, {"name": "b.txt"}]))
    assert cli.main(["search", "/", "--name", "*.txt", "--max-results", "1"]) == 6
    payload = json.loads(capsys.readouterr().err)
    assert "exceeding --max-results 1" in payload["error"]["message"]

    monkeypatch.setattr(cli.SeafileVaultClient, "from_env", lambda: FakeClient({"dirent_list": {}}))
    assert cli.main(["search", "/", "--name", "*.txt"]) == 6
    payload = json.loads(capsys.readouterr().err)
    assert "not a list" in payload["error"]["message"]


def test_cli_search_rejects_adversarial_server_paths(monkeypatch, capsys):
    from seafile_vault_cli import cli

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def validate_vault_path(self, path):
            return "/docs"

        def list_directory(self, path, *, recursive, type_filter):
            return [
                {"name": "good.txt", "type": "file", "parent_dir": "/docs/sub"},
                {"name": "../escape.txt", "type": "file", "parent_dir": "/docs"},
                {"name": "slash/name.txt", "type": "file", "parent_dir": "/docs"},
                {"name": "back\\name.txt", "type": "file", "parent_dir": "/docs"},
                {"name": "nul\x00name.txt", "type": "file", "parent_dir": "/docs"},
                {"name": "control\nname.txt", "type": "file", "parent_dir": "/docs"},
                {"name": "escape.txt", "type": "file", "parent_dir": "/docs/.."},
                {"name": "double.txt", "type": "file", "parent_dir": "/docs//sub"},
                {"name": "dot.txt", "type": "file", "parent_dir": "/docs/./sub"},
                {"name": "trail.txt", "type": "file", "parent_dir": "/docs/sub/"},
                {"name": "doubletrail.txt", "type": "file", "parent_dir": "/docs/sub//"},
                {"name": "pathtrail.txt", "type": "file", "path": "/docs/sub/pathtrail.txt/"},
                {"name": "fulltrail.txt", "type": "file", "full_path": "/docs/sub/fulltrail.txt/"},
                {"name": "outside.txt", "type": "file", "path": "/outside/outside.txt"},
                {"name": "mismatch.txt", "type": "file", "path": "/docs/other.txt"},
                {"name": "relative.txt", "type": "file", "parent_dir": "docs"},
            ]

    monkeypatch.setattr(cli.SeafileVaultClient, "from_env", lambda: FakeClient())
    assert cli.main(["search", "/docs", "--name", "*.txt", "--type", "file"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["data"]["results"] == [
        {"name": "good.txt", "path": "/docs/sub/good.txt", "type": "file"},
        {"name": "trail.txt", "path": "/docs/sub/trail.txt", "type": "file"},
    ]


def test_cli_search_rejects_invalid_max_bounds(capsys):
    from seafile_vault_cli.cli import build_parser

    with pytest.raises(SystemExit) as excinfo:
        build_parser().parse_args(["search", "/", "--name", "*", "--max-results", "1001"])
    assert excinfo.value.code == 2
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "usage"


def test_cli_download_stat_and_mkdir_json_calls(monkeypatch, capsys):
    from seafile_vault_cli import cli

    calls = []

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def download_file_path(self, remote_path, local_file, *, overwrite):
            calls.append(("download", remote_path, local_file, overwrite))
            return {"remote_path": remote_path, "local_name": local_file, "overwrite": overwrite}

        def stat_file(self, path):
            calls.append(("stat", path))
            return {"name": "remote.txt", "size": 1}

        def create_directory(self, path, *, parents):
            calls.append(("mkdir", path, parents))
            return {"path": path, "created": [path], "skipped": []}

    monkeypatch.setattr(cli.SeafileVaultClient, "from_env", lambda: FakeClient())
    assert cli.main(["download", "/remote.txt", "local.txt", "--overwrite"]) == 0
    assert json.loads(capsys.readouterr().out)["data"]["overwrite"] is True
    assert cli.main(["stat", "/remote.txt"]) == 0
    assert json.loads(capsys.readouterr().out)["data"]["size"] == 1
    assert cli.main(["mkdir", "/a/b", "--parents"]) == 0
    assert json.loads(capsys.readouterr().out)["data"]["created"] == ["/a/b"]
    assert calls == [("download", "/remote.txt", "local.txt", True), ("stat", "/remote.txt"), ("mkdir", "/a/b", True)]


def test_cli_copy_json_call(monkeypatch, capsys):
    from seafile_vault_cli import cli

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def copy_path(self, source, destination_directory, *, is_directory):
            assert (source, destination_directory, is_directory) == ("/source.txt", "/archive", False)
            return {"destination_path": "/archive/source.txt"}

    monkeypatch.setattr(cli.SeafileVaultClient, "from_env", lambda: FakeClient())
    assert cli.main(["copy", "/source.txt", "/archive"]) == 0
    assert json.loads(capsys.readouterr().out) == {"ok": True, "data": {"destination_path": "/archive/source.txt"}}


def test_cli_copy_directory_dispatch(monkeypatch, capsys):
    from seafile_vault_cli import cli

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def copy_path(self, source, destination_directory, *, is_directory):
            assert (source, destination_directory, is_directory) == ("/source", "/archive", True)
            return {"destination_path": "/archive/source", "type": "dir"}

    monkeypatch.setattr(cli.SeafileVaultClient, "from_env", lambda: FakeClient())
    assert cli.main(["copy", "/source", "/archive", "--dir"]) == 0
    assert json.loads(capsys.readouterr().out)["data"]["type"] == "dir"


def test_cli_lock_rolls_back_server_lock_when_registry_persistence_fails(monkeypatch, capsys):
    from seafile_vault_cli import cli
    from seafile_vault_cli.lock_registry import LockRegistryError

    calls = []

    class FakeClient:
        server_url = "https://seafile.example.com"

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def validate_vault_path(self, path):
            return path

        def get_repo_info(self):
            return {"repo_id": "11111111-2222-3333-4444-555555555555"}

        def lock_file(self, path, expires_seconds):
            calls.append(("lock", path, expires_seconds))
            return {"success": True}

        def unlock_file(self, path):
            calls.append(("unlock", path))
            return {"success": True}

    class FailingRegistry:
        def add(self, *_args, **_kwargs):
            raise LockRegistryError("disk full")

    monkeypatch.setattr(cli.SeafileVaultClient, "from_env", lambda: FakeClient())
    monkeypatch.setattr(cli, "_registry", lambda: FailingRegistry())
    assert cli.main(["lock", "/source.txt", "--expires", "120"]) == 6
    captured = capsys.readouterr()
    payload = json.loads(captured.err)
    assert payload["error"]["code"] == "lockregistry"
    assert "rolled back" in payload["error"]["message"]
    assert calls == [("lock", "/source.txt", 120), ("unlock", "/source.txt")]


def test_cli_lock_rollback_failure_requires_manual_unlock(monkeypatch, capsys):
    from seafile_vault_cli import cli
    from seafile_vault_cli.client import SeafileVaultError
    from seafile_vault_cli.lock_registry import LockRegistryError

    class FakeClient:
        server_url = "https://seafile.example.com"

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def validate_vault_path(self, path):
            return path

        def get_repo_info(self):
            return {"repo_id": "11111111-2222-3333-4444-555555555555"}

        def lock_file(self, path, expires_seconds):
            return {"success": True}

        def unlock_file(self, path):
            raise SeafileVaultError("remote refused")

    class FailingRegistry:
        def add(self, *_args, **_kwargs):
            raise LockRegistryError("readonly filesystem")

    monkeypatch.setattr(cli.SeafileVaultClient, "from_env", lambda: FakeClient())
    monkeypatch.setattr(cli, "_registry", lambda: FailingRegistry())
    assert cli.main(["lock", "/source.txt"]) == 6
    payload = json.loads(capsys.readouterr().err)
    assert payload["error"]["code"] == "seafilevault"
    assert "manual unlock is required" in payload["error"]["message"]


def test_unlock_refuses_untracked_lock_without_explicit_recovery_confirmation():
    from seafile_vault_cli.cli import _unlock_file_lifecycle
    from seafile_vault_cli.client import ConfigError
    from seafile_vault_cli.lock_registry import LockRegistryError

    calls = []

    class FakeClient:
        server_url = "https://seafile.example.com"

        def get_repo_info(self):
            return {"repo_id": "11111111-2222-3333-4444-555555555555"}

        def validate_vault_path(self, path):
            return path

        def unlock_file(self, path):
            calls.append(path)
            return {"success": True}

    class EmptyRegistry:
        def list(self, _identity):
            return []

    client = FakeClient()
    registry = EmptyRegistry()
    with pytest.raises(LockRegistryError, match="possibly foreign"):
        _unlock_file_lifecycle(client, "/note.txt", registry)
    with pytest.raises(ConfigError, match="requires --confirm"):
        _unlock_file_lifecycle(client, "/note.txt", registry, force_untracked=True)
    result = _unlock_file_lifecycle(client, "/note.txt", registry, force_untracked=True, confirmed=True)
    assert result["forced_untracked"] is True
    assert result["tracked_by_this_client"] is False
    assert calls == ["/note.txt"]


def test_cli_locks_audit_prune_removes_only_proven_stale(tmp_path):
    from seafile_vault_cli.cli import _list_lock_lifecycle
    from seafile_vault_cli.lock_registry import LockRegistry, build_library_identity

    identity = build_library_identity("https://seafile.example.com", "11111111-2222-3333-4444-555555555555")
    registry = LockRegistry(tmp_path / "locks.json")
    acquired = datetime(2026, 1, 1, tzinfo=UTC)
    registry.add(identity, "/active.txt", 3600, acquired_at=acquired)
    registry.add(identity, "/stale.txt", 3600, acquired_at=acquired)
    registry.add(identity, "/missing.txt", 3600, acquired_at=acquired)
    registry.add(identity, "/error.txt", 3600, acquired_at=acquired)

    class FakeClient:
        server_url = "https://seafile.example.com"

        def get_repo_info(self):
            return {"repo_id": identity.repo_id}

        def stat_file(self, path):
            from seafile_vault_cli.client import RemoteNotFoundError, SeafileVaultError

            if path == "/active.txt":
                return {"name": "active.txt", "size": 1, "is_locked": True}
            if path == "/stale.txt":
                return {"name": "stale.txt", "size": 1, "is_locked": False}
            if path == "/missing.txt":
                raise RemoteNotFoundError("remote file not found: /missing.txt")
            raise SeafileVaultError("temporary server failure")

    result = _list_lock_lifecycle(FakeClient(), prune=True, registry=registry)
    statuses = {item["path"]: item["status"] for item in result["locks"]}
    assert statuses == {
        "/active.txt": "expired_but_server_locked",
        "/stale.txt": "stale",
        "/missing.txt": "file_not_found",
        "/error.txt": "server_error",
    }
    assert result["pruned"] == ["/missing.txt", "/stale.txt"]
    remaining = [record.path for record in registry.list(identity)]
    assert remaining == ["/active.txt", "/error.txt"]


def test_cli_upload_json_passes_chunked_flags(monkeypatch, capsys):
    from seafile_vault_cli import cli

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def upload_file_path(self, local_file, remote_path, *, overwrite, direct_ip, upload_mode, chunk_size, resume):
            assert upload_mode == "chunked"
            assert chunk_size == 123
            assert resume is False
            return {"upload_mode": upload_mode, "chunk_size": chunk_size, "resume_supported": False}

    monkeypatch.setattr(cli.SeafileVaultClient, "from_env", lambda: FakeClient())
    assert cli.main(["upload", "local.txt", "/folder/remote.txt", "--chunked", "--chunk-size", "123", "--no-resume"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["data"]["upload_mode"] == "chunked"
    assert payload["data"]["chunk_size"] == 123


def test_cli_upload_chunked_direct_rejection_is_configuration_json(monkeypatch, capsys):
    from seafile_vault_cli import cli
    from seafile_vault_cli.client import ConfigError

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def upload_file_path(self, *args, **kwargs):
            raise ConfigError("--chunked cannot be combined with direct-origin upload")

    monkeypatch.setattr(cli.SeafileVaultClient, "from_env", lambda: FakeClient())
    assert cli.main(["upload", "local.txt", "/folder/remote.txt", "--chunked", "--direct-ip", "203.0.113.10"]) == 3
    payload = json.loads(capsys.readouterr().err)
    assert payload == {
        "error": {"code": "configuration", "message": "--chunked cannot be combined with direct-origin upload"},
        "ok": False,
    }


def test_cli_json_permission_error_envelope(monkeypatch, capsys):
    from seafile_vault_cli import cli
    from seafile_vault_cli.client import PermissionModeError

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def create_directory(self, path, *, parents=False):
            raise PermissionModeError("blocked")

    monkeypatch.setattr(cli.SeafileVaultClient, "from_env", lambda: FakeClient())
    assert cli.main(["mkdir", "/x"]) == 4
    captured = capsys.readouterr()
    assert captured.out == ""
    payload = json.loads(captured.err)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "permission_denied"


def test_cli_stable_exit_code_mapping(monkeypatch, capsys):
    from seafile_vault_cli import cli
    from seafile_vault_cli.client import ConfigError, LocalFileError, SeafileVaultError, SizeLimitError

    monkeypatch.setattr(cli.SeafileVaultClient, "from_env", lambda: (_ for _ in ()).throw(ConfigError("bad config")))
    assert cli.main(["repo-info"]) == 3
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "configuration"

    class FakeClient:
        def __init__(self, exc):
            self.exc = exc

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def get_repo_info(self):
            raise self.exc

    monkeypatch.setattr(cli.SeafileVaultClient, "from_env", lambda: FakeClient(LocalFileError("bad local")))
    assert cli.main(["repo-info"]) == 5
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "localfile"

    monkeypatch.setattr(cli.SeafileVaultClient, "from_env", lambda: FakeClient(SizeLimitError("too large")))
    assert cli.main(["repo-info"]) == 6
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "size_limit"

    monkeypatch.setattr(cli.SeafileVaultClient, "from_env", lambda: FakeClient(SeafileVaultError("remote failed")))
    assert cli.main(["repo-info"]) == 6
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "seafilevault"


def test_cli_remote_not_found_error_envelope(monkeypatch, capsys):
    from seafile_vault_cli import cli
    from seafile_vault_cli.client import RemoteNotFoundError

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def stat_file(self, path):
            raise RemoteNotFoundError(f"remote file not found: {path}")

        def download_file_path(self, remote_path, local_file, *, overwrite):
            raise RemoteNotFoundError(f"remote file not found: {remote_path}")

    monkeypatch.setattr(cli.SeafileVaultClient, "from_env", lambda: FakeClient())
    assert cli.main(["stat", "/missing.txt"]) == 6
    payload = json.loads(capsys.readouterr().err)
    assert payload == {"ok": False, "error": {"code": "remote_not_found", "message": "remote file not found: /missing.txt"}}
    assert cli.main(["download", "/missing.txt", "local.txt"]) == 6
    payload = json.loads(capsys.readouterr().err)
    assert payload == {"ok": False, "error": {"code": "remote_not_found", "message": "remote file not found: /missing.txt"}}


def test_mcp_server_module_importable():
    import seafile_vault_cli.mcp_server as mcp_server

    assert hasattr(mcp_server, "main")


def test_mcp_missing_extra_exits_deterministic_json(monkeypatch, capsys):
    import seafile_vault_cli.mcp_server as mcp_server

    monkeypatch.setitem(sys.modules, "mcp", None)
    assert mcp_server.main() == 3
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "error": {"code": "configuration", "message": "mcp package is required: install seafile-vault-cli[mcp]"},
        "ok": False,
    }
    assert "Traceback" not in captured.err


def test_mcp_server_registers_read_only_tool_names(monkeypatch):
    class FakeFastMCP:
        def __init__(self, name):
            self.name = name
            self.tools = []

        def tool(self):
            def decorator(func):
                self.tools.append(func.__name__)
                return func

            return decorator

    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_fastmcp.FastMCP = FakeFastMCP
    fake_server = types.ModuleType("mcp.server")
    fake_server.fastmcp = fake_fastmcp
    fake_mcp = types.ModuleType("mcp")
    fake_mcp.server = fake_server
    monkeypatch.setitem(sys.modules, "mcp", fake_mcp)
    monkeypatch.setitem(sys.modules, "mcp.server", fake_server)
    monkeypatch.setitem(sys.modules, "mcp.server.fastmcp", fake_fastmcp)

    from seafile_vault_cli.mcp_server import build_server

    server = build_server()
    assert server.name == "seafile-vault-cli"
    assert "seafile_vault_search_by_name" in server.tools
    assert "seafile_vault_library_history" in server.tools
    assert "seafile_vault_share_links" in server.tools
    assert "seafile_vault_metadata_views" in server.tools
    assert "seafile_vault_metadata_tag_files" in server.tools
    assert "seafile_vault_rename_path" not in server.tools
    assert "seafile_vault_move_path" not in server.tools
    assert "seafile_vault_delete_path" not in server.tools
    assert "seafile_vault_write_text_file" not in server.tools
    assert "seafile_vault_lock_path" not in server.tools
    assert "seafile_vault_unlock_path" not in server.tools


def test_mcp_metadata_records_exposes_pagination(monkeypatch):
    class FakeFastMCP:
        def __init__(self, name):
            self.name = name
            self.tools = {}

        def tool(self):
            def decorator(func):
                self.tools[func.__name__] = func
                return func

            return decorator

    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_fastmcp.FastMCP = FakeFastMCP
    fake_server = types.ModuleType("mcp.server")
    fake_server.fastmcp = fake_fastmcp
    fake_mcp = types.ModuleType("mcp")
    fake_mcp.server = fake_server
    monkeypatch.setitem(sys.modules, "mcp", fake_mcp)
    monkeypatch.setitem(sys.modules, "mcp.server", fake_server)
    monkeypatch.setitem(sys.modules, "mcp.server.fastmcp", fake_fastmcp)

    from seafile_vault_cli.mcp_server import build_server

    server = build_server()
    signature = inspect.signature(server.tools["seafile_vault_metadata_records"])
    assert signature.parameters["start"].default == 0
    assert signature.parameters["limit"].default == 1000


def test_mcp_search_uses_existing_safe_results(monkeypatch):
    class FakeFastMCP:
        def __init__(self, name):
            self.name = name
            self.tools = {}

        def tool(self):
            def decorator(func):
                self.tools[func.__name__] = func
                return func

            return decorator

    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_fastmcp.FastMCP = FakeFastMCP
    fake_server = types.ModuleType("mcp.server")
    fake_server.fastmcp = fake_fastmcp
    fake_mcp = types.ModuleType("mcp")
    fake_mcp.server = fake_server
    monkeypatch.setitem(sys.modules, "mcp", fake_mcp)
    monkeypatch.setitem(sys.modules, "mcp.server", fake_server)
    monkeypatch.setitem(sys.modules, "mcp.server.fastmcp", fake_fastmcp)

    import seafile_vault_cli.mcp_server as mcp_server

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def validate_vault_path(self, path):
            assert path == "/docs"
            return path

        def list_directory(self, path, *, recursive, type_filter):
            assert (path, recursive, type_filter) == ("/docs", True, "f")
            return [{"name": "note.md", "type": "file", "parent_dir": "/docs", "size": 1}]

    monkeypatch.setattr(mcp_server, "_client", lambda: FakeClient())
    server = mcp_server.build_server()
    result = server.tools["seafile_vault_search_by_name"]("/docs", "*.md", "file", 10, False)
    assert result["results"] == [{"path": "/docs/note.md", "name": "note.md", "type": "file", "size": 1}]
