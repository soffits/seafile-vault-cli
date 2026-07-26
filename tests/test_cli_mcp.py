import inspect
import json
import os
import subprocess
import sys
import types

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

        def create_directory(self, path):
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


def test_mcp_server_registers_mutation_tool_names(monkeypatch):
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
    assert "seafile_vault_rename_path" in server.tools
    assert "seafile_vault_move_path" in server.tools
    assert "seafile_vault_delete_path" in server.tools


def test_mcp_rename_and_move_expose_is_directory(monkeypatch):
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
    assert inspect.signature(server.tools["seafile_vault_rename_path"]).parameters["is_directory"].default is False
    assert inspect.signature(server.tools["seafile_vault_move_path"]).parameters["is_directory"].default is False
