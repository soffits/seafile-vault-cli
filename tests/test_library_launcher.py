import json
import os
import subprocess
import sys
from pathlib import Path


def _write_profile(path, text):
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)


def test_library_launcher_global_help_and_version_do_not_require_profile():
    help_result = subprocess.run(
        [sys.executable, "-m", "seafile_vault_cli.library_launcher", "--help"],
        cwd=os.getcwd(),
        text=True,
        capture_output=True,
        check=False,
    )
    assert help_result.returncode == 0
    assert "seafile-library" in help_result.stdout

    version_result = subprocess.run(
        [sys.executable, "-m", "seafile_vault_cli.library_launcher", "--version"],
        cwd=os.getcwd(),
        text=True,
        capture_output=True,
        check=False,
    )
    assert version_result.returncode == 0
    assert "0.4.0" in version_result.stdout


def test_library_launcher_list_returns_compact_json(tmp_path, monkeypatch, capsys):
    from seafile_vault_cli import library_launcher

    config_dir = tmp_path / "libraries"
    config_dir.mkdir(mode=0o700)
    _write_profile(config_dir / "beta.env", "SEAFILE_SERVER_URL=https://seafile.example.com\nSEAFILE_REPO_TOKEN=token\n")
    _write_profile(config_dir / "alpha.env", "SEAFILE_SERVER_URL=https://seafile.example.com\nSEAFILE_REPO_TOKEN=token\n")
    (config_dir / "ignored.txt").write_text("", encoding="utf-8")
    monkeypatch.setenv("SEAFILE_LIBRARY_CONFIG_DIR", str(config_dir))

    assert library_launcher.main(["--list"]) == 0
    assert json.loads(capsys.readouterr().out) == {"ok": True, "data": {"profiles": ["alpha", "beta"]}}


def test_library_launcher_profile_help_delegates_without_config(tmp_path, monkeypatch, capsys):
    from seafile_vault_cli import library_launcher

    monkeypatch.setenv("SEAFILE_LIBRARY_CONFIG_DIR", str(tmp_path / "missing"))
    assert library_launcher.main(["example", "--help"]) == 0
    captured = capsys.readouterr()
    assert "seafile-vault" in captured.out
    assert captured.err == ""


def test_library_launcher_unknown_profile_returns_safe_suggestions(tmp_path, monkeypatch, capsys):
    from seafile_vault_cli import library_launcher

    config_dir = tmp_path / "libraries"
    config_dir.mkdir(mode=0o700)
    _write_profile(config_dir / "docs.env", "SEAFILE_SERVER_URL=https://seafile.example.com\nSEAFILE_REPO_TOKEN=secret-token\n")
    monkeypatch.setenv("SEAFILE_LIBRARY_CONFIG_DIR", str(config_dir))

    assert library_launcher.main(["doc", "repo-info"]) == 3
    captured = capsys.readouterr()
    payload = json.loads(captured.err)
    assert payload["error"]["code"] == "configuration"
    assert payload["error"]["suggestions"] == ["docs"]
    assert "secret-token" not in captured.err
    assert str(config_dir) not in captured.err


def test_library_launcher_loads_profile_and_calls_cli_with_no_secret_output(tmp_path, monkeypatch, capsys):
    from seafile_vault_cli import library_launcher

    config_dir = tmp_path / "libraries"
    config_dir.mkdir(mode=0o700)
    _write_profile(
        config_dir / "docs.env",
        "SEAFILE_SERVER_URL=https://seafile.example.com\nSEAFILE_REPO_TOKEN=secret-token\nSEAFILE_PERMISSION_MODE=read_only\n",
    )
    calls = []

    def fake_main(argv):
        calls.append((argv, os.environ["SEAFILE_SERVER_URL"], os.environ["SEAFILE_REPO_TOKEN"]))
        print(json.dumps({"ok": True, "data": {"command": argv}}))
        return 0

    monkeypatch.setenv("SEAFILE_LIBRARY_CONFIG_DIR", str(config_dir))
    monkeypatch.setattr(library_launcher.cli, "main", fake_main)
    assert library_launcher.main(["docs", "repo-info"]) == 0
    captured = capsys.readouterr()
    assert calls == [(["repo-info"], "https://seafile.example.com", "secret-token")]
    assert "secret-token" not in captured.out


def test_library_launcher_only_inherits_documented_optional_seafile_env(tmp_path, monkeypatch):
    from seafile_vault_cli import library_launcher

    config_dir = tmp_path / "libraries"
    config_dir.mkdir(mode=0o700)
    _write_profile(config_dir / "docs.env", "SEAFILE_SERVER_URL=https://seafile.example.com\nSEAFILE_REPO_TOKEN=secret-token\n")
    seen = []

    def fake_main(argv):
        seen.append(
            {
                "server": os.environ.get("SEAFILE_SERVER_URL"),
                "token": os.environ.get("SEAFILE_REPO_TOKEN"),
                "optional": os.environ.get("SEAFILE_MAX_READ_SIZE"),
                "unsupported": os.environ.get("SEAFILE_UNSUPPORTED"),
                "config_dir": os.environ.get("SEAFILE_LIBRARY_CONFIG_DIR"),
            }
        )
        return 0

    monkeypatch.setenv("SEAFILE_LIBRARY_CONFIG_DIR", str(config_dir))
    monkeypatch.setenv("SEAFILE_SERVER_URL", "https://wrong.example.com")
    monkeypatch.setenv("SEAFILE_REPO_TOKEN", "wrong-token")
    monkeypatch.setenv("SEAFILE_MAX_READ_SIZE", "123")
    monkeypatch.setenv("SEAFILE_UNSUPPORTED", "not-passed")
    monkeypatch.setattr(library_launcher.cli, "main", fake_main)

    assert library_launcher.main(["docs", "repo-info"]) == 0
    assert seen == [
        {
            "server": "https://seafile.example.com",
            "token": "secret-token",
            "optional": "123",
            "unsupported": None,
            "config_dir": None,
        }
    ]
    assert os.environ["SEAFILE_UNSUPPORTED"] == "not-passed"


def test_library_launcher_rejects_symlink_and_insecure_permissions(tmp_path, monkeypatch, capsys):
    from seafile_vault_cli import library_launcher

    config_dir = tmp_path / "libraries"
    config_dir.mkdir(mode=0o700)
    target = config_dir / "target.env"
    _write_profile(target, "SEAFILE_SERVER_URL=https://seafile.example.com\nSEAFILE_REPO_TOKEN=secret-token\n")
    (config_dir / "link.env").symlink_to(target)
    monkeypatch.setenv("SEAFILE_LIBRARY_CONFIG_DIR", str(config_dir))
    assert library_launcher.main(["link", "repo-info"]) == 3
    assert "secret-token" not in capsys.readouterr().err

    _write_profile(config_dir / "open.env", "SEAFILE_SERVER_URL=https://seafile.example.com\nSEAFILE_REPO_TOKEN=secret-token\n")
    (config_dir / "open.env").chmod(0o644)
    assert library_launcher.main(["open", "repo-info"]) == 3
    payload = json.loads(capsys.readouterr().err)
    assert "permissions are insecure" in payload["error"]["message"]


def test_library_launcher_rejects_insecure_config_dir(tmp_path, monkeypatch, capsys):
    from seafile_vault_cli import library_launcher

    config_dir = tmp_path / "libraries"
    config_dir.mkdir(mode=0o777)
    config_dir.chmod(0o777)
    monkeypatch.setenv("SEAFILE_LIBRARY_CONFIG_DIR", str(config_dir))
    assert library_launcher.main(["--list"]) == 3
    payload = json.loads(capsys.readouterr().err)
    assert "permissions are insecure" in payload["error"]["message"]


def test_library_launcher_env_parser_rejects_duplicates_malformed_keys_nul_and_missing_required(tmp_path, monkeypatch, capsys):
    from seafile_vault_cli import library_launcher

    config_dir = tmp_path / "libraries"
    config_dir.mkdir(mode=0o700)
    monkeypatch.setenv("SEAFILE_LIBRARY_CONFIG_DIR", str(config_dir))

    cases = [
        ("dup", "SEAFILE_SERVER_URL=https://seafile.example.com\nSEAFILE_REPO_TOKEN=one\nSEAFILE_REPO_TOKEN=two\n", "duplicates"),
        ("badkey", "bad=1\nSEAFILE_SERVER_URL=https://seafile.example.com\nSEAFILE_REPO_TOKEN=one\n", "malformed key"),
        ("missing", "SEAFILE_SERVER_URL=https://seafile.example.com\n", "missing required keys"),
    ]
    for name, text, message in cases:
        _write_profile(config_dir / f"{name}.env", text)
        assert library_launcher.main([name, "repo-info"]) == 3
        assert message in json.loads(capsys.readouterr().err)["error"]["message"]

    nul_path = config_dir / "nul.env"
    nul_path.write_bytes(b"SEAFILE_SERVER_URL=https://seafile.example.com\nSEAFILE_REPO_TOKEN=one\x00\n")
    nul_path.chmod(0o600)
    assert library_launcher.main(["nul", "repo-info"]) == 3
    assert "NUL" in json.loads(capsys.readouterr().err)["error"]["message"]


def test_library_launcher_rejects_path_traversal_and_control_chars(capsys):
    from seafile_vault_cli import library_launcher

    assert library_launcher.main(["../x", "repo-info"]) == 2
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "usage"

    assert library_launcher.main(["bad\nname", "repo-info"]) == 2
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "usage"


def test_library_launcher_rejects_relative_config_dir(monkeypatch, capsys):
    from seafile_vault_cli import library_launcher

    monkeypatch.setenv("SEAFILE_LIBRARY_CONFIG_DIR", "relative/libraries")
    assert library_launcher.main(["--list"]) == 3
    assert "absolute path" in json.loads(capsys.readouterr().err)["error"]["message"]


def test_library_launcher_env_file_is_strict_utf8(tmp_path, monkeypatch, capsys):
    from seafile_vault_cli import library_launcher

    config_dir = tmp_path / "libraries"
    config_dir.mkdir(mode=0o700)
    path = config_dir / "docs.env"
    path.write_bytes(b"SEAFILE_SERVER_URL=https://seafile.example.com\nSEAFILE_REPO_TOKEN=\xff\n")
    path.chmod(0o600)
    monkeypatch.setenv("SEAFILE_LIBRARY_CONFIG_DIR", str(config_dir))
    assert library_launcher.main(["docs", "repo-info"]) == 3
    assert "strict UTF-8" in json.loads(capsys.readouterr().err)["error"]["message"]


def test_library_launcher_checks_opened_profile_fd_permissions(tmp_path, monkeypatch):
    from seafile_vault_cli import library_launcher

    safe = tmp_path / "safe.env"
    _write_profile(safe, "SEAFILE_SERVER_URL=https://seafile.example.com\nSEAFILE_REPO_TOKEN=token\n")
    insecure = tmp_path / "insecure.env"
    _write_profile(insecure, "SEAFILE_SERVER_URL=https://seafile.example.com\nSEAFILE_REPO_TOKEN=other\n")
    insecure.chmod(0o644)
    original_open = os.open

    def fake_open(path, flags):
        assert Path(path) == safe
        return original_open(insecure, flags)

    monkeypatch.setattr(library_launcher.os, "open", fake_open)
    try:
        library_launcher._read_profile_file(safe)
    except library_launcher.LauncherError as exc:
        assert "permissions are insecure" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected LauncherError")
