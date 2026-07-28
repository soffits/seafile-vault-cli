from __future__ import annotations

import difflib
import json
import os
import re
import stat
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import __version__, cli

EXIT_USAGE = 2
EXIT_CONFIG = 3

DEFAULT_CONFIG_DIR = "~/.config/seafile-vault/libraries"
PROFILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
KEY_RE = re.compile(r"[A-Z][A-Z0-9_]*")
REQUIRED_KEYS = {"SEAFILE_SERVER_URL", "SEAFILE_REPO_TOKEN"}
OPTIONAL_KEYS = {
    "SEAFILE_PERMISSION_MODE",
    "SEAFILE_MAX_READ_SIZE",
    "SEAFILE_MAX_WRITE_SIZE",
    "SEAFILE_REQUEST_TIMEOUT",
    "SEAFILE_UPLOAD_TIMEOUT",
    "SEAFILE_UPLOAD_CHUNK_SIZE",
    "SEAFILE_UPLOAD_DIRECT_IP",
}
ALLOWED_KEYS = REQUIRED_KEYS | OPTIONAL_KEYS


def _success(data: Any) -> dict[str, Any]:
    return {"ok": True, "data": data}


def _error(code: str, message: str, **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"ok": False, "error": {"code": code, "message": message}}
    payload["error"].update(extra)
    return payload


def _dump_stdout(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def _dump_stderr(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")), file=sys.stderr)


class LauncherError(Exception):
    def __init__(self, code: str, message: str, *, suggestions: list[str] | None = None):
        super().__init__(message)
        self.code = code
        self.suggestions = suggestions


def _is_safe_profile_name(name: str) -> bool:
    return bool(PROFILE_RE.fullmatch(name)) and ".." not in name and not any(ord(char) < 32 or ord(char) == 127 for char in name)


def _config_dir(environ: Mapping[str, str]) -> Path:
    raw = environ.get("SEAFILE_LIBRARY_CONFIG_DIR") or DEFAULT_CONFIG_DIR
    if "\x00" in raw or any(ord(char) < 32 or ord(char) == 127 for char in raw):
        raise LauncherError("configuration", "SEAFILE_LIBRARY_CONFIG_DIR contains unsafe characters")
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise LauncherError("configuration", "SEAFILE_LIBRARY_CONFIG_DIR must be an absolute path")
    return path


def _check_config_dir(path: Path) -> None:
    try:
        st = path.lstat()
    except FileNotFoundError as exc:
        raise LauncherError("configuration", "library config directory does not exist") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise LauncherError("configuration", "library config directory is not a real directory")
    if st.st_mode & stat.S_IWGRP or st.st_mode & stat.S_IWOTH:
        raise LauncherError("configuration", "library config directory permissions are insecure")
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        raise LauncherError("configuration", "library config directory owner is insecure")


def _available_profiles(config_dir: Path) -> list[str]:
    _check_config_dir(config_dir)
    names: list[str] = []
    for child in config_dir.iterdir():
        if child.suffix != ".env":
            continue
        profile = child.name[:-4]
        if _is_safe_profile_name(profile) and not child.is_symlink() and child.is_file():
            names.append(profile)
    return sorted(set(names))


def _suggest(profile: str, available: list[str]) -> list[str]:
    return difflib.get_close_matches(profile, available, n=3, cutoff=0.45)


def _profile_file(config_dir: Path, profile: str) -> Path:
    if not _is_safe_profile_name(profile):
        raise LauncherError("usage", "invalid library profile name")
    available = _available_profiles(config_dir)
    if profile not in available:
        raise LauncherError("configuration", "library profile was not found", suggestions=_suggest(profile, available))
    path = config_dir / f"{profile}.env"
    try:
        resolved_parent = path.parent.resolve(strict=True)
    except OSError as exc:
        raise LauncherError("configuration", "library config directory is unavailable") from exc
    if resolved_parent != config_dir.resolve(strict=True):
        raise LauncherError("configuration", "library profile path is unsafe")
    return path


def _read_profile_file(path: Path) -> dict[str, str]:
    try:
        st = path.lstat()
    except FileNotFoundError as exc:
        raise LauncherError("configuration", "library profile was not found") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise LauncherError("configuration", "library profile is not a regular file")
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise LauncherError("configuration", "library profile permissions are insecure")
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        raise LauncherError("configuration", "library profile owner is insecure")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise LauncherError("configuration", "library profile could not be opened securely") from exc
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode):
            raise LauncherError("configuration", "library profile is not a regular file")
        if fst.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise LauncherError("configuration", "library profile permissions are insecure")
        if hasattr(os, "geteuid") and fst.st_uid != os.geteuid():
            raise LauncherError("configuration", "library profile owner is insecure")
        with os.fdopen(fd, "rb") as file:
            fd = -1
            raw = file.read()
    except LauncherError:
        if fd != -1:
            os.close(fd)
        raise
    except OSError as exc:
        if fd != -1:
            os.close(fd)
        raise LauncherError("configuration", "library profile could not be read") from exc
    if b"\x00" in raw:
        raise LauncherError("configuration", "library profile contains a NUL byte")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LauncherError("configuration", "library profile must be strict UTF-8") from exc

    values: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in line:
            raise LauncherError("configuration", f"library profile line {number} is malformed")
        key, value = line.split("=", 1)
        if key != key.strip() or not KEY_RE.fullmatch(key):
            raise LauncherError("configuration", f"library profile line {number} has a malformed key")
        if key not in ALLOWED_KEYS:
            raise LauncherError("configuration", f"library profile line {number} uses an unsupported key")
        if key in values:
            raise LauncherError("configuration", f"library profile line {number} duplicates a key")
        if "\x00" in value:
            raise LauncherError("configuration", f"library profile line {number} contains a NUL byte")
        values[key] = value
    missing = sorted(REQUIRED_KEYS - values.keys())
    if missing:
        raise LauncherError("configuration", f"library profile is missing required keys: {', '.join(missing)}")
    return values


def _run_cli_with_profile(profile_values: dict[str, str], argv: list[str], environ: os._Environ[str]) -> int:
    seafile_keys = {key for key in environ if key.startswith("SEAFILE_")}
    old_values = {key: environ.get(key) for key in seafile_keys | ALLOWED_KEYS}
    preserved_optional = {key: environ[key] for key in OPTIONAL_KEYS if key in environ and key not in profile_values}
    try:
        for key in old_values:
            environ.pop(key, None)
        for key, value in preserved_optional.items():
            environ[key] = value
        for key, value in profile_values.items():
            environ[key] = value
        return cli.main(argv)
    finally:
        for key, value in old_values.items():
            if value is None:
                environ.pop(key, None)
            else:
                environ[key] = value


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if not args or args[0] in {"-h", "--help"}:
            print("usage: seafile-library [--version] [--list] PROFILE [seafile-vault command ...]")
            print("\nLaunch seafile-vault with one named library profile from ~/.config/seafile-vault/libraries.")
            return 0
        if args[0] == "--version":
            print(f"Seafile Library Launcher {__version__}")
            return 0
        config_dir = _config_dir(os.environ)
        if args[0] == "--list":
            _dump_stdout(_success({"profiles": _available_profiles(config_dir)}))
            return 0
        profile = args[0]
        command = args[1:]
        if command in ([], ["-h"], ["--help"]):
            cli.build_parser().print_help()
            return 0
        path = _profile_file(config_dir, profile)
        profile_values = _read_profile_file(path)
        return _run_cli_with_profile(profile_values, command, os.environ)
    except LauncherError as exc:
        extra = {"suggestions": exc.suggestions} if exc.suggestions is not None else {}
        _dump_stderr(_error(exc.code, str(exc), **extra))
        return EXIT_USAGE if exc.code == "usage" else EXIT_CONFIG


if __name__ == "__main__":
    raise SystemExit(main())
