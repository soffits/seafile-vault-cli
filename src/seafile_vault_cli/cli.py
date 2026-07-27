from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from . import __version__
from .client import (
    ConfigError,
    LinkSecurityError,
    LocalFileError,
    PathSecurityError,
    PermissionModeError,
    RemoteNotFoundError,
    SeafileVaultClient,
    SeafileVaultError,
    SizeLimitError,
    _parse_upload_chunk_size_text,
)

EXIT_USAGE = 2
EXIT_CONFIG = 3
EXIT_PERMISSION = 4
EXIT_SECURITY = 5
EXIT_SEAFILE = 6


class JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        _dump_stderr(_error("usage", message))
        raise SystemExit(EXIT_USAGE)


def build_parser() -> argparse.ArgumentParser:
    parser = JsonArgumentParser(
        prog="seafile-vault",
        description="Secure, non-interactive CLI for one Seafile library through a scoped repo token.",
    )
    parser.add_argument("--version", action="version", version=f"Seafile Vault CLI {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, parser_class=JsonArgumentParser)

    p_list = sub.add_parser("list", help="List a vault directory")
    p_list.add_argument("path", nargs="?", default="/")
    p_list.add_argument("--recursive", action="store_true", help="List recursively")
    p_list.add_argument("--type", choices=("file", "dir"), help="Filter entries by type")
    p_list.add_argument("--compact", action="store_true", help="Return agent-safe compact directory entries")
    sub.add_parser("repo-info", help="Show repo information")
    p_dl = sub.add_parser("download-link", help="Get a file download link")
    p_dl.add_argument("path")
    p_download = sub.add_parser("download", help="Download a remote file to a local file")
    p_download.add_argument("remote_path", metavar="REMOTE_PATH")
    p_download.add_argument("local_file", metavar="LOCAL_FILE")
    p_download.add_argument("--overwrite", action="store_true", help="Replace an existing local regular file")
    p_stat = sub.add_parser("stat", help="Show remote file metadata")
    p_stat.add_argument("path")
    p_mkdir = sub.add_parser("mkdir", help="Create a directory")
    p_mkdir.add_argument("path")
    p_mkdir.add_argument("--parents", action="store_true", help="Create missing parent directories idempotently")
    p_rename = sub.add_parser("rename", help="Rename a file or directory")
    p_rename.add_argument("path")
    p_rename.add_argument("new_name")
    p_rename.add_argument("--dir", action="store_true", help="Rename a directory instead of a file")
    p_move = sub.add_parser("move", help="Move a file or directory into a destination directory")
    p_move.add_argument("path")
    p_move.add_argument("destination_dir")
    p_move.add_argument("--dir", action="store_true", help="Move a directory instead of a file")
    p_delete = sub.add_parser("delete", help="Delete a file, or a directory with --recursive")
    p_delete.add_argument("path")
    p_delete.add_argument("--recursive", action="store_true", help="Required for directory deletion")
    p_upload = sub.add_parser("upload", help="Upload a local file to an absolute vault file path")
    p_upload.add_argument("local_file", metavar="LOCAL_FILE")
    p_upload.add_argument("remote_path", metavar="REMOTE_PATH")
    p_upload.add_argument("--overwrite", action="store_true", help="Replace an existing remote file")
    p_upload.add_argument("--direct-ip", help="Connect upload requests to this origin IP while preserving upload-link host/TLS")
    mode = p_upload.add_mutually_exclusive_group()
    mode.add_argument("--chunked", action="store_true", help="Force native Seafile multi-request chunked/resumable upload")
    mode.add_argument("--single-request", action="store_true", help="Force the existing single multipart upload request")
    p_upload.add_argument(
        "--chunk-size",
        type=_chunk_size_arg,
        metavar="SIZE",
        help="Chunk size for chunked upload, e.g. 67108864, 64MiB, or 64 MB; max 90000000 bytes",
    )
    p_upload.add_argument("--no-resume", action="store_true", help="Start chunked upload at byte 0 instead of querying uploadedBytes")
    return parser


def _chunk_size_arg(value: str) -> int:
    try:
        return _parse_upload_chunk_size_text("chunk size", value)
    except ConfigError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _success(data: Any) -> dict[str, Any]:
    return {"ok": True, "data": data}


def _error(code: str, message: str) -> dict[str, Any]:
    return {"ok": False, "error": {"code": code, "message": message}}


def _dump_stdout(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def _dump_stderr(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")), file=sys.stderr)


def _compact_list(path: str, data: Any) -> dict[str, Any]:
    entries = data.get("dirent_list") if isinstance(data, dict) else data
    if not isinstance(entries, list):
        raise SeafileVaultError("directory listing response was not a list")
    compact_entries = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name") or entry.get("obj_name")
        if not isinstance(name, str):
            continue
        raw_type = entry.get("type") or entry.get("obj_type")
        if raw_type in {"d", "directory"}:
            entry_type = "dir"
        elif raw_type == "f":
            entry_type = "file"
        else:
            entry_type = raw_type if raw_type in {"file", "dir"} else None
        item: dict[str, Any] = {"name": name}
        if entry_type is not None:
            item["type"] = entry_type
        size = entry.get("size")
        if isinstance(size, int) and not isinstance(size, bool):
            item["size"] = size
        mtime = entry["mtime"] if "mtime" in entry else entry.get("last_modified")
        if isinstance(mtime, (int, str)) and not isinstance(mtime, bool):
            item["mtime"] = mtime
        compact_entries.append(item)
    return {"path": path, "count": len(compact_entries), "entries": compact_entries}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        with SeafileVaultClient.from_env() as client:
            if args.command == "list":
                type_filter = {"file": "f", "dir": "d"}.get(args.type)
                result = client.list_directory(args.path, recursive=args.recursive, type_filter=type_filter)
                if args.compact:
                    result = _compact_list(args.path, result)
            elif args.command == "repo-info":
                result = client.get_repo_info()
            elif args.command == "download-link":
                result = client.get_download_link(args.path)
            elif args.command == "download":
                result = client.download_file_path(args.remote_path, args.local_file, overwrite=args.overwrite)
            elif args.command == "stat":
                result = client.stat_file(args.path)
            elif args.command == "mkdir":
                result = client.create_directory(args.path, parents=args.parents)
            elif args.command == "rename":
                result = client.rename_path(args.path, args.new_name, is_directory=args.dir)
            elif args.command == "move":
                result = client.move_path(args.path, args.destination_dir, is_directory=args.dir)
            elif args.command == "delete":
                result = client.delete_path(args.path, recursive=args.recursive)
            elif args.command == "upload":
                upload_mode = "chunked" if args.chunked else "single" if args.single_request else "auto"
                result = client.upload_file_path(
                    args.local_file,
                    args.remote_path,
                    overwrite=args.overwrite,
                    direct_ip=args.direct_ip,
                    upload_mode=upload_mode,
                    chunk_size=args.chunk_size,
                    resume=not args.no_resume,
                )
            else:  # pragma: no cover
                raise AssertionError(args.command)
        _dump_stdout(_success(result))
        return 0
    except PermissionModeError as exc:
        _dump_stderr(_error("permission_denied", str(exc)))
        return EXIT_PERMISSION
    except ConfigError as exc:
        _dump_stderr(_error("configuration", str(exc)))
        return EXIT_CONFIG
    except (PathSecurityError, LinkSecurityError, LocalFileError) as exc:
        name = type(exc).__name__.removesuffix("Error") or "Security"
        _dump_stderr(_error(name.lower(), str(exc)))
        return EXIT_SECURITY
    except SizeLimitError as exc:
        _dump_stderr(_error("size_limit", str(exc)))
        return EXIT_SEAFILE
    except RemoteNotFoundError as exc:
        _dump_stderr(_error("remote_not_found", str(exc)))
        return EXIT_SEAFILE
    except SeafileVaultError as exc:
        name = type(exc).__name__.removesuffix("Error") or "SeafileVault"
        _dump_stderr(_error(name.lower(), str(exc)))
        return EXIT_SEAFILE


if __name__ == "__main__":
    raise SystemExit(main())
