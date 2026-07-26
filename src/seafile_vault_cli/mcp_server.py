from __future__ import annotations

import json
import sys
from typing import Any

from .cli import EXIT_CONFIG
from .client import SeafileVaultClient


def _client() -> SeafileVaultClient:
    return SeafileVaultClient.from_env()


def build_server() -> Any:
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception as exc:  # pragma: no cover - depends on optional extra
        raise RuntimeError("mcp package is required: install seafile-vault-cli[mcp]") from exc

    mcp = FastMCP("seafile-vault-cli")

    @mcp.tool()
    def seafile_vault_repo_info() -> dict[str, Any]:
        """Get metadata for the configured token-scoped Seafile library."""
        with _client() as client:
            return client.get_repo_info()

    @mcp.tool()
    def seafile_vault_list_directory(path: str = "/") -> Any:
        """List a directory in the configured Seafile library."""
        with _client() as client:
            return client.list_directory(path)

    @mcp.tool()
    def seafile_vault_read_text_file(path: str) -> str:
        """Read a UTF-8 text file, enforcing SEAFILE_MAX_READ_SIZE."""
        with _client() as client:
            return client.read_text_file(path)

    @mcp.tool()
    def seafile_vault_get_download_link(path: str) -> str:
        """Return a same-origin Seafile download link for one file."""
        with _client() as client:
            return client.get_download_link(path)

    @mcp.tool()
    def seafile_vault_create_directory(path: str) -> Any:
        """Create a directory when SEAFILE_PERMISSION_MODE=read_write."""
        with _client() as client:
            return client.create_directory(path)

    @mcp.tool()
    def seafile_vault_rename_path(path: str, new_name: str, is_directory: bool = False) -> Any:
        """Rename one file or directory when SEAFILE_PERMISSION_MODE=read_write."""
        with _client() as client:
            return client.rename_path(path, new_name, is_directory=is_directory)

    @mcp.tool()
    def seafile_vault_move_path(path: str, destination_dir: str, is_directory: bool = False) -> Any:
        """Move one file or directory when SEAFILE_PERMISSION_MODE=read_write."""
        with _client() as client:
            return client.move_path(path, destination_dir, is_directory=is_directory)

    @mcp.tool()
    def seafile_vault_delete_path(path: str, recursive: bool = False) -> Any:
        """Delete one explicit path when SEAFILE_PERMISSION_MODE=read_write."""
        with _client() as client:
            return client.delete_path(path, recursive=recursive)

    @mcp.tool()
    def seafile_vault_write_text_file(path: str, text: str, overwrite: bool = False) -> Any:
        """Write UTF-8 text when SEAFILE_PERMISSION_MODE=read_write."""
        with _client() as client:
            return client.write_text_file(path, text, overwrite=overwrite)

    @mcp.tool()
    def seafile_vault_upload_file_base64(path: str, content_base64: str, overwrite: bool = False) -> Any:
        """Upload base64 content when SEAFILE_PERMISSION_MODE=read_write."""
        with _client() as client:
            return client.upload_file_base64(path, content_base64, overwrite=overwrite)

    return mcp


def main() -> int:
    try:
        build_server().run()
    except RuntimeError as exc:
        payload = {"ok": False, "error": {"code": "configuration", "message": str(exc)}}
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return EXIT_CONFIG
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
