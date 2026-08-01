from __future__ import annotations

import json
import sys
from typing import Any

from .cli import EXIT_CONFIG, SEARCH_DEFAULT_MAX_RESULTS, SEARCH_HARD_MAX_RESULTS, _search_results
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
    def seafile_vault_search_by_name(
        path: str = "/",
        name: str = "*",
        type_filter: str | None = None,
        max_results: int = SEARCH_DEFAULT_MAX_RESULTS,
        case_sensitive: bool = False,
    ) -> dict[str, Any]:
        """Search one directory recursively with the same safe glob rules as the CLI."""
        with _client() as client:
            base_path = client.validate_vault_path(path)
            if type_filter not in {"file", "dir", None}:
                raise ValueError("type_filter must be file or dir")
            if max_results < 1 or max_results > SEARCH_HARD_MAX_RESULTS:
                raise ValueError(f"max_results must be between 1 and {SEARCH_HARD_MAX_RESULTS}")
            remote_type = {"file": "f", "dir": "d", None: None}[type_filter]
            data = client.list_directory(base_path, recursive=True, type_filter=remote_type)
            return _search_results(
                base_path,
                data,
                pattern=name,
                type_filter=type_filter,
                max_results=max_results,
                case_sensitive=case_sensitive,
            )

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
    def seafile_vault_library_history(page: int = 1, per_page: int = 100) -> Any:
        """Show library history when SEAFILE_ACCOUNT_TOKEN is configured."""
        with _client() as client:
            return client.library_history(page=page, per_page=per_page)

    @mcp.tool()
    def seafile_vault_file_history(path: str, cursor: str | None = None) -> Any:
        """Show file history when SEAFILE_ACCOUNT_TOKEN is configured."""
        with _client() as client:
            return client.file_history(path, cursor=cursor)

    @mcp.tool()
    def seafile_vault_share_links() -> dict[str, Any]:
        """List current-library public share links when SEAFILE_ACCOUNT_TOKEN is configured."""
        with _client() as client:
            return client.list_share_links()

    @mcp.tool()
    def seafile_vault_metadata_views() -> Any:
        """List metadata views for the configured library."""
        with _client() as client:
            return client.metadata_views_list()

    @mcp.tool()
    def seafile_vault_metadata_view(view_id: str) -> Any:
        """Get one metadata view by ID."""
        with _client() as client:
            return client.metadata_view_get(view_id)

    @mcp.tool()
    def seafile_vault_metadata_records(view_id: str, start: int = 0, limit: int = 1000) -> Any:
        """List metadata records in one view."""
        with _client() as client:
            return client.metadata_records_list(view_id, start=start, limit=limit)

    @mcp.tool()
    def seafile_vault_metadata_tags_status() -> dict[str, Any]:
        """Check whether metadata tags are enabled for the configured library."""
        with _client() as client:
            return client.metadata_tags_status()

    @mcp.tool()
    def seafile_vault_metadata_tags(start: int = 0, limit: int = 1000) -> Any:
        """List metadata tags for the configured library."""
        with _client() as client:
            return client.metadata_tags_list(start=start, limit=limit)

    @mcp.tool()
    def seafile_vault_metadata_tag_files(tag_id: str) -> Any:
        """List files linked to one metadata tag."""
        with _client() as client:
            return client.metadata_tag_files(tag_id)

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
