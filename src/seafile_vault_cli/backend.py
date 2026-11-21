"""Seafile API dialects: the repo-token API and the regular account-token user API.

Both expose the same library operations with nearly identical bodies, so the client speaks one
vocabulary (the repo-token route names) and a backend translates routes, query parameter names,
request bodies, and the few response shapes that differ.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote


def _isoformat_utc(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, UTC).isoformat(timespec="seconds")


@dataclass(frozen=True)
class RepoTokenBackend:
    """/api/v2.1/via-repo-token/ with a per-library repo token."""

    server_url: str
    token: str
    path_key = "path"
    type_key = "type"

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}

    def url(self, route: str) -> str:
        return f"{self.server_url}/api/v2.1/via-repo-token/{route.lstrip('/')}"

    def download_link_params(self, path: str) -> dict[str, str]:
        return {"path": path}

    def upload_link_params(self, parent_dir: str, *, overwrite: bool) -> dict[str, str]:
        return {"path": parent_dir, "replace": "1" if overwrite else "0"}

    def file_transfer_body(self, operation: str, destination_dir: str) -> dict[str, Any]:
        return {"operation": operation, "dst_dir": destination_dir}

    def move_directory_request(self, source_parent: str, name: str, destination_dir: str) -> tuple[str, dict[str, Any]]:
        return "move-dir/", {"src_parent_dir": source_parent, "src_dirent_name": name, "dst_parent_dir": destination_dir}

    def copy_directory_request(self, source_parent: str, name: str, destination_dir: str) -> tuple[str, dict[str, Any]]:
        return "sync-batch-copy-item/", {
            "src_parent_dir": source_parent,
            "src_dirents": [name],
            "dst_parent_dir": destination_dir,
        }

    def normalize_repo_info(self, data: Any) -> Any:
        return data

    def normalize_listing(self, data: Any) -> Any:
        return data


@dataclass(frozen=True)
class AccountTokenBackend:
    """The regular user API (/api/v2.1/repos/<id>/..., /api2/repos/<id>/...) with an account token."""

    server_url: str
    token: str
    repo_id: str
    path_key = "p"
    type_key = "t"

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Token {self.token}", "Accept": "application/json"}

    @property
    def _repo_base(self) -> str:
        return f"{self.server_url}/api/v2.1/repos/{quote(self.repo_id, safe='')}"

    def url(self, route: str) -> str:
        route = route.lstrip("/")
        if route == "repo-info/":
            return f"{self._repo_base}/"
        if route in {"dir/", "file/"} or route.startswith("metadata/"):
            return f"{self._repo_base}/{route}"
        if route == "download-link/":
            return f"{self.server_url}/api2/repos/{quote(self.repo_id, safe='')}/file/"
        if route == "upload-link/":
            return f"{self.server_url}/api2/repos/{quote(self.repo_id, safe='')}/upload-link/"
        if route in {"sync-batch-move-item/", "sync-batch-copy-item/"}:
            return f"{self.server_url}/api/v2.1/repos/{route}"
        raise ValueError(f"route has no account-token equivalent: {route}")

    def download_link_params(self, path: str) -> dict[str, str]:
        return {"p": path, "reuse": "1"}

    def upload_link_params(self, parent_dir: str, *, overwrite: bool) -> dict[str, str]:
        return {"p": parent_dir, "replace": "1" if overwrite else "0"}

    def file_transfer_body(self, operation: str, destination_dir: str) -> dict[str, Any]:
        return {"operation": operation, "dst_repo": self.repo_id, "dst_dir": destination_dir}

    def _batch_body(self, source_parent: str, name: str, destination_dir: str) -> dict[str, Any]:
        return {
            "src_repo_id": self.repo_id,
            "src_parent_dir": source_parent,
            "src_dirents": [name],
            "dst_repo_id": self.repo_id,
            "dst_parent_dir": destination_dir,
        }

    def move_directory_request(self, source_parent: str, name: str, destination_dir: str) -> tuple[str, dict[str, Any]]:
        return "sync-batch-move-item/", self._batch_body(source_parent, name, destination_dir)

    def copy_directory_request(self, source_parent: str, name: str, destination_dir: str) -> tuple[str, dict[str, Any]]:
        return "sync-batch-copy-item/", self._batch_body(source_parent, name, destination_dir)

    def normalize_repo_info(self, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        keys = ("repo_id", "repo_name", "size", "file_count", "last_modified")
        return {key: data[key] for key in keys if key in data}

    def normalize_listing(self, data: Any) -> Any:
        """Give directory entries the repo-token API shape: ISO modification times."""
        entries = data.get("dirent_list") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            return data
        normalized = []
        for entry in entries:
            if isinstance(entry, dict) and isinstance(entry.get("mtime"), int) and not isinstance(entry["mtime"], bool):
                entry = {**entry, "mtime": _isoformat_utc(entry["mtime"])}
            normalized.append(entry)
        return {**data, "dirent_list": normalized}


Backend = RepoTokenBackend | AccountTokenBackend
