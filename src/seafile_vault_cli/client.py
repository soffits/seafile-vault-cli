from __future__ import annotations

import base64
import hashlib
import ipaddress
import math
import os
import re
import secrets
import stat
import subprocess
import time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Literal
from urllib.parse import quote, urljoin, urlparse

import httpx

from .lock_policy import validate_lock_expiry_seconds

DEFAULT_MAX_READ_SIZE = 1024 * 1024
DEFAULT_MAX_WRITE_SIZE = 10 * 1024 * 1024
DEFAULT_REQUEST_TIMEOUT = 30.0
DEFAULT_UPLOAD_TIMEOUT = 3600.0
DEFAULT_UPLOAD_CHUNK_SIZE = 64 * 1024 * 1024
MAX_UPLOAD_CHUNK_SIZE = 90_000_000
MAX_MULTIPART_REQUEST_BODY_SIZE = 100_000_000
CHUNK_READ_SIZE = 1024 * 1024
MAX_CHUNK_ATTEMPTS = 3
FINAL_VERIFY_ATTEMPTS = 3
DEFAULT_SHARE_EXPIRE_DAYS = 7
MAX_SHARE_EXPIRE_DAYS = 30
DEFAULT_THUMBNAIL_SIZE = 256
MAX_THUMBNAIL_SIZE = 1024
MAX_THUMBNAIL_BYTES = 1024 * 1024
METADATA_DEFAULT_LIMIT = 1000
METADATA_MAX_LIMIT = 1000
METADATA_RECORD_UPDATE_LIMIT = 1000
METADATA_JSON_MAX_BYTES = 256 * 1024
METADATA_MAX_BODY_ITEMS = 1000
METADATA_ROUTES = {
    "records": "metadata/records/",
    "views": "metadata/views/",
    "views_detail": "metadata/views/{view_id}/",
    "views_duplicate": "metadata/duplicate-view/",
    "views_move": "metadata/move-views/",
    "tags": "metadata/tags/",
    "tags_status": "metadata/tags-status/",
    "tags_links": "metadata/tags-links/",
    "file_tags": "metadata/file-tags/",
    "tag_files": "metadata/tag-files/{tag_id}/",
    "tags_files": "metadata/tags-files/",
    "merge_tags": "metadata/merge-tags/",
}
_REPO_ID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_COMMIT_ID_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_METADATA_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_CHUNK_SIZE_TEXT_RE = re.compile(r"^([0-9]+)(?:\s*([A-Za-z]+))?$")
_CHUNK_SIZE_UNITS = {
    "b": 1,
    "kb": 1000,
    "mb": 1000**2,
    "gb": 1000**3,
    "kib": 1024,
    "mib": 1024**2,
    "gib": 1024**3,
}


class SeafileVaultError(RuntimeError):
    """Base error for Seafile Vault CLI."""


class ConfigError(SeafileVaultError):
    """Configuration is missing or invalid."""


class CapabilityError(SeafileVaultError):
    """The active token set cannot perform a requested optional capability."""


class PermissionModeError(SeafileVaultError, PermissionError):
    """A write operation was attempted while permission mode is read-only."""


class PathSecurityError(SeafileVaultError, ValueError):
    """Path is outside the allowed vault path model."""


class LinkSecurityError(SeafileVaultError, ValueError):
    """A Seafile-returned URL failed safety validation."""


class SizeLimitError(SeafileVaultError, ValueError):
    """Operation exceeds configured size limits."""


class LocalFileError(SeafileVaultError, ValueError):
    """Local upload source is invalid."""


class RemoteNotFoundError(SeafileVaultError, FileNotFoundError):
    """Remote path was not found."""


class LockNotActiveError(SeafileVaultError):
    """Server reported that the requested file is not currently locked."""


class PermissionMode(StrEnum):
    READ_ONLY = "read_only"
    READ_WRITE = "read_write"


def redact_secret(text: str, *secrets: str | None) -> str:
    redacted = text or ""
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "[REDACTED]")
    return redacted


def _sanitize_upload_value(value: Any, *secrets: str | None) -> Any:
    if isinstance(value, dict):
        sanitized: dict[Any, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and any(marker in key.lower() for marker in ("url", "token", "link", "authorization")):
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = _sanitize_upload_value(item, *secrets)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_upload_value(item, *secrets) for item in value]
    if isinstance(value, str):
        return redact_secret(value, *secrets)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return None


def _strip_sensitive_metadata(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_sensitive_metadata(item)
            for key, item in value.items()
            if isinstance(key, str)
            and key.lower()
            not in {
                "account_token",
                "authorization",
                "library_key",
                "lock_owner",
                "modifier_email",
                "owner_email",
                "password",
                "repo_id",
                "repoid",
                "token",
            }
        }
    if isinstance(value, list):
        return [_strip_sensitive_metadata(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return None


def _curl_config_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r") + '"'


def _parse_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if not math.isfinite(value) or value <= 0:
        raise ConfigError(f"{name} must be positive")
    return value


def _validate_upload_chunk_size(name: str, value: int) -> int:
    value = _validate_positive_int(name, value)
    if value > MAX_UPLOAD_CHUNK_SIZE:
        raise ConfigError(f"{name} must be <= {MAX_UPLOAD_CHUNK_SIZE}")
    return value


def _parse_upload_chunk_size_text(name: str, raw: str) -> int:
    match = _CHUNK_SIZE_TEXT_RE.fullmatch(raw.strip())
    if match is None:
        raise ConfigError(f"{name} must be a positive integer with optional unit B, KB, MB, GB, KiB, MiB, or GiB")
    quantity = int(match.group(1))
    suffix = match.group(2)
    multiplier = 1
    if suffix is not None:
        multiplier = _CHUNK_SIZE_UNITS.get(suffix.lower(), 0)
        if multiplier == 0:
            raise ConfigError(f"{name} unit must be B, KB, MB, GB, KiB, MiB, or GiB")
    return _validate_upload_chunk_size(name, quantity * multiplier)


def _parse_chunk_size_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return _parse_upload_chunk_size_text(name, raw)


@dataclass
class LocalUpload:
    fd: int
    size: int

    def close(self) -> None:
        os.close(self.fd)


@dataclass
class DownloadDestination:
    parent_fd: int
    name: str

    def close(self) -> None:
        os.close(self.parent_fd)


class BoundedFileReader:
    def __init__(self, fd: int, remaining: int, *, block_size: int = CHUNK_READ_SIZE) -> None:
        self.fd = fd
        self.remaining = remaining
        self.block_size = block_size
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        if self.remaining <= 0:
            return b""
        if size is None or size < 0:
            size = self.block_size
        size = min(size, self.block_size, self.remaining)
        data = os.read(self.fd, size)
        self.remaining -= len(data)
        self.bytes_read += len(data)
        return data


class MultipartChunkStream(httpx.SyncByteStream):
    def __init__(self, *, fd: int, chunk_length: int, parent: str, name: str, overwrite: bool, boundary: str) -> None:
        self.reader = BoundedFileReader(fd, chunk_length)
        self.chunk_length = chunk_length
        replace = "1" if overwrite else "0"
        self.prefix = b"".join(
            [
                f"--{boundary}\r\n".encode("ascii"),
                _multipart_disposition("parent_dir"),
                b"\r\n\r\n",
                parent.encode("utf-8"),
                b"\r\n",
                f"--{boundary}\r\n".encode("ascii"),
                _multipart_disposition("replace"),
                b"\r\n\r\n",
                replace.encode("ascii"),
                b"\r\n",
                f"--{boundary}\r\n".encode("ascii"),
                _multipart_disposition("file", name),
                b"\r\nContent-Type: application/octet-stream\r\n\r\n",
            ]
        )
        self.suffix = f"\r\n--{boundary}--\r\n".encode("ascii")
        self.content_length = len(self.prefix) + chunk_length + len(self.suffix)

    def __iter__(self):
        yield self.prefix
        while True:
            chunk = self.reader.read()
            if not chunk:
                break
            yield chunk
        if self.reader.bytes_read != self.chunk_length:
            raise SeafileVaultError("local file ended before chunk boundary")
        yield self.suffix


def _parse_float_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number") from exc
    if not math.isfinite(value) or value <= 0:
        raise ConfigError(f"{name} must be positive")
    return value


def _parse_permission_mode(raw: str | None) -> PermissionMode:
    value = (raw or PermissionMode.READ_ONLY.value).strip()
    try:
        return PermissionMode(value)
    except ValueError as exc:
        raise ConfigError("SEAFILE_PERMISSION_MODE must be read_only or read_write") from exc


def _parse_direct_ip(raw: str | None) -> str | None:
    value = (raw or "").strip()
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ConfigError("SEAFILE_UPLOAD_DIRECT_IP must be a valid IP address") from exc
    return str(ip)


def _validate_positive_int(name: str, value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ConfigError(f"{name} must be a positive integer")
    return value


def validate_commit_id(value: str) -> str:
    if not isinstance(value, str) or _COMMIT_ID_RE.fullmatch(value) is None:
        raise ConfigError("commit ID must be a 40-character hexadecimal Seafile commit ID")
    return value.lower()


def validate_share_expire_days(value: int) -> int:
    days = _validate_positive_int("expire_days", value)
    if days > MAX_SHARE_EXPIRE_DAYS:
        raise ConfigError(f"expire_days must be <= {MAX_SHARE_EXPIRE_DAYS}")
    return days


def validate_thumbnail_size(value: int) -> int:
    size = _validate_positive_int("thumbnail_size", value)
    if size > MAX_THUMBNAIL_SIZE:
        raise ConfigError(f"thumbnail_size must be <= {MAX_THUMBNAIL_SIZE}")
    return size


def validate_metadata_id(name: str, value: str) -> str:
    if not isinstance(value, str) or _METADATA_ID_RE.fullmatch(value) is None:
        raise ConfigError(f"{name} must be 1-128 characters of ASCII letters, digits, '_' or '-'")
    return value


def validate_metadata_start(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ConfigError("start must be a non-negative integer")
    return value


def validate_metadata_limit(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1 or value > METADATA_MAX_LIMIT:
        raise ConfigError(f"limit must be between 1 and {METADATA_MAX_LIMIT}")
    return value


def validate_metadata_body_items(name: str, value: Any, *, limit: int = METADATA_MAX_BODY_ITEMS) -> list[Any]:
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{name} must be a non-empty array")
    if len(value) > limit:
        raise ConfigError(f"{name} must contain at most {limit} items")
    return value


def _validate_positive_float(name: str, value: float) -> float:
    if isinstance(value, bool):
        raise ConfigError(f"{name} must be positive")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{name} must be a number") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise ConfigError(f"{name} must be positive")
    return parsed


def _contains_ascii_control(value: str) -> bool:
    return any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)


def _default_port(scheme: str) -> int | None:
    if scheme == "https":
        return 443
    if scheme == "http":
        return 80
    return None


def _origin_port(parsed: Any) -> int | None:
    return parsed.port or _default_port(parsed.scheme)


def _curl_form_filename_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _content_disposition_filename(value: str) -> str:
    safe = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    encoded = "".join(chr(byte) if byte in safe else f"%{byte:02X}" for byte in value.encode("utf-8"))
    return f'attachment; filename="{encoded}"'


def _require_multipart_body_under_cap(content_length: int) -> None:
    if content_length >= MAX_MULTIPART_REQUEST_BODY_SIZE:
        raise ConfigError(f"multipart request body must be < {MAX_MULTIPART_REQUEST_BODY_SIZE} bytes")


def _multipart_disposition(name: str, filename: str | None = None) -> bytes:
    disposition = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        quoted_filename = filename.replace("\\", "\\\\").replace('"', '\\"')
        disposition += f'; filename="{quoted_filename}"'
    return disposition.encode("utf-8")


def _curl_resolve_part(value: str) -> str:
    return f"[{value}]" if ":" in value and not value.startswith("[") else value


def _format_curl_number(value: float) -> str:
    return f"{value:g}"


def _validated_server_url(raw: str) -> str:
    server_url = raw.strip().rstrip("/")
    parsed = urlparse(server_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.path not in {"", "/"}:
        raise ConfigError("SEAFILE_SERVER_URL must be an absolute http(s) origin URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ConfigError("SEAFILE_SERVER_URL must not contain credentials, query, or fragment")
    return server_url


@dataclass(frozen=True)
class Config:
    server_url: str
    repo_token: str
    account_token: str | None = None
    permission_mode: PermissionMode = PermissionMode.READ_ONLY
    max_read_size: int = DEFAULT_MAX_READ_SIZE
    max_write_size: int = DEFAULT_MAX_WRITE_SIZE
    request_timeout: float = DEFAULT_REQUEST_TIMEOUT
    upload_timeout: float = DEFAULT_UPLOAD_TIMEOUT
    upload_chunk_size: int = DEFAULT_UPLOAD_CHUNK_SIZE
    upload_direct_ip: str | None = None

    @classmethod
    def from_env(cls) -> Config:
        server_url = os.environ.get("SEAFILE_SERVER_URL") or ""
        repo_token = os.environ.get("SEAFILE_REPO_TOKEN") or ""
        account_token = os.environ.get("SEAFILE_ACCOUNT_TOKEN") if "SEAFILE_ACCOUNT_TOKEN" in os.environ else None
        if not server_url.strip():
            raise ConfigError("SEAFILE_SERVER_URL is required")
        if not repo_token:
            raise ConfigError("SEAFILE_REPO_TOKEN is required")
        if account_token is not None and not account_token.strip():
            raise ConfigError("SEAFILE_ACCOUNT_TOKEN must be non-empty when set")
        return cls(
            server_url=_validated_server_url(server_url),
            repo_token=repo_token,
            account_token=account_token,
            permission_mode=_parse_permission_mode(os.environ.get("SEAFILE_PERMISSION_MODE")),
            max_read_size=_parse_int_env("SEAFILE_MAX_READ_SIZE", DEFAULT_MAX_READ_SIZE),
            max_write_size=_parse_int_env("SEAFILE_MAX_WRITE_SIZE", DEFAULT_MAX_WRITE_SIZE),
            request_timeout=_parse_float_env("SEAFILE_REQUEST_TIMEOUT", DEFAULT_REQUEST_TIMEOUT),
            upload_timeout=_parse_float_env("SEAFILE_UPLOAD_TIMEOUT", DEFAULT_UPLOAD_TIMEOUT),
            upload_chunk_size=_parse_chunk_size_env("SEAFILE_UPLOAD_CHUNK_SIZE", DEFAULT_UPLOAD_CHUNK_SIZE),
            upload_direct_ip=_parse_direct_ip(os.environ.get("SEAFILE_UPLOAD_DIRECT_IP")),
        )


class SeafileVaultClient:
    """Repo-token-only Seafile client using /api/v2.1/via-repo-token endpoints."""

    def __init__(
        self,
        server_url: str,
        repo_token: str,
        *,
        account_token: str | None = None,
        permission_mode: PermissionMode | str = PermissionMode.READ_ONLY,
        max_read_size: int = DEFAULT_MAX_READ_SIZE,
        max_write_size: int = DEFAULT_MAX_WRITE_SIZE,
        timeout: float = DEFAULT_REQUEST_TIMEOUT,
        upload_timeout: float = DEFAULT_UPLOAD_TIMEOUT,
        upload_chunk_size: int = DEFAULT_UPLOAD_CHUNK_SIZE,
        upload_direct_ip: str | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.server_url = _validated_server_url(server_url)
        if not isinstance(repo_token, str) or not repo_token.strip():
            raise ConfigError("repo_token must be a non-empty string")
        if account_token is not None and (not isinstance(account_token, str) or not account_token.strip()):
            raise ConfigError("account_token must be a non-empty string when set")
        self.repo_token = repo_token
        self.account_token = account_token
        self.permission_mode = _parse_permission_mode(str(permission_mode))
        self.max_read_size = _validate_positive_int("max_read_size", max_read_size)
        self.max_write_size = _validate_positive_int("max_write_size", max_write_size)
        timeout = _validate_positive_float("timeout", timeout)
        self.upload_timeout = _validate_positive_float("upload_timeout", upload_timeout)
        self.upload_chunk_size = _validate_upload_chunk_size("upload_chunk_size", upload_chunk_size)
        self.upload_direct_ip = _parse_direct_ip(upload_direct_ip)
        self._owns_client = http_client is None
        self.http = http_client or httpx.Client(timeout=timeout)

    @classmethod
    def from_env(cls) -> SeafileVaultClient:
        cfg = Config.from_env()
        return cls(
            cfg.server_url,
            cfg.repo_token,
            account_token=cfg.account_token,
            permission_mode=cfg.permission_mode,
            max_read_size=cfg.max_read_size,
            max_write_size=cfg.max_write_size,
            timeout=cfg.request_timeout,
            upload_timeout=cfg.upload_timeout,
            upload_chunk_size=cfg.upload_chunk_size,
            upload_direct_ip=cfg.upload_direct_ip,
        )

    def close(self) -> None:
        if self._owns_client:
            self.http.close()

    def __enter__(self) -> SeafileVaultClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def require_read_write(self) -> None:
        if self.permission_mode != PermissionMode.READ_WRITE:
            raise PermissionModeError("write operation blocked: set SEAFILE_PERMISSION_MODE=read_write")

    def validate_vault_path(self, path: str) -> str:
        if not isinstance(path, str) or not path:
            raise PathSecurityError("path must be a non-empty string")
        if _contains_ascii_control(path):
            raise PathSecurityError("path must not contain ASCII control characters")
        if not path.startswith("/"):
            raise PathSecurityError("path must be absolute and start with '/'")
        if path == "/":
            return "/"
        if path.endswith("/"):
            path = path.rstrip("/")
        parts = path.split("/")
        if any(part == "" for part in parts[1:]):
            raise PathSecurityError("path must not contain empty segments")
        for part in parts[1:]:
            if part in {".", ".."}:
                raise PathSecurityError("path must not contain '.' or '..' segments")
        normalized = str(PurePosixPath(path))
        if normalized != path:
            raise PathSecurityError("path must already be normalized")
        return normalized

    def _url(self, suffix: str) -> str:
        return f"{self.server_url}/api/v2.1/via-repo-token/{suffix.lstrip('/')}"

    def _api_url(self, suffix: str) -> str:
        return f"{self.server_url}/api/v2.1/{suffix.lstrip('/')}"

    @property
    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.repo_token}", "Accept": "application/json"}

    @property
    def _account_headers(self) -> dict[str, str]:
        if self.account_token is None:
            raise CapabilityError("SEAFILE_ACCOUNT_TOKEN is required for this account-token capability")
        return {"Authorization": f"Token {self.account_token}", "Accept": "application/json"}

    def _redact(self, text: str, *secrets_to_redact: str | None) -> str:
        return redact_secret(text, self.repo_token, self.account_token, *secrets_to_redact)

    def _request(self, method: str, suffix: str, **kwargs: Any) -> httpx.Response:
        headers = dict(self._headers)
        headers.update(kwargs.pop("headers", {}) or {})
        url = self._url(suffix)
        try:
            response = self.http.request(method, url, headers=headers, **kwargs)
            response.raise_for_status()
            return response
        except httpx.HTTPStatusError as exc:
            body = exc.response.text[:1000] if exc.response is not None else ""
            status = exc.response.status_code if exc.response else "error"
            msg = f"Seafile HTTP {status}: {body}"
            raise SeafileVaultError(self._redact(msg, url)) from None
        except httpx.HTTPError as exc:
            raise SeafileVaultError(self._redact(str(exc), url)) from None

    def _metadata_capability_message(self, response: httpx.Response) -> str | None:
        body = response.text[:1000]
        lowered = body.lower()
        if response.status_code in {404, 409} and (
            "metadata module is disabled" in lowered
            or "metadata module is not enabled" in lowered
            or "tags is disabled" in lowered
            or "disabled the tags manage" in lowered
            or "tags not be used" in lowered
            or "tags table not found" in lowered
        ):
            if "tag" in lowered:
                return "metadata tags are disabled for this library; enable tags before using tag operations"
            return "metadata is disabled for this library; enable Seafile metadata before using metadata operations"
        if response.status_code == 405:
            return "this Seafile deployment does not expose the requested repo-token metadata capability"
        return None

    def _metadata_request(self, method: str, suffix: str, **kwargs: Any) -> httpx.Response:
        headers = dict(self._headers)
        headers.update(kwargs.pop("headers", {}) or {})
        url = self._url(suffix)
        try:
            response = self.http.request(method, url, headers=headers, **kwargs)
            capability_message = self._metadata_capability_message(response)
            if capability_message is not None:
                raise CapabilityError(capability_message)
            response.raise_for_status()
            return response
        except CapabilityError:
            raise
        except httpx.HTTPStatusError as exc:
            body = exc.response.text[:1000] if exc.response is not None else ""
            status = exc.response.status_code if exc.response else "error"
            msg = f"Seafile metadata HTTP {status}: {body}"
            raise SeafileVaultError(self._redact(msg, url)) from None
        except httpx.HTTPError as exc:
            raise SeafileVaultError(self._redact(str(exc), url)) from None

    def _account_request(self, method: str, suffix: str, **kwargs: Any) -> httpx.Response:
        extra_redactions = tuple(kwargs.pop("_redact_secrets", ()) or ())
        headers = dict(self._account_headers)
        headers.update(kwargs.pop("headers", {}) or {})
        url = self._api_url(suffix)
        try:
            response = self.http.request(method, url, headers=headers, **kwargs)
            response.raise_for_status()
            return response
        except httpx.HTTPStatusError as exc:
            body = exc.response.text[:1000] if exc.response is not None else ""
            status = exc.response.status_code if exc.response else "error"
            raise SeafileVaultError(self._redact(f"Seafile account HTTP {status}: {body}", url, *extra_redactions)) from None
        except httpx.HTTPError as exc:
            raise SeafileVaultError(self._redact(str(exc), url, *extra_redactions)) from None

    def _raise_stream_status(self, response: httpx.Response, context: str, *secrets_to_redact: str | None) -> None:
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError:
            message = f"Seafile {context} HTTP {response.status_code}"
            raise SeafileVaultError(self._redact(message, *secrets_to_redact)) from None

    def get_repo_info(self) -> dict[str, Any]:
        return self._request("GET", "repo-info/").json()

    def _repo_id(self) -> str:
        repo_info = self.get_repo_info()
        repo_id = repo_info.get("repo_id") if isinstance(repo_info, dict) else None
        if not isinstance(repo_id, str) or not _REPO_ID_RE.fullmatch(repo_id):
            raise SeafileVaultError("repo-info response did not include repo_id")
        return repo_id

    def _validate_page(self, name: str, value: int) -> int:
        return _validate_positive_int(name, value)

    def library_history(self, *, page: int = 1, per_page: int = 100) -> Any:
        repo_id = self._repo_id()
        response = self._account_request(
            "GET",
            f"repos/{repo_id}/history/",
            params={"page": self._validate_page("page", page), "per_page": self._validate_page("per_page", per_page)},
        )
        return _strip_sensitive_metadata(response.json())

    def file_history(self, path: str, *, cursor: str | None = None) -> Any:
        path = self._validate_non_root_path(path, "read history for")
        repo_id = self._repo_id()
        params = {"path": path}
        if cursor is not None:
            params["commit_id"] = validate_commit_id(cursor)
        response = self._account_request("GET", f"repos/{repo_id}/file/history/", params=params)
        return _strip_sensitive_metadata(response.json())

    def restore_file(self, path: str, *, commit_id: str) -> dict[str, Any]:
        return self._restore_path(path, commit_id=commit_id, is_directory=False)

    def restore_directory(self, path: str, *, commit_id: str) -> dict[str, Any]:
        return self._restore_path(path, commit_id=commit_id, is_directory=True)

    def _restore_path(self, path: str, *, commit_id: str, is_directory: bool) -> dict[str, Any]:
        self.require_read_write()
        path = self._validate_non_root_path(path, "restore")
        commit_id = validate_commit_id(commit_id)
        endpoint = "dir/" if is_directory else "file/"
        response = self._request("POST", endpoint, params={"path": path}, json={"operation": "revert", "commit_id": commit_id})
        return {
            "path": path,
            "type": "dir" if is_directory else "file",
            "commit_id": commit_id,
            "server_result": _strip_sensitive_metadata(response.json()),
        }

    def _share_items(self, data: Any) -> list[dict[str, Any]]:
        raw_items = data.get("share_links") if isinstance(data, dict) else data
        if not isinstance(raw_items, list):
            raise SeafileVaultError("share-links response was not a list")
        return [item for item in raw_items if isinstance(item, dict)]

    def _current_library_share_items(self) -> tuple[str, list[dict[str, Any]]]:
        repo_id = self._repo_id()
        data = self._account_request("GET", "share-links/").json()
        return repo_id, [item for item in self._share_items(data) if item.get("repo_id") == repo_id]

    def _public_share_output(self, item: dict[str, Any]) -> dict[str, Any]:
        safe = _strip_sensitive_metadata(item)
        if not isinstance(safe, dict):
            raise SeafileVaultError("share-link item was not an object")
        result = {key: value for key, value in safe.items() if isinstance(key, str) and key.lower() not in {"token"}}
        link = result.get("link")
        if link is not None:
            if not isinstance(link, str):
                raise LinkSecurityError("share link must be a string")
            result["link"] = self._validate_same_origin_url(link, "share link")
        return result

    def list_share_links(self) -> dict[str, Any]:
        _repo_id, items = self._current_library_share_items()
        links = [self._public_share_output(item) for item in items]
        return {"count": len(links), "links": links}

    def create_share_link(
        self,
        path: str,
        *,
        expire_days: int = DEFAULT_SHARE_EXPIRE_DAYS,
        permission: Literal["view-download", "view-only"] = "view-download",
        password: str | None = None,
    ) -> dict[str, Any]:
        self.require_read_write()
        path = self._validate_non_root_path(path, "share")
        expire_days = validate_share_expire_days(expire_days)
        permission_json = {
            "view-download": {"can_view": True, "can_download": True},
            "view-only": {"can_view": True, "can_download": False},
        }.get(permission)
        if permission_json is None:
            raise ConfigError("share permission must be view-download or view-only")
        repo_id = self._repo_id()
        payload: dict[str, Any] = {
            "repo_id": repo_id,
            "path": path,
            "expire_days": expire_days,
            "permissions": permission_json,
        }
        if password is not None:
            if not password:
                raise ConfigError("share password must be non-empty")
            payload["password"] = password
        response = self._account_request(
            "POST",
            "share-links/",
            json=payload,
            _redact_secrets=(password,) if password is not None else (),
        )
        data = response.json()
        if not isinstance(data, dict):
            raise SeafileVaultError("share-link create response was not an object")
        return self._public_share_output(data)

    def revoke_share_link(self, token: str) -> dict[str, Any]:
        self.require_read_write()
        if not isinstance(token, str) or not token:
            raise ConfigError("share token must be non-empty")
        _repo_id, items = self._current_library_share_items()
        if not any(item.get("token") == token for item in items):
            raise CapabilityError("share token does not belong to the current library")
        response = self._account_request("DELETE", f"share-links/{quote(token, safe='')}/", _redact_secrets=(token,))
        data: Any
        try:
            data = response.json()
        except ValueError:
            data = None
        return {"revoked": True, "server_result": _strip_sensitive_metadata(data)}

    def _metadata_json(
        self,
        method: str,
        route: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> Any:
        kwargs: dict[str, Any] = {}
        if params is not None:
            kwargs["params"] = params
        if json_body is not None:
            kwargs["json"] = json_body
        response = self._metadata_request(method, route, **kwargs)
        return _strip_sensitive_metadata(response.json())

    def metadata_views_list(self) -> Any:
        return self._metadata_json("GET", METADATA_ROUTES["views"])

    def metadata_view_get(self, view_id: str) -> Any:
        view_id = validate_metadata_id("view_id", view_id)
        return self._metadata_json("GET", METADATA_ROUTES["views_detail"].format(view_id=quote(view_id, safe="")))

    def metadata_records_list(self, view_id: str, *, start: int = 0, limit: int = METADATA_DEFAULT_LIMIT) -> Any:
        view_id = validate_metadata_id("view_id", view_id)
        return self._metadata_json(
            "GET",
            METADATA_ROUTES["records"],
            params={"view_id": view_id, "start": validate_metadata_start(start), "limit": validate_metadata_limit(limit)},
        )

    def metadata_records_update(self, body: dict[str, Any]) -> Any:
        self.require_read_write()
        validate_metadata_body_items("records_data", body.get("records_data"), limit=METADATA_RECORD_UPDATE_LIMIT)
        return self._metadata_json("PUT", METADATA_ROUTES["records"], json_body=body)

    def metadata_views_create(self, body: dict[str, Any]) -> Any:
        self.require_read_write()
        name = body.get("name")
        if not isinstance(name, str) or not name:
            raise ConfigError("name must be a non-empty string")
        folder_id = body.get("folder_id")
        if folder_id is not None:
            validate_metadata_id("folder_id", folder_id)
        view_type = body.get("type")
        if view_type is not None and (not isinstance(view_type, str) or not view_type):
            raise ConfigError("type must be a non-empty string when set")
        data = body.get("data")
        if data is not None and not isinstance(data, dict):
            raise ConfigError("data must be an object when set")
        return self._metadata_json("POST", METADATA_ROUTES["views"], json_body=body)

    def metadata_views_update(self, body: dict[str, Any]) -> Any:
        self.require_read_write()
        validate_metadata_id("view_id", body.get("view_id"))
        if not isinstance(body.get("view_data"), dict) or not body["view_data"]:
            raise ConfigError("view_data must be a non-empty object")
        return self._metadata_json("PUT", METADATA_ROUTES["views"], json_body=body)

    def metadata_views_delete(self, body: dict[str, Any]) -> Any:
        self.require_read_write()
        validate_metadata_id("view_id", body.get("view_id"))
        folder_id = body.get("folder_id")
        if folder_id is not None:
            validate_metadata_id("folder_id", folder_id)
        return self._metadata_json("DELETE", METADATA_ROUTES["views"], json_body=body)

    def metadata_views_duplicate(self, body: dict[str, Any]) -> Any:
        self.require_read_write()
        validate_metadata_id("view_id", body.get("view_id"))
        folder_id = body.get("folder_id")
        if folder_id is not None:
            validate_metadata_id("folder_id", folder_id)
        return self._metadata_json("POST", METADATA_ROUTES["views_duplicate"], json_body=body)

    def metadata_views_move(self, body: dict[str, Any]) -> Any:
        self.require_read_write()
        for key in ("source_view_id", "source_folder_id", "target_view_id", "target_folder_id"):
            value = body.get(key)
            if value is not None:
                validate_metadata_id(key, value)
        if not body.get("source_view_id") and not body.get("source_folder_id"):
            raise ConfigError("source_view_id or source_folder_id is required")
        if not body.get("target_view_id") and not body.get("target_folder_id"):
            raise ConfigError("target_view_id or target_folder_id is required")
        if "is_above_folder" in body and not isinstance(body["is_above_folder"], bool):
            raise ConfigError("is_above_folder must be a boolean when set")
        return self._metadata_json("POST", METADATA_ROUTES["views_move"], json_body=body)

    def metadata_tags_status(self) -> dict[str, Any]:
        try:
            data = self.metadata_tags_list(start=0, limit=1)
        except CapabilityError as exc:
            if "tags are disabled" in str(exc):
                return {"enabled": False, "message": str(exc)}
            raise
        return {"enabled": True, "sample": data}

    def metadata_tags_enable(self, *, lang: str) -> Any:
        self.require_read_write()
        if not isinstance(lang, str) or not lang:
            raise ConfigError("lang must be a non-empty string")
        return self._metadata_json("PUT", METADATA_ROUTES["tags_status"], json_body={"lang": lang})

    def metadata_tags_disable(self) -> Any:
        self.require_read_write()
        return self._metadata_json("DELETE", METADATA_ROUTES["tags_status"], json_body={})

    def metadata_tags_list(self, *, start: int = 0, limit: int = METADATA_DEFAULT_LIMIT) -> Any:
        return self._metadata_json(
            "GET",
            METADATA_ROUTES["tags"],
            params={"start": validate_metadata_start(start), "limit": validate_metadata_limit(limit)},
        )

    def metadata_tags_create(self, body: dict[str, Any]) -> Any:
        self.require_read_write()
        validate_metadata_body_items("tags_data", body.get("tags_data"))
        return self._metadata_json("POST", METADATA_ROUTES["tags"], json_body=body)

    def metadata_tags_update(self, body: dict[str, Any]) -> Any:
        self.require_read_write()
        validate_metadata_body_items("tags_data", body.get("tags_data"))
        return self._metadata_json("PUT", METADATA_ROUTES["tags"], json_body=body)

    def metadata_tags_delete(self, body: dict[str, Any]) -> Any:
        self.require_read_write()
        tag_ids = validate_metadata_body_items("tag_ids", body.get("tag_ids"))
        for tag_id in tag_ids:
            validate_metadata_id("tag_id", tag_id)
        return self._metadata_json("DELETE", METADATA_ROUTES["tags"], json_body=body)

    def metadata_tag_link_create(self, body: dict[str, Any]) -> Any:
        self.require_read_write()
        self._validate_tag_link_body(body, require_column=True)
        return self._metadata_json("POST", METADATA_ROUTES["tags_links"], json_body=body)

    def metadata_tag_link_update(self, body: dict[str, Any]) -> Any:
        self.require_read_write()
        self._validate_tag_link_body(body, require_column=False)
        return self._metadata_json("PUT", METADATA_ROUTES["tags_links"], json_body=body)

    def metadata_tag_link_delete(self, body: dict[str, Any]) -> Any:
        self.require_read_write()
        self._validate_tag_link_body(body, require_column=True)
        return self._metadata_json("DELETE", METADATA_ROUTES["tags_links"], json_body=body)

    def _validate_tag_link_body(self, body: dict[str, Any], *, require_column: bool) -> None:
        link_column_key = body.get("link_column_key")
        if require_column and (not isinstance(link_column_key, str) or not link_column_key):
            raise ConfigError("link_column_key must be a non-empty string")
        if link_column_key is not None and (not isinstance(link_column_key, str) or not link_column_key or len(link_column_key) > 128):
            raise ConfigError("link_column_key must be a non-empty string up to 128 characters when set")
        if not isinstance(body.get("row_id_map"), dict) or not body["row_id_map"]:
            raise ConfigError("row_id_map must be a non-empty object")

    def metadata_file_tags_assign(self, body: dict[str, Any]) -> Any:
        self.require_read_write()
        file_tags_data = validate_metadata_body_items("file_tags_data", body.get("file_tags_data"))
        for item in file_tags_data:
            if isinstance(item, dict) and item.get("record_id"):
                validate_metadata_id("record_id", item["record_id"])
        return self._metadata_json("PUT", METADATA_ROUTES["file_tags"], json_body=body)

    def metadata_tag_files(self, tag_id: str) -> Any:
        tag_id = validate_metadata_id("tag_id", tag_id)
        return self._metadata_json(
            "GET",
            METADATA_ROUTES["tag_files"].format(tag_id=quote(tag_id, safe="")),
        )

    def metadata_tags_files(self, body: dict[str, Any]) -> Any:
        tags_ids = validate_metadata_body_items("tags_ids", body.get("tags_ids"))
        for tag_id in tags_ids:
            validate_metadata_id("tag_id", tag_id)
        return self._metadata_json("POST", METADATA_ROUTES["tags_files"], json_body=body)

    def metadata_tags_merge(self, body: dict[str, Any]) -> Any:
        self.require_read_write()
        validate_metadata_id("target_tag_id", body.get("target_tag_id"))
        merged_tags_ids = validate_metadata_body_items("merged_tags_ids", body.get("merged_tags_ids"))
        for tag_id in merged_tags_ids:
            validate_metadata_id("tag_id", tag_id)
        return self._metadata_json("POST", METADATA_ROUTES["merge_tags"], json_body=body)

    def _get_remote_file_info(self, path: str) -> dict[str, Any] | None:
        url = self._url("file/")
        try:
            response = self.http.get(url, headers=self._headers, params={"path": path}, timeout=self.upload_timeout)
        except httpx.HTTPError as exc:
            raise SeafileVaultError(redact_secret(str(exc), self.repo_token, url)) from None
        if response.status_code == 404:
            return None
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            body = exc.response.text[:1000] if exc.response is not None else ""
            status = exc.response.status_code if exc.response else "error"
            raise SeafileVaultError(redact_secret(f"Seafile file-info HTTP {status}: {body}", self.repo_token, url)) from None
        try:
            data = response.json()
        except ValueError as exc:
            raise SeafileVaultError("file-info response was not valid JSON") from exc
        if not isinstance(data, dict):
            raise SeafileVaultError("file-info response was not an object")
        size = data.get("size")
        if not isinstance(size, int) or isinstance(size, bool):
            raise SeafileVaultError("file-info response size was not an integer")
        return data

    def stat_file(self, path: str) -> dict[str, Any]:
        path = self._validate_non_root_path(path, "stat")
        info = self._get_remote_file_info(path)
        if info is None:
            raise RemoteNotFoundError(f"remote file not found: {path}")
        return info

    def _parse_operation_response(self, response: httpx.Response, *secrets_to_redact: str | None) -> Any:
        try:
            return _sanitize_upload_value(response.json(), self.repo_token, *secrets_to_redact)
        except ValueError:
            return {"response_text": redact_secret(response.text[:1000], self.repo_token, *secrets_to_redact)}

    def _verify_remote_file_size(self, path: str, expected_size: int, *, allow_missing: bool = False) -> dict[str, Any] | None:
        info = self._get_remote_file_info(path)
        if info is None:
            if allow_missing:
                return None
            raise SeafileVaultError("remote file was not visible after final chunk")
        if info["size"] != expected_size:
            raise SeafileVaultError("remote file size did not match local file size")
        return info

    def _verify_remote_file_size_with_retries(self, path: str, expected_size: int) -> dict[str, Any]:
        last_missing = False
        for attempt in range(FINAL_VERIFY_ATTEMPTS):
            info = self._get_remote_file_info(path)
            if info is not None:
                if info["size"] != expected_size:
                    raise SeafileVaultError("remote file size did not match local file size")
                return info
            last_missing = True
            if attempt + 1 < FINAL_VERIFY_ATTEMPTS:
                time.sleep(0.05 * (attempt + 1))
        if last_missing:
            raise SeafileVaultError("remote file was not visible after final chunk")
        raise SeafileVaultError("remote file verification failed")

    def _get_uploaded_bytes(self, *, repo_id: str, parent: str, name: str, total: int) -> int | None:
        url = self._api_url(f"repos/{repo_id}/file-uploaded-bytes/")
        try:
            response = self.http.get(
                url,
                headers=self._headers,
                params={"parent_dir": parent, "file_name": name},
                timeout=self.upload_timeout,
            )
        except httpx.HTTPError as exc:
            raise SeafileVaultError(redact_secret(str(exc), self.repo_token, url)) from None
        if response.status_code in {401, 403, 404, 405, 501}:
            return None
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            body = exc.response.text[:1000] if exc.response is not None else ""
            status = exc.response.status_code if exc.response else "error"
            raise SeafileVaultError(redact_secret(f"Seafile resume HTTP {status}: {body}", self.repo_token, url)) from None
        try:
            data = response.json()
        except ValueError as exc:
            raise SeafileVaultError("resume response was not valid JSON") from exc
        uploaded = data.get("uploadedBytes") if isinstance(data, dict) else None
        if not isinstance(uploaded, int) or isinstance(uploaded, bool):
            raise SeafileVaultError("resume response uploadedBytes was not an integer")
        if uploaded < 0 or uploaded > total:
            raise SeafileVaultError("resume response uploadedBytes was outside local file size")
        return uploaded

    def list_directory(
        self,
        path: str = "/",
        *,
        recursive: bool = False,
        type_filter: str | None = None,
        with_thumbnail: bool = False,
        thumbnail_size: int | None = None,
    ) -> Any:
        path = self.validate_vault_path(path)
        params: dict[str, str] = {"path": path}
        if recursive:
            params["recursive"] = "1"
        if type_filter:
            if type_filter not in {"f", "d"}:
                raise ValueError("type_filter must be 'f' or 'd'")
            params["type"] = type_filter
        if with_thumbnail:
            params["with_thumbnail"] = "true"
            if thumbnail_size is not None:
                params["thumbnail_size"] = str(validate_thumbnail_size(thumbnail_size))
        return self._request("GET", "dir/", params=params).json()

    def _directory_entries(self, data: Any) -> list[dict[str, Any]]:
        entries = data.get("dirent_list") if isinstance(data, dict) else data
        if not isinstance(entries, list):
            raise SeafileVaultError("directory listing response was not a list")
        normalized = []
        for entry in entries:
            if isinstance(entry, dict):
                normalized.append(entry)
        return normalized

    def _entry_name(self, entry: dict[str, Any]) -> str | None:
        name = entry.get("name") or entry.get("obj_name")
        return name if isinstance(name, str) else None

    def _entry_type(self, entry: dict[str, Any]) -> str | None:
        raw = entry.get("type") or entry.get("obj_type")
        if raw in {"dir", "d", "directory"}:
            return "dir"
        if raw in {"file", "f"}:
            return "file"
        return raw if isinstance(raw, str) else None

    def _find_exact_child(self, parent: str, name: str) -> dict[str, Any] | None:
        for entry in self._directory_entries(self.list_directory(parent)):
            if self._entry_name(entry) == name:
                return entry
        return None

    def _create_directory_unchecked(self, path: str, name: str) -> Any:
        result = self._request("POST", "dir/", params={"path": path}, json={"operation": "mkdir"}).json()
        if not isinstance(result, dict):
            raise SeafileVaultError("directory create response was not an object")
        reported_name = result.get("obj_name")
        if not isinstance(reported_name, str) or not reported_name:
            raise SeafileVaultError("directory create response did not include obj_name")
        if reported_name != name:
            try:
                self.delete_path(f"{path.rpartition('/')[0] or '/'}/{reported_name}".replace("//", "/"), recursive=True)
            except SeafileVaultError:
                pass
            raise SeafileVaultError("directory create response reported a different name")
        return result

    def create_directory(self, path: str, *, parents: bool = False) -> Any:
        self.require_read_write()
        path = self.validate_vault_path(path)
        if path == "/":
            raise PathSecurityError("cannot create root directory")
        if parents:
            created: list[str] = []
            skipped: list[str] = []
            current = "/"
            for segment in path.strip("/").split("/"):
                next_path = f"/{segment}" if current == "/" else f"{current}/{segment}"
                entry = self._find_exact_child(current, segment)
                if entry is not None:
                    if self._entry_type(entry) != "dir":
                        raise SeafileVaultError(f"remote path segment is not a directory: {next_path}")
                    skipped.append(next_path)
                else:
                    self._create_directory_unchecked(next_path, segment)
                    created.append(next_path)
                current = next_path
            return {"path": path, "created": created, "skipped": skipped}

        parent, name = self._split_parent_name(path)
        if self._find_exact_child(parent, name) is not None:
            raise SeafileVaultError(f"remote path already exists: {path}")
        result = self._create_directory_unchecked(path, name)
        return result

    def _validate_non_root_path(self, path: str, operation: str) -> str:
        path = self.validate_vault_path(path)
        if path == "/":
            raise PathSecurityError(f"cannot {operation} root path")
        return path

    def _validate_name_segment(self, name: str) -> str:
        if not isinstance(name, str) or not name:
            raise PathSecurityError("name must be a non-empty string")
        if _contains_ascii_control(name):
            raise PathSecurityError("name must not contain ASCII control characters")
        if "/" in name:
            raise PathSecurityError("name must not contain '/'")
        if name in {".", ".."}:
            raise PathSecurityError("name must not be '.' or '..'")
        return name

    def rename_path(self, path: str, new_name: str, *, is_directory: bool = False) -> Any:
        self.require_read_write()
        path = self._validate_non_root_path(path, "rename")
        new_name = self._validate_name_segment(new_name)
        endpoint = "dir/" if is_directory else "file/"
        return self._request(
            "POST",
            endpoint,
            params={"path": path},
            json={"operation": "rename", "newname": new_name},
        ).json()

    def move_path(self, path: str, destination_dir: str, *, is_directory: bool = False) -> Any:
        self.require_read_write()
        path = self._validate_non_root_path(path, "move")
        destination_dir = self.validate_vault_path(destination_dir)
        if is_directory:
            src_parent_dir, src_dirent_name = self._split_parent_name(path)
            return self._request(
                "POST",
                "move-dir/",
                json={
                    "src_parent_dir": src_parent_dir,
                    "src_dirent_name": src_dirent_name,
                    "dst_parent_dir": destination_dir,
                },
            ).json()
        return self._request(
            "POST",
            "file/",
            params={"path": path},
            json={"operation": "move", "dst_dir": destination_dir},
        ).json()

    def _normalize_file_operation_metadata(self, source_path: str, destination_dir: str, data: Any) -> dict[str, Any]:
        metadata = _strip_sensitive_metadata(data)
        result: dict[str, Any] = {"source_path": source_path, "destination_dir": destination_dir, "metadata": metadata}
        if isinstance(metadata, dict):
            name = metadata.get("name") or metadata.get("obj_name")
            if isinstance(name, str) and name:
                name = self._validate_name_segment(name)
                result["destination_name"] = name
                result["destination_path"] = f"/{name}" if destination_dir == "/" else f"{destination_dir}/{name}"
        return result

    def copy_file(self, source_path: str, destination_dir: str) -> dict[str, Any]:
        self.require_read_write()
        source_path = self._validate_non_root_path(source_path, "copy")
        destination_dir = self.validate_vault_path(destination_dir)
        response = self._request(
            "POST",
            "file/",
            params={"path": source_path},
            json={"operation": "copy", "dst_dir": destination_dir},
        )
        return self._normalize_file_operation_metadata(source_path, destination_dir, response.json())

    def copy_directory(self, source_path: str, destination_dir: str) -> dict[str, Any]:
        self.require_read_write()
        source_path = self._validate_non_root_path(source_path, "copy")
        destination_dir = self.validate_vault_path(destination_dir)
        source_parent, source_name = self._split_file_path(source_path)
        if destination_dir == source_parent:
            raise PathSecurityError("directory copy destination must differ from the source parent directory")
        if destination_dir == source_path or destination_dir.startswith(f"{source_path}/"):
            raise PathSecurityError("cannot copy a directory into itself or one of its descendants")
        response = self._request(
            "POST",
            "sync-batch-copy-item/",
            json={
                "src_parent_dir": source_parent,
                "src_dirents": [source_name],
                "dst_parent_dir": destination_dir,
            },
        )
        return {
            "source_path": source_path,
            "destination_directory": destination_dir,
            "destination_path": f"/{source_name}" if destination_dir == "/" else f"{destination_dir}/{source_name}",
            "type": "dir",
            "server_result": _strip_sensitive_metadata(response.json()),
        }

    def copy_path(self, source_path: str, destination_dir: str, *, is_directory: bool = False) -> dict[str, Any]:
        if is_directory:
            return self.copy_directory(source_path, destination_dir)
        return self.copy_file(source_path, destination_dir)

    def lock_file(self, path: str, expires_seconds: int) -> Any:
        self.require_read_write()
        path = self._validate_non_root_path(path, "lock")
        try:
            expires_seconds = validate_lock_expiry_seconds("expires_seconds", expires_seconds)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
        return self._put_file_operation(path, {"operation": "lock", "expire": expires_seconds}, context="lock")

    def unlock_file(self, path: str) -> Any:
        self.require_read_write()
        path = self._validate_non_root_path(path, "unlock")
        return self._put_file_operation(path, {"operation": "unlock"}, context="unlock", detect_not_locked=True)

    def _put_file_operation(
        self,
        path: str,
        payload: dict[str, Any],
        *,
        context: str,
        detect_not_locked: bool = False,
    ) -> Any:
        url = self._url("file/")
        try:
            response = self.http.put(url, headers=self._headers, params={"path": path}, json=payload)
        except httpx.HTTPError as exc:
            raise SeafileVaultError(redact_secret(str(exc), self.repo_token, url)) from None
        if response.status_code == 404:
            raise RemoteNotFoundError(f"remote file not found: {path}")
        if detect_not_locked and response.status_code in {400, 409}:
            body = response.text[:1000]
            lowered = body.lower()
            if "not lock" in lowered or "unlocked" in lowered or "unlock" in lowered:
                raise LockNotActiveError(f"remote file is not locked: {path}")
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            body = exc.response.text[:1000] if exc.response is not None else ""
            status = exc.response.status_code if exc.response else "error"
            raise SeafileVaultError(redact_secret(f"Seafile {context} HTTP {status}: {body}", self.repo_token, url)) from None
        return self._parse_operation_response(response, url)

    def delete_path(self, path: str, *, recursive: bool = False) -> Any:
        self.require_read_write()
        path = self._validate_non_root_path(path, "delete")
        endpoint = "dir/" if recursive else "file/"
        return self._request("DELETE", endpoint, params={"path": path}).json()

    def get_download_link(self, path: str) -> str:
        path = self.validate_vault_path(path)
        if path == "/":
            raise PathSecurityError("download link requires a file path")
        url = self._url("download-link/")
        try:
            response = self.http.get(url, headers=self._headers, params={"path": path})
        except httpx.HTTPError as exc:
            raise SeafileVaultError(redact_secret(str(exc), self.repo_token, url)) from None
        if response.status_code == 404:
            raise RemoteNotFoundError(f"remote file not found: {path}")
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            body = exc.response.text[:1000] if exc.response is not None else ""
            status = exc.response.status_code if exc.response else "error"
            raise SeafileVaultError(redact_secret(f"Seafile download-link HTTP {status}: {body}", self.repo_token, url)) from None
        data = response.json()
        if not isinstance(data, str):
            raise SeafileVaultError("download-link response was not a string")
        return self.validate_download_url(data)

    def _open_download_parent(self, local_path: str | os.PathLike[str]) -> DownloadDestination:
        path = Path(local_path)
        if not path.name:
            raise LocalFileError("download destination must include a file name")
        parent = path.parent
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        try:
            parent_fd = os.open(parent, flags)
        except OSError as exc:
            raise LocalFileError(f"destination parent is not accessible: {exc.strerror or exc}") from None
        try:
            parent_stat = os.fstat(parent_fd)
            if not stat.S_ISDIR(parent_stat.st_mode):
                raise LocalFileError("destination parent must be a real directory")
        except Exception:
            os.close(parent_fd)
            raise
        return DownloadDestination(parent_fd=parent_fd, name=path.name)

    def _validate_download_destination(self, destination: DownloadDestination, *, overwrite: bool) -> None:
        try:
            dst_lstat = os.stat(destination.name, dir_fd=destination.parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise LocalFileError(f"destination is not accessible: {exc.strerror or exc}") from None
        if stat.S_ISLNK(dst_lstat.st_mode):
            raise LocalFileError("destination must not be a symlink")
        if not overwrite:
            raise LocalFileError("destination already exists; pass --overwrite to replace it")
        if not stat.S_ISREG(dst_lstat.st_mode):
            raise LocalFileError("destination overwrite target must be a regular file")

    def _write_all(self, fd: int, data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise LocalFileError("download destination write made no progress")
            view = view[written:]

    def download_file_path(self, remote_path: str, local_path: str | os.PathLike[str], *, overwrite: bool = False) -> dict[str, Any]:
        remote_path = self._validate_non_root_path(remote_path, "download")
        destination = self._open_download_parent(local_path)
        fd: int | None = None
        link: str | None = None
        tmp_name: str | None = None
        total = 0
        digest = hashlib.sha256()
        try:
            self._validate_download_destination(destination, overwrite=overwrite)
            link = self.get_download_link(remote_path)
            tmp_name = f".{destination.name}.seafile-vault-{secrets.token_hex(16)}.tmp"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(tmp_name, flags, 0o600, dir_fd=destination.parent_fd)
            with self.http.stream("GET", link, follow_redirects=False) as resp:
                self._raise_stream_status(resp, "download", link)
                content_length = resp.headers.get("content-length")
                declared_size: int | None = None
                if content_length is not None:
                    try:
                        declared_size = int(content_length)
                    except ValueError as exc:
                        raise SeafileVaultError("download response content-length was not an integer") from exc
                    if declared_size < 0:
                        raise SeafileVaultError("download response content-length was negative")
                    if declared_size > self.max_read_size:
                        raise SizeLimitError(f"file exceeds max read size ({self.max_read_size} bytes)")
                for chunk in resp.iter_bytes():
                    if total + len(chunk) > self.max_read_size:
                        raise SizeLimitError(f"file exceeds max read size ({self.max_read_size} bytes)")
                    self._write_all(fd, chunk)
                    total += len(chunk)
                    digest.update(chunk)
                if declared_size is not None and total != declared_size:
                    raise SeafileVaultError("download response size did not match content-length")
            os.fsync(fd)
            os.close(fd)
            fd = None
            if overwrite:
                self._validate_download_destination(destination, overwrite=True)
                os.replace(tmp_name, destination.name, src_dir_fd=destination.parent_fd, dst_dir_fd=destination.parent_fd)
            else:
                os.link(
                    tmp_name,
                    destination.name,
                    src_dir_fd=destination.parent_fd,
                    dst_dir_fd=destination.parent_fd,
                    follow_symlinks=False,
                )
                os.unlink(tmp_name, dir_fd=destination.parent_fd)
            os.fsync(destination.parent_fd)
            return {
                "remote_path": remote_path,
                "local_name": destination.name,
                "size": total,
                "sha256": digest.hexdigest(),
                "overwrite": overwrite,
            }
        except httpx.HTTPError as exc:
            raise SeafileVaultError(redact_secret(str(exc), self.repo_token, link)) from None
        except RemoteNotFoundError:
            raise
        except OSError as exc:
            raise LocalFileError(f"download destination failed: {exc.strerror or exc}") from None
        finally:
            if fd is not None:
                os.close(fd)
            if tmp_name is not None:
                try:
                    os.unlink(tmp_name, dir_fd=destination.parent_fd)
                except FileNotFoundError:
                    pass
            destination.close()

    def _thumbnail_api_url(self, remote_path: str, size: int) -> str:
        repo_id = self._repo_id()
        base = f"{self.server_url}/api2/repos/{quote(repo_id, safe='')}/thumbnail/"
        return str(httpx.URL(base, params={"p": remote_path, "size": str(size)}))

    def _redirect_target(self, current_url: str, response: httpx.Response, thumbnail_url: str) -> str:
        location = response.headers.get("location")
        if not location:
            raise SeafileVaultError("thumbnail redirect did not include a location")
        target = urljoin(current_url, location)
        try:
            return self._validate_same_origin_url(target, "thumbnail redirect")
        except LinkSecurityError as exc:
            raise LinkSecurityError(self._redact(str(exc), thumbnail_url, target)) from None

    def download_thumbnail_path(
        self,
        remote_path: str,
        local_path: str | os.PathLike[str],
        *,
        size: int = DEFAULT_THUMBNAIL_SIZE,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        remote_path = self._validate_non_root_path(remote_path, "thumbnail")
        size = validate_thumbnail_size(size)
        account_headers = self._account_headers
        thumbnail_url = self._thumbnail_api_url(remote_path, size)
        destination = self._open_download_parent(local_path)
        fd: int | None = None
        tmp_name: str | None = None
        total = 0
        content_type = ""
        try:
            self._validate_download_destination(destination, overwrite=overwrite)
            tmp_name = f".{destination.name}.seafile-vault-{secrets.token_hex(16)}.tmp"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(tmp_name, flags, 0o600, dir_fd=destination.parent_fd)
            current_url = thumbnail_url
            for _redirect in range(6):
                with self.http.stream("GET", current_url, headers=account_headers, follow_redirects=False) as resp:
                    if resp.status_code in {301, 302, 303, 307, 308}:
                        current_url = self._redirect_target(current_url, resp, thumbnail_url)
                        continue
                    try:
                        self._validate_same_origin_url(str(resp.url), "thumbnail final")
                    except LinkSecurityError as exc:
                        raise LinkSecurityError(self._redact(str(exc), thumbnail_url, str(resp.url))) from None
                    if resp.status_code in {401, 403}:
                        raise CapabilityError("account token could not authenticate server thumbnail route")
                    self._raise_stream_status(resp, "thumbnail", thumbnail_url)
                    content_type = resp.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                    if not content_type.startswith("image/"):
                        if "html" in content_type:
                            raise CapabilityError("thumbnail route returned HTML instead of an image")
                        raise SeafileVaultError("thumbnail response content type was not image/*")
                    declared_size: int | None = None
                    content_length = resp.headers.get("content-length")
                    if content_length is not None:
                        try:
                            declared_size = int(content_length)
                        except ValueError as exc:
                            raise SeafileVaultError("thumbnail response content-length was not an integer") from exc
                        if declared_size < 0:
                            raise SeafileVaultError("thumbnail response content-length was negative")
                        if declared_size > MAX_THUMBNAIL_BYTES:
                            raise SizeLimitError(f"thumbnail exceeds max size ({MAX_THUMBNAIL_BYTES} bytes)")
                    for chunk in resp.iter_bytes():
                        if total + len(chunk) > MAX_THUMBNAIL_BYTES:
                            raise SizeLimitError(f"thumbnail exceeds max size ({MAX_THUMBNAIL_BYTES} bytes)")
                        self._write_all(fd, chunk)
                        total += len(chunk)
                    if declared_size is not None and total != declared_size:
                        raise SeafileVaultError("thumbnail response length did not match content-length")
                    break
            else:
                raise SeafileVaultError("thumbnail redirect limit exceeded")
            os.fsync(fd)
            os.close(fd)
            fd = None
            if overwrite:
                self._validate_download_destination(destination, overwrite=True)
                os.replace(tmp_name, destination.name, src_dir_fd=destination.parent_fd, dst_dir_fd=destination.parent_fd)
            else:
                os.link(
                    tmp_name,
                    destination.name,
                    src_dir_fd=destination.parent_fd,
                    dst_dir_fd=destination.parent_fd,
                    follow_symlinks=False,
                )
                os.unlink(tmp_name, dir_fd=destination.parent_fd)
            os.fsync(destination.parent_fd)
            return {
                "remote_path": remote_path,
                "local_path": os.fspath(Path(local_path)),
                "byte_count": total,
                "content_type": content_type,
                "requested_size": size,
            }
        except httpx.HTTPError as exc:
            raise SeafileVaultError(self._redact(str(exc), thumbnail_url)) from None
        except (RemoteNotFoundError, CapabilityError, LinkSecurityError, SizeLimitError):
            raise
        except OSError as exc:
            raise LocalFileError(f"thumbnail destination failed: {exc.strerror or exc}") from None
        finally:
            if fd is not None:
                os.close(fd)
            if tmp_name is not None:
                try:
                    os.unlink(tmp_name, dir_fd=destination.parent_fd)
                except FileNotFoundError:
                    pass
            destination.close()

    def validate_download_url(self, url: str) -> str:
        return self._validate_same_origin_url(url, "download")

    def _validate_upload_url(self, url: str) -> str:
        return self._validate_same_origin_url(url, "upload")

    def _validate_same_origin_url(self, url: str, kind: str) -> str:
        parsed = urlparse(url)
        server = urlparse(self.server_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or not parsed.hostname:
            raise LinkSecurityError(f"{kind} URL must be absolute http(s)")
        if parsed.username or parsed.password:
            raise LinkSecurityError(f"{kind} URL must not contain credentials")
        if parsed.scheme != server.scheme:
            raise LinkSecurityError(f"{kind} URL scheme must match SEAFILE_SERVER_URL")
        if parsed.hostname != server.hostname:
            raise LinkSecurityError(f"{kind} URL host must match SEAFILE_SERVER_URL")
        if _origin_port(parsed) != _origin_port(server):
            raise LinkSecurityError(f"{kind} URL port must match SEAFILE_SERVER_URL")
        return url

    def read_text_file(self, path: str, *, encoding: str = "utf-8") -> str:
        return self.read_file_bytes(path).decode(encoding)

    def read_file_bytes(self, path: str) -> bytes:
        link = self.get_download_link(path)
        try:
            with self.http.stream("GET", link, follow_redirects=False) as resp:
                self._raise_stream_status(resp, "download", link)
                content_length = resp.headers.get("content-length")
                if content_length is not None:
                    try:
                        declared_size = int(content_length)
                    except ValueError as exc:
                        raise SeafileVaultError("download response content-length was not an integer") from exc
                    if declared_size < 0:
                        raise SeafileVaultError("download response content-length was negative")
                    if declared_size > self.max_read_size:
                        raise SizeLimitError(f"file exceeds max read size ({self.max_read_size} bytes)")
                chunks: list[bytes] = []
                total = 0
                for chunk in resp.iter_bytes():
                    total += len(chunk)
                    if total > self.max_read_size:
                        raise SizeLimitError(f"file exceeds max read size ({self.max_read_size} bytes)")
                    chunks.append(chunk)
                return b"".join(chunks)
        except httpx.HTTPError as exc:
            raise SeafileVaultError(redact_secret(str(exc), self.repo_token, link)) from None

    def read_file_base64(self, path: str) -> str:
        return base64.b64encode(self.read_file_bytes(path)).decode("ascii")

    def _split_file_path(self, path: str) -> tuple[str, str]:
        path = self.validate_vault_path(path)
        if path == "/":
            raise PathSecurityError("file path cannot be root")
        return self._split_parent_name(path)

    def _split_parent_name(self, path: str) -> tuple[str, str]:
        parent, _, name = path.rpartition("/")
        parent = parent or "/"
        if not name:
            raise PathSecurityError("path name is required")
        return parent, name

    def _get_upload_link(self, parent_dir: str, *, overwrite: bool) -> str:
        params = {"path": parent_dir, "replace": "1" if overwrite else "0"}
        data = self._request("GET", "upload-link/", params=params).json()
        if not isinstance(data, str):
            raise SeafileVaultError("upload-link response was not a string")
        return data

    def _upload_result(
        self,
        *,
        remote_path: str,
        parent: str,
        name: str,
        size: int,
        overwrite: bool,
        direct_ip: str | None,
        upload_mode: str = "single",
        chunk_size: int | None = None,
        chunks_sent: int | None = None,
        resumed_from: int | None = None,
        resume_supported: bool | None = None,
        final_result: Any = None,
    ) -> dict[str, Any]:
        result = {
            "remote_path": remote_path,
            "remote_parent_dir": parent,
            "remote_name": name,
            "size": size,
            "overwrite": overwrite,
            "direct_origin": direct_ip is not None,
            "upload_mode": upload_mode,
        }
        if upload_mode == "chunked":
            result.update(
                {
                    "chunk_size": chunk_size,
                    "chunks_sent": chunks_sent,
                    "resumed_from": resumed_from,
                    "resume_supported": resume_supported,
                    "final_result": final_result,
                }
            )
        return result

    def _parse_upload_response(self, response: httpx.Response, upload_link: str) -> Any:
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            body = exc.response.text[:1000] if exc.response is not None else ""
            status = exc.response.status_code if exc.response else "error"
            msg = f"Seafile upload HTTP {status}: {body}"
            raise SeafileVaultError(redact_secret(msg, self.repo_token, upload_link)) from None
        try:
            return _sanitize_upload_value(response.json(), self.repo_token, upload_link)
        except ValueError:
            return {"response_text": redact_secret(response.text[:1000], self.repo_token, upload_link)}

    def _parse_chunk_response(self, response: httpx.Response, upload_link: str, *, final: bool) -> Any:
        data = self._parse_upload_response(response, upload_link)
        if final:
            return data
        if data != {"success": True}:
            raise SeafileVaultError("intermediate chunk response was not success")
        return data

    def _is_transient_upload_error(self, exc: Exception) -> bool:
        if isinstance(exc, httpx.HTTPStatusError):
            return exc.response.status_code >= 500
        return isinstance(exc, httpx.TransportError)

    def _safe_final_result(self, result: Any) -> Any:
        if isinstance(result, dict):
            return {
                key: value
                for key, value in result.items()
                if isinstance(key, str) and "url" not in key.lower() and "token" not in key.lower() and key.lower() not in {"link"}
            }
        if isinstance(result, list):
            return [self._safe_final_result(item) for item in result]
        if isinstance(result, (str, int, float, bool)) or result is None:
            return result
        return None

    def upload_file_bytes(self, path: str, data: bytes, *, overwrite: bool = False) -> Any:
        self.require_read_write()
        if len(data) > self.max_write_size:
            raise SizeLimitError(f"file exceeds max write size ({self.max_write_size} bytes)")
        parent, name = self._split_file_path(path)
        upload_link = self._validate_upload_url(self._get_upload_link(parent, overwrite=overwrite))
        form = {"parent_dir": parent, "replace": "1" if overwrite else "0"}
        files = {"file": (name, data)}
        try:
            response = self.http.post(upload_link, data=form, files=files, timeout=self.upload_timeout)
            return self._parse_upload_response(response, upload_link)
        except httpx.HTTPError as exc:
            raise SeafileVaultError(redact_secret(str(exc), self.repo_token, upload_link)) from None

    def _open_local_upload_file(self, local_path: str | os.PathLike[str]) -> LocalUpload:
        path = Path(local_path)
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            lst = path.lstat()
            fd = os.open(path, flags)
        except OSError as exc:
            raise LocalFileError(f"local file is not accessible: {exc.strerror or exc}") from None
        try:
            fst = os.fstat(fd)
        except OSError:
            os.close(fd)
            raise
        if stat.S_ISLNK(lst.st_mode):
            os.close(fd)
            raise LocalFileError("local path must not be a symlink")
        if (lst.st_dev, lst.st_ino) != (fst.st_dev, fst.st_ino):
            os.close(fd)
            raise LocalFileError("local file changed while opening")
        if not stat.S_ISREG(fst.st_mode):
            os.close(fd)
            raise LocalFileError("local path must be an existing regular file")
        if fst.st_size > self.max_write_size:
            os.close(fd)
            raise SizeLimitError(f"file exceeds max write size ({self.max_write_size} bytes)")
        return LocalUpload(fd=fd, size=fst.st_size)

    def upload_file_path(
        self,
        local_path: str | os.PathLike[str],
        remote_path: str,
        *,
        overwrite: bool = False,
        direct_ip: str | None = None,
        upload_mode: Literal["auto", "single", "chunked"] = "auto",
        chunk_size: int | None = None,
        resume: bool = True,
    ) -> dict[str, Any]:
        self.require_read_write()
        if upload_mode not in {"auto", "single", "chunked"}:
            raise ConfigError("upload_mode must be auto, single, or chunked")
        effective_chunk_size = self.upload_chunk_size if chunk_size is None else _validate_upload_chunk_size("chunk_size", chunk_size)
        local = self._open_local_upload_file(local_path)
        try:
            parent, name = self._split_file_path(remote_path)
            direct_ip = _parse_direct_ip(direct_ip) or self.upload_direct_ip
            if direct_ip is not None and upload_mode == "chunked":
                raise ConfigError("--chunked cannot be combined with direct-origin upload")
            selected_mode = (
                "chunked"
                if local.size > 0
                and (upload_mode == "chunked" or (upload_mode == "auto" and direct_ip is None and local.size > effective_chunk_size))
                else "single"
            )
            upload_link = self._validate_upload_url(self._get_upload_link(parent, overwrite=overwrite))
            final_result = None
            chunks_sent = None
            resumed_from = None
            resume_supported = None
            if selected_mode == "chunked":
                chunked_result = self._upload_file_path_chunked(
                    local,
                    parent=parent,
                    name=name,
                    overwrite=overwrite,
                    upload_link=upload_link,
                    chunk_size=effective_chunk_size,
                    resume=resume,
                    remote_path=remote_path,
                )
                final_result = chunked_result["final_result"]
                chunks_sent = chunked_result["chunks_sent"]
                resumed_from = chunked_result["resumed_from"]
                resume_supported = chunked_result["resume_supported"]
            elif direct_ip is not None:
                self._upload_file_path_direct(
                    local,
                    parent=parent,
                    name=name,
                    overwrite=overwrite,
                    upload_link=upload_link,
                    direct_ip=direct_ip,
                )
            else:
                final_result = self._upload_file_path_httpx(local, parent=parent, name=name, overwrite=overwrite, upload_link=upload_link)
            return self._upload_result(
                remote_path=remote_path,
                parent=parent,
                name=name,
                size=local.size,
                overwrite=overwrite,
                direct_ip=direct_ip,
                upload_mode=selected_mode,
                chunk_size=effective_chunk_size if selected_mode == "chunked" else None,
                chunks_sent=chunks_sent,
                resumed_from=resumed_from,
                resume_supported=resume_supported,
                final_result=self._safe_final_result(final_result),
            )
        finally:
            local.close()

    def _upload_file_path_httpx(self, local: LocalUpload, *, parent: str, name: str, overwrite: bool, upload_link: str) -> Any:
        try:
            os.lseek(local.fd, 0, os.SEEK_SET)
            boundary = "seafile-vault-" + secrets.token_hex(16)
            stream = MultipartChunkStream(
                fd=local.fd,
                chunk_length=local.size,
                parent=parent,
                name=name,
                overwrite=overwrite,
                boundary=boundary,
            )
            _require_multipart_body_under_cap(stream.content_length)
            headers = {
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Content-Length": str(stream.content_length),
            }
            response = self.http.post(upload_link, content=stream, headers=headers, timeout=self.upload_timeout)
            return self._parse_upload_response(response, upload_link)
        except httpx.HTTPError as exc:
            raise SeafileVaultError(redact_secret(str(exc), self.repo_token, upload_link)) from None

    def _upload_file_path_chunked(
        self,
        local: LocalUpload,
        *,
        parent: str,
        name: str,
        overwrite: bool,
        upload_link: str,
        chunk_size: int,
        resume: bool,
        remote_path: str,
    ) -> dict[str, Any]:
        repo_id = self._repo_id()
        uploaded = 0
        resume_supported = False
        if resume:
            uploaded_or_none = self._get_uploaded_bytes(repo_id=repo_id, parent=parent, name=name, total=local.size)
            if uploaded_or_none is not None:
                resume_supported = True
                uploaded = uploaded_or_none
        if uploaded == local.size:
            info = self._verify_remote_file_size(remote_path, local.size, allow_missing=True)
            if info is not None:
                return {
                    "chunks_sent": 0,
                    "resumed_from": uploaded,
                    "resume_supported": resume_supported,
                    "final_result": {"verified_remote_file": self._safe_final_result(info)},
                }
            if local.size == 0:
                raise SeafileVaultError("resume reported complete empty upload but remote file was not visible")
            uploaded = ((local.size - 1) // chunk_size) * chunk_size
        os.lseek(local.fd, uploaded, os.SEEK_SET)
        offset = uploaded
        chunks_sent = 0
        final_result: Any = None
        while offset < local.size:
            chunk_start = offset
            chunk_length = min(chunk_size, local.size - chunk_start)
            chunk_end = chunk_start + chunk_length - 1
            final = chunk_start + chunk_length == local.size
            last_exc: Exception | None = None
            for attempt in range(MAX_CHUNK_ATTEMPTS):
                try:
                    os.lseek(local.fd, chunk_start, os.SEEK_SET)
                    upload_link = self._validate_upload_url(upload_link)
                    boundary = "seafile-vault-" + secrets.token_hex(16)
                    stream = MultipartChunkStream(
                        fd=local.fd,
                        chunk_length=chunk_length,
                        parent=parent,
                        name=name,
                        overwrite=overwrite,
                        boundary=boundary,
                    )
                    _require_multipart_body_under_cap(stream.content_length)
                    headers = {
                        "Content-Type": f"multipart/form-data; boundary={boundary}",
                        "Content-Length": str(stream.content_length),
                        "Content-Range": f"bytes {chunk_start}-{chunk_end}/{local.size}",
                        "Content-Disposition": _content_disposition_filename(name),
                    }
                    response = self.http.post(upload_link, content=stream, headers=headers, timeout=self.upload_timeout)
                    if 400 <= response.status_code < 500:
                        self._parse_upload_response(response, upload_link)
                    if response.status_code >= 500:
                        raise httpx.HTTPStatusError("transient upload status", request=response.request, response=response)
                    parsed_result = self._parse_chunk_response(response, upload_link, final=final)
                    if final:
                        info = self._verify_remote_file_size_with_retries(remote_path, local.size)
                        final_result = {"response": parsed_result, "verified_remote_file": self._safe_final_result(info)}
                    else:
                        final_result = parsed_result
                    chunks_sent += 1
                    offset = chunk_start + chunk_length
                    break
                except (httpx.TransportError, httpx.HTTPStatusError) as exc:
                    if isinstance(exc, httpx.HTTPStatusError) and 400 <= exc.response.status_code < 500:
                        body = exc.response.text[:1000]
                        msg = f"Seafile upload HTTP {exc.response.status_code}: {body}"
                        raise SeafileVaultError(redact_secret(msg, self.repo_token, upload_link)) from None
                    last_exc = exc
                    if final:
                        try:
                            info = self._verify_remote_file_size(remote_path, local.size, allow_missing=True)
                        except SeafileVaultError as verify_exc:
                            raise SeafileVaultError(redact_secret(str(verify_exc), self.repo_token, upload_link)) from None
                        if info is not None:
                            final_result = {"verified_remote_file": self._safe_final_result(info)}
                            chunks_sent += 1
                            offset = local.size
                            break
                    if resume_supported:
                        committed = self._get_uploaded_bytes(repo_id=repo_id, parent=parent, name=name, total=local.size)
                        if committed is None:
                            raise SeafileVaultError("resume endpoint became unavailable during retry") from None
                        if committed < offset:
                            raise SeafileVaultError("server reported uploadedBytes regression") from None
                        if committed > local.size:
                            raise SeafileVaultError("server reported uploadedBytes outside local file size") from None
                        if committed > chunk_start + chunk_length:
                            raise SeafileVaultError("server reported uploadedBytes beyond attempted chunk") from None
                        if final and committed == local.size:
                            offset = chunk_start
                        elif committed > chunk_start:
                            offset = committed
                            break
                    if attempt + 1 >= MAX_CHUNK_ATTEMPTS:
                        raise SeafileVaultError(redact_secret(str(exc), self.repo_token, upload_link)) from None
                    upload_link = self._validate_upload_url(self._get_upload_link(parent, overwrite=overwrite))
                    time.sleep(0.05 * (attempt + 1))
            else:  # pragma: no cover
                raise SeafileVaultError(str(last_exc) if last_exc else "chunk upload failed")
            if offset == chunk_start:
                raise SeafileVaultError("chunk upload made no progress")
        return {
            "chunks_sent": chunks_sent,
            "resumed_from": uploaded,
            "resume_supported": resume_supported,
            "final_result": final_result,
        }

    def _upload_file_path_direct(
        self,
        local: LocalUpload,
        *,
        parent: str,
        name: str,
        overwrite: bool,
        upload_link: str,
        direct_ip: str,
    ) -> None:
        direct_ip = _parse_direct_ip(direct_ip)
        if direct_ip is None:
            raise ConfigError("direct_ip must be a valid IP address")
        parsed = urlparse(upload_link)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        fd_path = f"/proc/self/fd/{local.fd}"
        if not Path(fd_path).exists():
            raise LocalFileError("direct upload requires /proc/self/fd for descriptor-safe curl input")
        config = "\n".join(
            [
                "silent",
                "show-error",
                "connect-timeout = " + _curl_config_quote(str(min(self.upload_timeout, DEFAULT_REQUEST_TIMEOUT))),
                "max-time = " + _curl_config_quote(_format_curl_number(self.upload_timeout)),
                "request = " + _curl_config_quote("POST"),
                "url = " + _curl_config_quote(upload_link),
                "resolve = "
                + _curl_config_quote(f"{_curl_resolve_part(parsed.hostname or '')}:{port}:{_curl_resolve_part(direct_ip)}"),
                "form = " + _curl_config_quote(f"parent_dir={parent}"),
                "form = " + _curl_config_quote(f"replace={'1' if overwrite else '0'}"),
                "form = " + _curl_config_quote(f"file=@{fd_path};filename={_curl_form_filename_quote(name)}"),
                "write-out = " + _curl_config_quote("\\n%{http_code}"),
            ]
        )
        try:
            completed = subprocess.run(
                ["curl", "--config", "-"],
                input=config,
                text=True,
                capture_output=True,
                check=False,
                pass_fds=(local.fd,),
                timeout=self.upload_timeout + 5,
            )
        except subprocess.TimeoutExpired:
            raise SeafileVaultError("direct upload timed out") from None
        except OSError as exc:
            raise SeafileVaultError(f"direct upload failed to start curl: {exc.strerror or exc}") from None

        stdout = redact_secret(completed.stdout or "", self.repo_token, upload_link)
        stderr = redact_secret(completed.stderr or "", self.repo_token, upload_link)
        if completed.returncode != 0:
            detail = stderr[:1000] or stdout[:1000] or "curl failed"
            raise SeafileVaultError(f"direct upload failed (curl exit {completed.returncode}): {detail}")
        stdout_raw = completed.stdout or ""
        if "\n" not in stdout_raw:
            raise SeafileVaultError("direct upload failed: curl did not return an HTTP status")
        body, status_text = stdout_raw.rsplit("\n", 1)
        if not status_text.isdigit():
            raise SeafileVaultError("direct upload failed: curl did not return an HTTP status")
        status = int(status_text)
        if status < 200 or status >= 300:
            safe_body = redact_secret(body[:1000], self.repo_token, upload_link)
            raise SeafileVaultError(f"Seafile upload HTTP {status}: {safe_body}")

    def write_text_file(self, path: str, text: str, *, overwrite: bool = False, encoding: str = "utf-8") -> Any:
        return self.upload_file_bytes(path, text.encode(encoding), overwrite=overwrite)

    def upload_file_base64(self, path: str, content_base64: str, *, overwrite: bool = False) -> Any:
        try:
            data = base64.b64decode(content_base64, validate=True)
        except Exception as exc:
            raise ValueError("content_base64 must be valid base64") from exc
        return self.upload_file_bytes(path, data, overwrite=overwrite)
