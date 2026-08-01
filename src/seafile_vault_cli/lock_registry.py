from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .lock_policy import validate_lock_expiry_seconds

LOCK_REGISTRY_SCHEMA_VERSION = 1
_REPO_ID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class LockRegistryError(RuntimeError):
    """Local lock registry data could not be safely read or written."""


@dataclass(frozen=True)
class LibraryIdentity:
    origin: str
    repo_id: str

    @property
    def key(self) -> str:
        return hashlib.sha256(f"{self.origin}\n{self.repo_id}".encode()).hexdigest()


@dataclass(frozen=True)
class LockRecord:
    path: str
    acquired_at: datetime
    requested_expires_seconds: int
    expected_expires_at: datetime

    def to_json(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "acquired_at": _format_utc(self.acquired_at),
            "requested_expires_seconds": self.requested_expires_seconds,
            "expected_expires_at": _format_utc(self.expected_expires_at),
        }

    @classmethod
    def from_json(cls, value: Any) -> LockRecord:
        if not isinstance(value, dict):
            raise LockRegistryError("lock registry record was not an object")
        path = value.get("path")
        requested = value.get("requested_expires_seconds")
        if not isinstance(path, str) or not path.startswith("/"):
            raise LockRegistryError("lock registry record path was invalid")
        try:
            requested = validate_lock_expiry_seconds("requested_expires_seconds", requested)
        except ValueError as exc:
            raise LockRegistryError(str(exc)) from exc
        return cls(
            path=path,
            acquired_at=_parse_utc(value.get("acquired_at"), "acquired_at"),
            requested_expires_seconds=requested,
            expected_expires_at=_parse_utc(value.get("expected_expires_at"), "expected_expires_at"),
        )


def default_registry_path() -> Path:
    state_home = os.environ.get("XDG_STATE_HOME")
    base = Path(state_home) if state_home else Path.home() / ".local" / "state"
    return base / "seafile-vault" / "locks.json"


def normalize_origin(server_url: str) -> str:
    parsed = urlparse(server_url.strip().rstrip("/"))
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise LockRegistryError("server origin was invalid")
    port = parsed.port
    default_port = 443 if parsed.scheme == "https" else 80
    netloc = parsed.hostname.lower()
    if port is not None and port != default_port:
        netloc = f"{netloc}:{port}"
    return f"{parsed.scheme.lower()}://{netloc}"


def build_library_identity(server_url: str, repo_id: str) -> LibraryIdentity:
    origin = normalize_origin(server_url)
    if not isinstance(repo_id, str) or not _REPO_ID_RE.fullmatch(repo_id):
        raise LockRegistryError("repo_id was invalid")
    return LibraryIdentity(origin=origin, repo_id=repo_id.lower())


class LockRegistry:
    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path is not None else default_registry_path()

    def add(self, identity: LibraryIdentity, path: str, expires_seconds: int, *, acquired_at: datetime | None = None) -> LockRecord:
        try:
            expires_seconds = validate_lock_expiry_seconds("expires_seconds", expires_seconds)
        except ValueError as exc:
            raise LockRegistryError(str(exc)) from exc
        acquired = _utc_now() if acquired_at is None else _ensure_utc(acquired_at)
        record = LockRecord(
            path=path,
            acquired_at=acquired,
            requested_expires_seconds=expires_seconds,
            expected_expires_at=acquired + timedelta(seconds=expires_seconds),
        )
        with self._locked():
            data = self._read_unlocked()
            library = self._library(data, identity)
            records = library["records"]
            records[path] = record.to_json()
            self._write_unlocked(data)
        return record

    def remove(self, identity: LibraryIdentity, path: str) -> bool:
        with self._locked():
            data = self._read_unlocked()
            library = self._library(data, identity)
            existed = path in library["records"]
            library["records"].pop(path, None)
            self._write_unlocked(data)
            return existed

    def list(self, identity: LibraryIdentity) -> list[LockRecord]:
        with self._locked():
            data = self._read_unlocked()
            library = self._library(data, identity)
            return [LockRecord.from_json(record) for record in library["records"].values()]

    def replace_records(self, identity: LibraryIdentity, records: list[LockRecord]) -> None:
        with self._locked():
            data = self._read_unlocked()
            library = self._library(data, identity)
            library["records"] = {record.path: record.to_json() for record in records}
            self._write_unlocked(data)

    def _library(self, data: dict[str, Any], identity: LibraryIdentity) -> dict[str, Any]:
        libraries = data["libraries"]
        library = libraries.setdefault(identity.key, {"origin": identity.origin, "repo_id": identity.repo_id, "records": {}})
        if not isinstance(library, dict):
            raise LockRegistryError("lock registry library entry was invalid")
        if library.get("origin") != identity.origin or library.get("repo_id") != identity.repo_id:
            raise LockRegistryError("lock registry library identity mismatch")
        records = library.get("records")
        if not isinstance(records, dict):
            raise LockRegistryError("lock registry records were invalid")
        for key, value in records.items():
            record = LockRecord.from_json(value)
            if key != record.path:
                raise LockRegistryError("lock registry record key mismatch")
        return library

    def _locked(self):
        return _RegistryLock(self.path)

    def _read_unlocked(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"schema_version": LOCK_REGISTRY_SCHEMA_VERSION, "libraries": {}}
        try:
            mode = self.path.stat().st_mode
        except OSError as exc:
            raise LockRegistryError(f"lock registry is not accessible: {exc.strerror or exc}") from None
        if not stat.S_ISREG(mode):
            raise LockRegistryError("lock registry path is not a regular file")
        os.chmod(self.path, 0o600)
        try:
            raw = self.path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LockRegistryError(f"lock registry is malformed: {exc}") from exc
        if not isinstance(data, dict):
            raise LockRegistryError("lock registry root was not an object")
        if data.get("schema_version") != LOCK_REGISTRY_SCHEMA_VERSION:
            raise LockRegistryError("lock registry schema_version was unsupported")
        if not isinstance(data.get("libraries"), dict):
            raise LockRegistryError("lock registry libraries were invalid")
        self._validate_registry(data)
        return data

    def _write_unlocked(self, data: dict[str, Any]) -> None:
        self._validate_registry(data)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        tmp_name = self.path.with_name(f".{self.path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
        payload = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        fd: int | None = None
        try:
            fd = os.open(tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            _write_all(fd, payload.encode("utf-8"))
            os.fsync(fd)
            os.close(fd)
            fd = None
            os.replace(tmp_name, self.path)
            os.chmod(self.path, 0o600)
            parent_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        except OSError as exc:
            raise LockRegistryError(f"lock registry write failed: {exc.strerror or exc}") from None
        finally:
            if fd is not None:
                os.close(fd)
            try:
                tmp_name.unlink()
            except FileNotFoundError:
                pass

    def _validate_registry(self, data: dict[str, Any]) -> None:
        if data.get("schema_version") != LOCK_REGISTRY_SCHEMA_VERSION or not isinstance(data.get("libraries"), dict):
            raise LockRegistryError("lock registry data was invalid")
        for library in data["libraries"].values():
            if not isinstance(library, dict) or not isinstance(library.get("records"), dict):
                raise LockRegistryError("lock registry library data was invalid")
            if not isinstance(library.get("origin"), str) or not isinstance(library.get("repo_id"), str):
                raise LockRegistryError("lock registry library identity was invalid")
            for record in library["records"].values():
                LockRecord.from_json(record)


class _RegistryLock:
    def __init__(self, registry_path: Path) -> None:
        self.registry_path = registry_path
        self.fd: int | None = None

    def __enter__(self) -> _RegistryLock:
        self.registry_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.registry_path.parent, 0o700)
        lock_path = self.registry_path.with_suffix(self.registry_path.suffix + ".lock")
        self.fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        os.chmod(lock_path, 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *_: object) -> None:
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = None


def _utc_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise LockRegistryError("UTC timestamp must include timezone")
    return value.astimezone(UTC).replace(microsecond=0)


def _format_utc(value: datetime) -> str:
    return _ensure_utc(value).isoformat().replace("+00:00", "Z")


def _parse_utc(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise LockRegistryError(f"lock registry {field} was not a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise LockRegistryError(f"lock registry {field} was invalid") from exc
    return _ensure_utc(parsed)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise LockRegistryError("lock registry write made no progress")
        view = view[written:]
