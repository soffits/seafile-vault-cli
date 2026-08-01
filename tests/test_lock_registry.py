import json
import stat
import threading
from datetime import UTC, datetime

import pytest

from seafile_vault_cli.lock_registry import LockRegistry, LockRegistryError, build_library_identity, default_registry_path


def test_default_registry_path_uses_xdg_state_home(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    assert default_registry_path() == tmp_path / "state" / "seafile-vault" / "locks.json"


def test_registry_writes_restrictive_modes_atomically_and_persists_no_secrets(tmp_path):
    identity = build_library_identity("https://Seafile.Example.com:443", "11111111-2222-3333-4444-555555555555")
    registry_path = tmp_path / "state" / "seafile-vault" / "locks.json"
    registry = LockRegistry(registry_path)
    acquired = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)

    record = registry.add(identity, "/docs/note.txt", 120, acquired_at=acquired)

    assert record.to_json() == {
        "path": "/docs/note.txt",
        "acquired_at": "2026-01-02T03:04:05Z",
        "requested_expires_seconds": 120,
        "expected_expires_at": "2026-01-02T03:06:05Z",
    }
    assert stat.S_IMODE(registry_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(registry_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(registry_path.with_suffix(".json.lock").stat().st_mode) == 0o600
    raw = registry_path.read_text(encoding="utf-8")
    assert "super-secret-token" not in raw
    assert "Authorization" not in raw
    assert "Bearer" not in raw
    assert "11111111-2222-3333-4444-555555555555" in raw
    assert list(registry_path.parent.glob("*.tmp")) == []
    assert json.loads(raw)["schema_version"] == 1


def test_registry_rejects_malformed_data_without_overwrite(tmp_path):
    identity = build_library_identity("https://seafile.example.com", "11111111-2222-3333-4444-555555555555")
    registry_path = tmp_path / "locks.json"
    registry_path.write_text("not json", encoding="utf-8")
    original = registry_path.read_text(encoding="utf-8")

    with pytest.raises(LockRegistryError):
        LockRegistry(registry_path).add(identity, "/docs/note.txt", 120)

    assert registry_path.read_text(encoding="utf-8") == original


def test_registry_concurrent_adds_keep_all_records(tmp_path):
    identity = build_library_identity("https://seafile.example.com", "11111111-2222-3333-4444-555555555555")
    registry = LockRegistry(tmp_path / "locks.json")
    acquired = datetime(2026, 1, 2, tzinfo=UTC)

    def add(index):
        registry.add(identity, f"/docs/{index}.txt", 120, acquired_at=acquired)

    threads = [threading.Thread(target=add, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(record.path for record in registry.list(identity)) == [f"/docs/{index}.txt" for index in range(8)]


def test_registry_rejects_invalid_records(tmp_path):
    registry_path = tmp_path / "locks.json"
    registry_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "libraries": {
                    "key": {
                        "origin": "https://seafile.example.com",
                        "repo_id": "11111111-2222-3333-4444-555555555555",
                        "records": {"/bad.txt": {"path": "relative", "acquired_at": "bad"}},
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    identity = build_library_identity("https://seafile.example.com", "11111111-2222-3333-4444-555555555555")
    with pytest.raises(LockRegistryError):
        LockRegistry(registry_path).list(identity)
