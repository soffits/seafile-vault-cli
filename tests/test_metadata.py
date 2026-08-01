import io
import json
import sys
import types

import httpx
import pytest

from seafile_vault_cli.client import CapabilityError, ConfigError, PermissionMode, PermissionModeError, SeafileVaultClient


def _client(handler, *, permission_mode=PermissionMode.READ_WRITE):
    return SeafileVaultClient(
        "https://seafile.example.com",
        "repo-secret",
        permission_mode=permission_mode,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def test_metadata_read_routes_and_output_scrubbing():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/api/v2.1/via-repo-token/metadata/views/":
            return httpx.Response(200, json=[{"_id": "view_1", "repo_id": "secret-repo", "owner_email": "owner@example.com"}])
        if request.url.path == "/api/v2.1/via-repo-token/metadata/views/view_1/":
            return httpx.Response(200, json={"view": {"_id": "view_1", "modifier_email": "person@example.com"}})
        if request.url.path == "/api/v2.1/via-repo-token/metadata/records/":
            assert request.url.params["view_id"] == "view_1"
            assert request.url.params["start"] == "2"
            assert request.url.params["limit"] == "3"
            return httpx.Response(200, json={"results": [{"_id": "rec_1", "repo_id": "secret-repo"}]})
        if request.url.path == "/api/v2.1/via-repo-token/metadata/tags/":
            assert request.url.params["start"] == "0"
            assert request.url.params["limit"] == "1"
            return httpx.Response(200, json={"results": [{"_id": "tag_1", "token": "raw-token"}]})
        if request.url.path == "/api/v2.1/via-repo-token/metadata/tag-files/tag_1/":
            assert len(request.url.params) == 0
            return httpx.Response(200, json={"results": [{"_id": "rec_1", "owner_email": "x@example.com"}]})
        raise AssertionError(str(request.url))

    client = _client(handler)
    assert client.metadata_views_list() == [{"_id": "view_1"}]
    assert client.metadata_view_get("view_1") == {"view": {"_id": "view_1"}}
    assert client.metadata_records_list("view_1", start=2, limit=3) == {"results": [{"_id": "rec_1"}]}
    assert client.metadata_tags_status()["enabled"] is True
    assert client.metadata_tag_files("tag_1") == {"results": [{"_id": "rec_1"}]}
    assert all(request.headers["authorization"] == "Bearer repo-secret" for request in requests)


def test_metadata_write_payloads_require_read_write_and_exact_routes():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"success": True, "repo_id": "secret-repo"})

    client = _client(handler)
    assert client.metadata_records_update({"records_data": [{"record_id": "rec_1", "record": {"name": "n"}}]}) == {"success": True}
    assert client.metadata_views_create({"name": "V", "type": "table", "data": {}}) == {"success": True}
    assert client.metadata_views_update({"view_id": "view_1", "view_data": {"name": "V2"}}) == {"success": True}
    assert client.metadata_views_delete({"view_id": "view_1"}) == {"success": True}
    assert client.metadata_views_duplicate({"view_id": "view_1"}) == {"success": True}
    assert client.metadata_views_move(
        {"source_view_id": "view_1", "target_view_id": "view_2", "is_above_folder": False}
    ) == {"success": True}
    assert client.metadata_tags_enable(lang="en") == {"success": True}
    assert client.metadata_tags_disable() == {"success": True}
    assert client.metadata_tags_create({"tags_data": [{"name": "A"}]}) == {"success": True}
    assert client.metadata_tags_update({"tags_data": [{"tag_id": "tag_1", "tag": {"name": "B"}}]}) == {"success": True}
    assert client.metadata_tags_delete({"tag_ids": ["tag_1"]}) == {"success": True}
    assert client.metadata_tag_link_create({"link_column_key": "parent_links", "row_id_map": {"tag_1": ["tag_2"]}}) == {"success": True}
    assert client.metadata_tag_link_update({"link_column_key": "parent_links", "row_id_map": {"tag_1": ["tag_2"]}}) == {"success": True}
    assert client.metadata_tag_link_delete({"link_column_key": "parent_links", "row_id_map": {"tag_1": ["tag_2"]}}) == {"success": True}
    assert client.metadata_file_tags_assign({"file_tags_data": [{"record_id": "rec_1", "tags": ["tag_1"]}]}) == {"success": True}
    assert client.metadata_tags_files({"tags_ids": ["tag_1"]}) == {"success": True}
    assert client.metadata_tags_merge({"target_tag_id": "tag_1", "merged_tags_ids": ["tag_2"]}) == {"success": True}

    paths = [request.url.path for request in requests]
    assert paths[:6] == [
        "/api/v2.1/via-repo-token/metadata/records/",
        "/api/v2.1/via-repo-token/metadata/views/",
        "/api/v2.1/via-repo-token/metadata/views/",
        "/api/v2.1/via-repo-token/metadata/views/",
        "/api/v2.1/via-repo-token/metadata/duplicate-view/",
        "/api/v2.1/via-repo-token/metadata/move-views/",
    ]
    assert json.loads(requests[0].content) == {"records_data": [{"record_id": "rec_1", "record": {"name": "n"}}]}
    assert requests[0].method == "PUT"
    assert [(request.method, request.url.path) for request in requests[6:]] == [
        ("PUT", "/api/v2.1/via-repo-token/metadata/tags-status/"),
        ("DELETE", "/api/v2.1/via-repo-token/metadata/tags-status/"),
        ("POST", "/api/v2.1/via-repo-token/metadata/tags/"),
        ("PUT", "/api/v2.1/via-repo-token/metadata/tags/"),
        ("DELETE", "/api/v2.1/via-repo-token/metadata/tags/"),
        ("POST", "/api/v2.1/via-repo-token/metadata/tags-links/"),
        ("PUT", "/api/v2.1/via-repo-token/metadata/tags-links/"),
        ("DELETE", "/api/v2.1/via-repo-token/metadata/tags-links/"),
        ("PUT", "/api/v2.1/via-repo-token/metadata/file-tags/"),
        ("POST", "/api/v2.1/via-repo-token/metadata/tags-files/"),
        ("POST", "/api/v2.1/via-repo-token/metadata/merge-tags/"),
    ]

    read_only = _client(handler, permission_mode=PermissionMode.READ_ONLY)
    with pytest.raises(PermissionModeError):
        read_only.metadata_tags_create({"tags_data": [{"name": "A"}]})


def test_metadata_validation_and_disabled_capability_mapping():
    client = _client(lambda request: httpx.Response(200, json={"success": True}))
    with pytest.raises(ConfigError, match="view_id"):
        client.metadata_view_get("../bad")
    with pytest.raises(ConfigError, match="limit"):
        client.metadata_tags_list(limit=1001)
    with pytest.raises(ConfigError, match="records_data"):
        client.metadata_records_update({"records_data": []})

    def disabled(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error_msg": "The tags is disabled for repo 11111111-2222-3333-4444-555555555555."})

    assert _client(disabled).metadata_tags_status()["enabled"] is False
    with pytest.raises(CapabilityError, match="tags are disabled"):
        _client(disabled).metadata_tags_list()


def test_cli_metadata_json_stdin_confirmation_and_trailing_data(monkeypatch, capsys):
    from seafile_vault_cli import cli

    parser = cli.build_parser()
    assert parser.parse_args(["metadata", "views", "list"]).metadata_command == "views"
    assert parser.parse_args(["metadata", "records", "list", "view_1", "--start", "0", "--limit", "10"]).limit == 10
    with pytest.raises(SystemExit):
        parser.parse_args(["metadata", "records", "update", "--json-stdin"])
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "usage"

    calls = []

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def metadata_records_update(self, body):
            calls.append(body)
            return {"success": True}

    monkeypatch.setattr(cli.SeafileVaultClient, "from_env", lambda: FakeClient())
    monkeypatch.setattr("sys.stdin", io.StringIO('{"records_data":[{"record_id":"rec_1","record":{"name":"n"}}]}'))
    assert cli.main(["metadata", "records", "update", "--json-stdin", "--confirm"]) == 0
    assert calls == [{"records_data": [{"record_id": "rec_1", "record": {"name": "n"}}]}]

    monkeypatch.setattr("sys.stdin", io.StringIO('{"records_data":[]} []'))
    assert cli.main(["metadata", "records", "update", "--json-stdin", "--confirm"]) == 3
    assert "trailing data" in json.loads(capsys.readouterr().err)["error"]["message"]


def test_mcp_registers_read_only_metadata_and_no_mutations(monkeypatch):
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

    import seafile_vault_cli.mcp_server as mcp_server

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def metadata_records_list(self, view_id, *, start, limit):
            return {"view_id": view_id, "start": start, "limit": limit}

    monkeypatch.setattr(mcp_server, "_client", lambda: FakeClient())
    server = mcp_server.build_server()
    assert "seafile_vault_metadata_records" in server.tools
    assert "seafile_vault_share_links" in server.tools
    assert "seafile_vault_create_directory" not in server.tools
    assert "seafile_vault_delete_path" not in server.tools
    assert server.tools["seafile_vault_metadata_records"]("view_1", 2, 3) == {"view_id": "view_1", "start": 2, "limit": 3}
