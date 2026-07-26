import httpx
import pytest

from seafile_vault_cli.client import PermissionMode, SeafileVaultClient


@pytest.fixture
def httpx_mock_transport():
    def make(status_code=200, json_body=None, content=b"", headers=None, handler=None, permission_mode=PermissionMode.READ_WRITE):
        requests = []

        def default_handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if json_body is not None:
                return httpx.Response(status_code, json=json_body, headers=headers or {})
            return httpx.Response(status_code, content=content, headers=headers or {})

        transport = httpx.MockTransport(handler or default_handler)
        client = SeafileVaultClient(
            "https://seafile.example.com",
            "super-secret-token",
            permission_mode=permission_mode,
            http_client=httpx.Client(transport=transport),
        )
        return client, requests

    return make
