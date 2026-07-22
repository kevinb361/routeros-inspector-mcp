from __future__ import annotations

import inspect
from typing import Any

import pytest

from routeros_inspector_mcp.backends.base import BackendError
from routeros_inspector_mcp.backends.routeros_api import RouterOSAPIBackend
from routeros_inspector_mcp.config import DeviceEntry


class FakeConnection:
    def __init__(
        self, *, items: list[dict[str, Any]] | None = None, error: Exception | None = None
    ):
        self.items = items or []
        self.error = error
        self.close_count = 0

    def path(self, *segments: str):
        def query(command: str):
            if self.error is not None:
                raise self.error
            return self.items

        return query

    def close(self) -> None:
        self.close_count += 1


def backend() -> RouterOSAPIBackend:
    entry = DeviceEntry(
        role="gateway",
        risk="critical",
        host="192.0.2.1",
        transport="api",
        credential_ref="vault:test",
    )
    return RouterOSAPIBackend({"router": entry})


def test_live_backend_has_no_fixture_dispatch_path() -> None:
    parameters = inspect.signature(RouterOSAPIBackend).parameters
    api = backend()

    assert list(parameters) == ["device_inventory"]
    assert not hasattr(api, "_fixture")
    assert not hasattr(api, "_get_device")


def test_query_closes_connection_after_success(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = FakeConnection(items=[{"name": "ether1"}])
    api = backend()
    monkeypatch.setattr(api, "_connect", lambda device_id: connection)

    assert api.get_interfaces("router") == [{"name": "ether1"}]
    assert connection.close_count == 1


def test_query_closes_connection_after_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = FakeConnection(error=RuntimeError("query failed"))
    api = backend()
    monkeypatch.setattr(api, "_connect", lambda device_id: connection)

    with pytest.raises(BackendError, match="Query failed"):
        api.get_interfaces("router")

    assert connection.close_count == 1


def test_query_closes_primary_and_latin1_connections_after_retry_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decode_error = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid byte")
    primary = FakeConnection(error=decode_error)
    latin1 = FakeConnection(error=RuntimeError("retry failed"))
    api = backend()
    monkeypatch.setattr(api, "_connect", lambda device_id: primary)
    monkeypatch.setattr(api, "_connect_latin1", lambda device_id: latin1)

    with pytest.raises(BackendError, match="Query failed"):
        api.get_interfaces("router")

    assert primary.close_count == 1
    assert latin1.close_count == 1
