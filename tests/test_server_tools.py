"""Tests for FastMCP tool registration and fixture-backed tool calls."""

from __future__ import annotations

import asyncio
import pathlib

import pytest
from fastmcp.exceptions import ToolError

import routeros_inspector_mcp.server as server_module
from routeros_inspector_mcp.audits.qos import audit_qos_state
from routeros_inspector_mcp.server import AUDIT_REGISTRY, build_parser, create_server

ROOT = pathlib.Path(__file__).parent.parent
CONFIG_DIR = ROOT / "config"
FIXTURE_DIR = pathlib.Path(__file__).parent / "fixtures" / "routeros"


@pytest.fixture
def app(tmp_path):
    return create_server(
        devices_path=CONFIG_DIR / "devices.example.yaml",
        fixture_dir=FIXTURE_DIR,
        policy_path=CONFIG_DIR / "policy.example.yaml",
        audit_log_path=tmp_path / "audit.jsonl",
    )


async def _call_async(app, name: str, arguments: dict | None = None):
    result = await app.call_tool(name, arguments or {})
    assert result.is_error is False
    content = result.structured_content
    if isinstance(content, dict) and set(content) == {"result"}:
        return content["result"]
    return content


def _call(app, name: str, arguments: dict | None = None):
    return asyncio.run(_call_async(app, name, arguments))


def test_fixture_only_server_never_constructs_live_backend(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
):
    class ForbiddenLiveBackend:
        def __init__(self, *args, **kwargs):
            raise AssertionError("fixture-only mode constructed the live backend")

    monkeypatch.setattr(
        "routeros_inspector_mcp.backends.routeros_api.RouterOSAPIBackend",
        ForbiddenLiveBackend,
    )
    fixture_app = create_server(
        devices_path=CONFIG_DIR / "devices.example.yaml",
        fixture_dir=FIXTURE_DIR,
        policy_path=CONFIG_DIR / "policy.example.yaml",
        audit_log_path=tmp_path / "audit.jsonl",
        fixture_only=True,
    )

    interfaces = _call(fixture_app, "get_interfaces", {"device": "edge-router"})

    assert interfaces


def test_server_requires_explicit_live_mode():
    parser = build_parser()

    args = parser.parse_args([])
    assert args.transport == "stdio"
    assert args.live is False
    assert args.allow_loopback_http is False
    assert parser.parse_args(["--live"]).live is True


def test_network_transport_requires_explicit_loopback_opt_in(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        server_module,
        "create_server",
        lambda **kwargs: pytest.fail("server constructed before transport validation"),
    )

    with pytest.raises(SystemExit) as exc_info:
        server_module.main(["--transport", "http"])

    assert exc_info.value.code == 2


def test_network_transport_is_forced_to_loopback(monkeypatch: pytest.MonkeyPatch):
    observed: dict[str, object] = {}

    class FakeApp:
        def run(self, **kwargs):
            observed.update(kwargs)

    monkeypatch.setattr(server_module, "create_server", lambda **kwargs: FakeApp())

    server_module.main(["--transport", "http", "--allow-loopback-http"])

    assert observed["transport"] == "http"
    assert observed["host"] == "127.0.0.1"
    assert observed["show_banner"] is False


def test_registers_read_only_tool_surface(app):
    async def run():
        tools = await app.list_tools()
        return {tool.name for tool in tools}

    names = asyncio.run(run())
    expected = {
        "get_capabilities",
        "list_devices",
        "get_device_summary",
        "get_interfaces",
        "get_bridge_ports",
        "get_bridge_vlans",
        "get_routes",
        "get_firewall_filter",
        "get_firewall_nat",
        "get_firewall_mangle",
        "get_address_lists",
        "get_dhcp_leases",
        "get_arp",
        "get_recent_logs",
        "list_audits",
        "run_audit",
    }
    assert expected <= names
    assert not any("command" in name for name in names)
    assert not any(
        name.startswith(("create_", "set_", "update_", "delete_", "remove_")) for name in names
    )


def test_capabilities_report_read_only_mode(app):
    caps = _call(app, "get_capabilities")
    assert caps["mode"] == "read-only"
    assert caps["devices_count"] >= 2
    assert caps["max_audit_fanout"] == 128
    assert "get_interfaces" in caps["collectors"]
    assert "qos_state" in caps["audits"]


def test_fixture_backed_collector_tools_work(app):
    devices = _call(app, "list_devices")
    summary = _call(app, "get_device_summary", {"device": "edge-router"})
    interfaces = _call(app, "get_interfaces", {"device": "edge-router"})
    routes = _call(app, "get_routes", {"device": "edge-router"})
    mangle = _call(app, "get_firewall_mangle", {"device": "edge-router"})
    logs = _call(app, "get_recent_logs", {"device": "edge-router"})

    assert devices
    assert summary["device_id"] == "edge-router"
    assert interfaces
    assert routes
    assert mangle
    assert isinstance(logs, list)


def test_run_audit_deduplicates_devices_and_audits(app, monkeypatch):
    calls: list[tuple[object, str]] = []

    def record_call(service, device_id):
        calls.append((service, device_id))
        return audit_qos_state(service, device_id)

    monkeypatch.setitem(AUDIT_REGISTRY, "record_call", record_call)

    results = _call(
        app,
        "run_audit",
        {
            "audits": ["record_call", "record_call"],
            "device_ids": ["edge-router", "edge-router"],
        },
    )

    assert len(results) == 1
    assert [device_id for _, device_id in calls] == ["edge-router"]


def test_run_audit_rejects_oversized_fanout_before_execution(app, monkeypatch):
    calls: list[str] = []

    def record_call(service, device_id):
        calls.append(device_id)
        return audit_qos_state(service, device_id)

    monkeypatch.setitem(AUDIT_REGISTRY, "record_call", record_call)
    monkeypatch.setattr(server_module, "MAX_AUDIT_FANOUT", 1)

    with pytest.raises(ToolError, match="Audit fan-out 2 exceeds limit 1"):
        asyncio.run(
            app.call_tool(
                "run_audit",
                {
                    "audits": ["record_call"],
                    "device_ids": ["edge-router", "core-switch"],
                },
            )
        )

    assert calls == []


@pytest.mark.parametrize(
    ("audits", "device_ids", "error"),
    [
        (["record_call", "unknown"], ["edge-router"], "Unknown audit"),
        (["record_call"], ["edge-router", "unknown"], "Unknown device"),
    ],
)
def test_run_audit_rejects_unknown_inputs_before_execution(
    app, monkeypatch, audits, device_ids, error
):
    calls: list[str] = []

    def record_call(service, device_id):
        calls.append(device_id)
        return audit_qos_state(service, device_id)

    monkeypatch.setitem(AUDIT_REGISTRY, "record_call", record_call)

    with pytest.raises(ToolError, match=error):
        asyncio.run(
            app.call_tool(
                "run_audit",
                {"audits": audits, "device_ids": device_ids},
            )
        )

    assert calls == []


def test_run_audit_does_not_expose_exception_details(app, monkeypatch):
    def fail_with_secret(service, device_id):
        raise RuntimeError("password=hunter2")

    monkeypatch.setitem(AUDIT_REGISTRY, "secret_failure", fail_with_secret)

    results = _call(
        app,
        "run_audit",
        {"audits": ["secret_failure"], "device_ids": ["edge-router"]},
    )

    assert results == [
        {
            "audit_name": "secret_failure",
            "device_id": "edge-router",
            "error": "internal_error",
        }
    ]
    assert "hunter2" not in str(results)


def test_audit_tools_work_with_fixture_backend(app):
    audits = _call(app, "list_audits")
    assert "qos_state" in audits
    assert "dead_mangle_rules" in audits
    assert "dscp_policy" in audits

    results = _call(
        app,
        "run_audit",
        {
            "audits": ["qos_state", "dead_mangle_rules", "dscp_policy"],
            "device_ids": ["edge-router"],
        },
    )
    assert len(results) == 3
    assert {result["audit_name"] for result in results} == {
        "qos_state",
        "dead_mangle_rules",
        "dscp_policy",
    }
    assert all(result["findings"] for result in results)
