"""Tests for service layer."""

import logging
import pathlib

import pytest

from routeros_inspector_mcp.backends.fixture import FixtureBackend
from routeros_inspector_mcp.config import DeviceEntry, DeviceInventory, load_inventory, load_policy
from routeros_inspector_mcp.service import Service, ServiceError

CONFIG_DIR = pathlib.Path(__file__).parent.parent / "config"
FIXTURE_DIR = pathlib.Path(__file__).parent / "fixtures" / "routeros"


@pytest.fixture
def service():
    inventory = load_inventory(CONFIG_DIR / "devices.example.yaml")
    backend = FixtureBackend(FIXTURE_DIR)
    policy = load_policy(CONFIG_DIR / "policy.example.yaml")
    return Service(inventory, {"fixture": backend}, policy)


def test_list_devices(service):
    devices = service.list_devices()
    assert len(devices) >= 2
    dev_ids = {d["device_id"] for d in devices}
    assert "edge-router" in dev_ids
    assert "core-switch" in dev_ids
    # credential_ref should NOT be in output
    for d in devices:
        assert "credential_ref" not in d


def test_list_devices_does_not_expose_connection_details():
    inventory = DeviceInventory(
        devices={
            "router": DeviceEntry(
                role="gateway",
                risk="critical",
                host="router.example.test",
                transport="api",
                credential_ref="vault:test",
                routeros_api_port=8729,
                routeros_api_tls=True,
                routeros_api_certificate="/private/router.crt",
                routeros_api_server_name="router.example.test",
            )
        }
    )
    devices = Service(inventory, {}).list_devices()

    assert devices == [
        {
            "device_id": "router",
            "role": "gateway",
            "risk": "critical",
            "transport": "api",
            "allowed": True,
            "tags": [],
        }
    ]


def test_get_device_summary(service):
    summary = service.get_device_summary("edge-router")
    assert summary["device_id"] == "edge-router"
    assert summary["role"] == "gateway"
    assert summary["device_id_hint"] == "edge-router"


def test_get_interfaces(service):
    interfaces = service.get_interfaces("edge-router")
    assert len(interfaces) > 0
    assert any(i["name"] == "ether1-WAN-primary" for i in interfaces)


def test_get_routes(service):
    routes = service.get_routes("edge-router")
    assert len(routes) >= 2


def test_get_firewall_mangle(service):
    rules = service.get_firewall_mangle("edge-router")
    assert len(rules) > 0


def test_get_dns_config(service):
    dns = service.get_dns_config("edge-router")
    assert "servers" in dns


def test_invalid_device_id(service):
    with pytest.raises(ValueError, match="Unknown device ID"):
        service.get_device_summary("nonexistent")


def test_configured_transport_does_not_fall_back_to_another_backend():
    inventory = DeviceInventory(
        devices={
            "router": DeviceEntry(
                role="gateway",
                risk="critical",
                host="router.example.test",
                transport="ssh",
                credential_ref="vault:test",
            )
        }
    )
    fixture = FixtureBackend(FIXTURE_DIR)
    svc = Service(inventory, {"fixture": fixture})

    with pytest.raises(ValueError, match="No backend available for transport 'ssh'"):
        svc.get_interfaces("router")


def test_disabled_device(tmp_path):
    """Test that a non-allowed device is rejected."""
    inventory = load_inventory(CONFIG_DIR / "devices.example.yaml")
    # Temporarily modify a device
    inventory.devices["edge-router"].allowed = False
    backend = FixtureBackend(FIXTURE_DIR)
    svc = Service(inventory, {"fixture": backend})

    with pytest.raises(ValueError, match="not allowed"):
        svc.get_device_summary("edge-router")


def test_fleet_call_partial_errors(service):
    result = service.fleet_call("get_interfaces", ["edge-router", "nonexistent"])
    assert result["total"] == 2
    assert result["succeeded"] == 1
    assert result["failed"] == 1
    assert "nonexistent" in result["errors"]


def test_service_rejects_unregistered_backend_operation(service):
    with pytest.raises(ValueError, match="Unknown or denied operation"):
        service._call_backend("edge-router", "not_registered")


def test_single_device_call_does_not_expose_exception_details():
    class FailingBackend:
        def get_interfaces(self, device_id):
            raise RuntimeError("password=hunter2")

    inventory = DeviceInventory(
        devices={
            "router": DeviceEntry(
                role="gateway",
                risk="critical",
                host="router.example.test",
                transport="api",
                credential_ref="vault:test",
            )
        }
    )
    svc = Service(inventory, {"api": FailingBackend()})

    with pytest.raises(ServiceError, match="^internal_error$") as exc_info:
        svc.get_interfaces("router")

    assert "hunter2" not in str(exc_info.value)


def test_backend_failure_logs_safe_private_diagnostic(caplog: pytest.LogCaptureFixture):
    class FailingBackend:
        def get_interfaces(self, device_id):
            raise RuntimeError("password=hunter2")

    inventory = DeviceInventory(
        devices={
            "router": DeviceEntry(
                role="gateway",
                risk="critical",
                host="router.example.test",
                transport="api",
                credential_ref="vault:test",
            )
        }
    )
    svc = Service(inventory, {"api": FailingBackend()})

    with caplog.at_level(logging.ERROR, logger="routeros_inspector_mcp.service"):
        with pytest.raises(ServiceError):
            svc.get_interfaces("router")

    record = caplog.records[-1]
    assert record.device_id == "router"
    assert record.operation == "get_interfaces"
    assert record.exception_class == "RuntimeError"
    assert record.error_class == "internal_error"
    assert "hunter2" not in caplog.text


def test_fleet_call_does_not_expose_exception_details():
    class FailingBackend:
        def get_interfaces(self, device_id):
            raise RuntimeError("password=hunter2")

    inventory = DeviceInventory(
        devices={
            "router": DeviceEntry(
                role="gateway",
                risk="critical",
                host="router.example.test",
                transport="api",
                credential_ref="vault:test",
            )
        }
    )
    svc = Service(inventory, {"api": FailingBackend()})

    result = svc.fleet_call("get_interfaces", ["router"])

    assert result["errors"] == {"router": "internal_error"}
    assert "hunter2" not in str(result)


def test_fleet_call_partial_failure(service):
    result = service.fleet_call(
        "get_system_summary",
        device_ids=["edge-router", "nonexistent"],
    )
    assert result["succeeded"] == 1
    assert result["failed"] == 1
    assert "edge-router" in result["results"]
    assert "nonexistent" in result["errors"]


def test_policy_access(service):
    policy = service.get_policy()
    assert policy is not None
    assert policy.dns.encrypted is False
