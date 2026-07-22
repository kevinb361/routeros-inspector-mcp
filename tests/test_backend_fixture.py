"""Tests for fixture backend."""

import pathlib

from routeros_inspector_mcp.backends.fixture import FixtureBackend

FIXTURE_DIR = pathlib.Path(__file__).parent / "fixtures" / "routeros"


def test_fixture_system_summary():
    backend = FixtureBackend(FIXTURE_DIR)
    summary = backend.get_system_summary("edge-router")
    assert summary["device_id_hint"] == "edge-router"
    assert "version" in summary


def test_fixture_interfaces():
    backend = FixtureBackend(FIXTURE_DIR)
    interfaces = backend.get_interfaces("edge-router")
    assert len(interfaces) > 0
    assert any(i["name"] == "ether1-WAN-primary" for i in interfaces)


def test_fixture_routes():
    backend = FixtureBackend(FIXTURE_DIR)
    routes = backend.get_routes("edge-router")
    assert len(routes) > 0
    default_routes = [r for r in routes if r["dst_address"] == "0.0.0.0/0"]
    assert len(default_routes) >= 2


def test_fixture_firewall_filter():
    backend = FixtureBackend(FIXTURE_DIR)
    rules = backend.get_firewall_filter("edge-router")
    assert len(rules) > 0
    chains = {r["chain"] for r in rules}
    assert "forward" in chains


def test_fixture_bridge_ports():
    backend = FixtureBackend(FIXTURE_DIR)
    ports = backend.get_bridge_ports("core-switch")
    assert len(ports) > 0
    assert any(p["interface"] == "sfp-router" for p in ports)


def test_fixture_bridge_vlans():
    backend = FixtureBackend(FIXTURE_DIR)
    vlans = backend.get_bridge_vlans("core-switch")
    assert len(vlans) > 0
    assert "vlan_ids" in vlans[0]


def test_fixture_arp():
    backend = FixtureBackend(FIXTURE_DIR)
    entries = backend.get_arp("edge-router")
    assert len(entries) > 0
    assert "mac_address" in entries[0]


def test_fixture_dhcp_leases():
    backend = FixtureBackend(FIXTURE_DIR)
    leases = backend.get_dhcp_leases("edge-router")
    assert len(leases) > 0


def test_fixture_logs():
    backend = FixtureBackend(FIXTURE_DIR)
    logs = backend.get_recent_logs("edge-router")
    assert isinstance(logs, list)


def test_fixture_qos_queues():
    backend = FixtureBackend(FIXTURE_DIR)
    queues = backend.get_qos_queues("edge-router")
    # Synthetic fixture intentionally omits queues.
    assert queues == []
    queue_tree = backend.get_queue_tree("edge-router")
    assert queue_tree == []
    queues_empty = backend.get_qos_queues("core-switch")
    assert len(queues_empty) == 0


def test_fixture_backup_info():
    backend = FixtureBackend(FIXTURE_DIR)
    backups = backend.get_backup_info("edge-router")
    assert len(backups) > 0
    assert "created" in backups[0]


def test_fixture_dns_config():
    backend = FixtureBackend(FIXTURE_DIR)
    dns = backend.get_dns_config("edge-router")
    assert "servers" in dns
    assert "dns_over_https" in dns


def test_fixture_firmware_version():
    backend = FixtureBackend(FIXTURE_DIR)
    ver = backend.get_firmware_version("edge-router")
    assert ver == "7.20.0"


def test_fixture_snmp_config():
    backend = FixtureBackend(FIXTURE_DIR)
    snmp = backend.get_snmp_config("core-switch")
    assert "community" in snmp


def test_fixture_missing_device():
    backend = FixtureBackend(FIXTURE_DIR)
    summary = backend.get_system_summary("nonexistent-device")
    assert summary == {}
