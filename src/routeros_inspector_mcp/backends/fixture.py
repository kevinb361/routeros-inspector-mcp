"""Fixture backend — static JSON data for testing and MVP.

Loads pre-written fixture files from a directory. No network access.
Returns structured Python objects matching the backend protocol.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

from .base import BackendProtocol


class FixtureBackend(BackendProtocol):
    """Load device data from pre-written JSON fixture files."""

    def __init__(self, fixture_dir: pathlib.Path):
        self.fixture_dir = fixture_dir

    def _load(self, device_id: str, key: str) -> Any:
        """Load a fixture key for a device. Returns empty dict/list if missing."""
        path = self.fixture_dir / f"{device_id}.json"
        if not path.exists():
            return {}
        data = json.loads(path.read_text())
        return data.get(key, {})

    def _load_list(self, device_id: str, key: str) -> list[dict[str, Any]]:
        """Load a fixture key, ensuring it returns a list."""
        data = self._load(device_id, key)
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and data:
            return [data]
        return []

    def _load_str(self, device_id: str, key: str, default: str = "") -> str:
        """Load a fixture key, ensuring it returns a string."""
        data = self._load(device_id, key)
        if isinstance(data, str):
            return data
        if isinstance(data, (int, float)):
            return str(data)
        return default

    # ── Protocol implementation ──────────────────────────────────────

    def get_system_summary(self, device_id: str) -> dict[str, Any]:
        return self._load(device_id, "system_summary") or {}

    def get_interfaces(self, device_id: str) -> list[dict[str, Any]]:
        return self._load_list(device_id, "interfaces")

    def get_bridge_ports(self, device_id: str) -> list[dict[str, Any]]:
        return self._load_list(device_id, "bridge_ports")

    def get_bridge_vlans(self, device_id: str) -> list[dict[str, Any]]:
        return self._load_list(device_id, "bridge_vlans")

    def get_routes(self, device_id: str) -> list[dict[str, Any]]:
        return self._load_list(device_id, "routes")

    def get_routing_tables(self, device_id: str) -> list[dict[str, Any]]:
        return self._load_list(device_id, "routing_tables")

    def get_routing_rules(self, device_id: str) -> list[dict[str, Any]]:
        return self._load_list(device_id, "routing_rules")

    def get_firewall_filter(self, device_id: str) -> list[dict[str, Any]]:
        return self._load_list(device_id, "firewall_filter")

    def get_firewall_nat(self, device_id: str) -> list[dict[str, Any]]:
        return self._load_list(device_id, "firewall_nat")

    def get_firewall_mangle(self, device_id: str) -> list[dict[str, Any]]:
        return self._load_list(device_id, "firewall_mangle")

    def get_address_lists(self, device_id: str) -> list[dict[str, Any]]:
        return self._load_list(device_id, "address_lists")

    def get_dhcp_leases(self, device_id: str) -> list[dict[str, Any]]:
        return self._load_list(device_id, "dhcp_leases")

    def get_arp(self, device_id: str) -> list[dict[str, Any]]:
        return self._load_list(device_id, "arp")

    def get_recent_logs(
        self, device_id: str, minutes: int = 60, topics: list[str] | None = None
    ) -> list[dict[str, Any]]:
        return self._load_list(device_id, "recent_logs")

    def get_qos_queues(self, device_id: str) -> list[dict[str, Any]]:
        return self._load_list(device_id, "qos_queues")

    def get_queue_tree(self, device_id: str) -> list[dict[str, Any]]:
        return self._load_list(device_id, "queue_tree")

    def get_queue_types(self, device_id: str) -> list[dict[str, Any]]:
        return self._load_list(device_id, "queue_types")

    def get_wireguard_interfaces(self, device_id: str) -> list[dict[str, Any]]:
        return self._load_list(device_id, "wireguard_interfaces")

    def get_wireguard_peers(self, device_id: str) -> list[dict[str, Any]]:
        return self._load_list(device_id, "wireguard_peers")

    def get_ip_services(self, device_id: str) -> list[dict[str, Any]]:
        return self._load_list(device_id, "ip_services")

    def get_dhcp_servers(self, device_id: str) -> list[dict[str, Any]]:
        return self._load_list(device_id, "dhcp_servers")

    def get_backup_info(self, device_id: str) -> list[dict[str, Any]]:
        return self._load_list(device_id, "backup_info")

    def get_dns_config(self, device_id: str) -> dict[str, Any]:
        return self._load(device_id, "dns_config") or {}

    def get_firmware_version(self, device_id: str) -> str:
        return self._load_str(device_id, "firmware_version", "unknown")

    def get_snmp_config(self, device_id: str) -> dict[str, Any]:
        return self._load(device_id, "snmp_config") or {}
