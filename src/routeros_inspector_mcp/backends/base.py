"""Backend protocol abstraction.

All backends implement this interface. Methods return structured Python
objects (dicts/lists), not raw strings. Error taxonomy is defined here.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

# ── Error taxonomy ─────────────────────────────────────────────────────

ERROR_AUTH = "auth"
ERROR_HOSTKEY_MISMATCH = "hostkey_mismatch"
ERROR_TIMEOUT = "timeout"
ERROR_DENIED = "denied"
ERROR_PARSE_ERROR = "parse_error"
ERROR_UNSUPPORTED_VERSION = "unsupported_version"
ERROR_UNREACHABLE = "unreachable"
ERROR_NOT_IMPLEMENTED = "not_implemented"


@dataclass
class BackendError(Exception):
    """Structured backend error with a class label."""

    error_class: str
    message: str


# ── Protocol ───────────────────────────────────────────────────────────

class BackendProtocol(ABC):
    """Abstract backend for device data collection."""

    @abstractmethod
    def get_system_summary(self, device_id: str) -> dict[str, Any]:
        """Return system summary (name, uptime, version, model)."""

    @abstractmethod
    def get_interfaces(self, device_id: str) -> list[dict[str, Any]]:
        """Return list of interface dicts."""

    @abstractmethod
    def get_bridge_ports(self, device_id: str) -> list[dict[str, Any]]:
        """Return list of bridge port dicts."""

    @abstractmethod
    def get_bridge_vlans(self, device_id: str) -> list[dict[str, Any]]:
        """Return list of bridge VLAN dicts."""

    @abstractmethod
    def get_routes(self, device_id: str) -> list[dict[str, Any]]:
        """Return list of route dicts."""

    @abstractmethod
    def get_routing_tables(self, device_id: str) -> list[dict[str, Any]]:
        """Return list of routing table dicts."""

    @abstractmethod
    def get_routing_rules(self, device_id: str) -> list[dict[str, Any]]:
        """Return list of routing rule dicts."""

    @abstractmethod
    def get_firewall_filter(self, device_id: str) -> list[dict[str, Any]]:
        """Return list of filter rule dicts."""

    @abstractmethod
    def get_firewall_nat(self, device_id: str) -> list[dict[str, Any]]:
        """Return list of NAT rule dicts."""

    @abstractmethod
    def get_firewall_mangle(self, device_id: str) -> list[dict[str, Any]]:
        """Return list of mangle rule dicts."""

    @abstractmethod
    def get_address_lists(self, device_id: str) -> list[dict[str, Any]]:
        """Return list of address list entry dicts."""

    @abstractmethod
    def get_dhcp_leases(self, device_id: str) -> list[dict[str, Any]]:
        """Return list of DHCP lease dicts."""

    @abstractmethod
    def get_arp(self, device_id: str) -> list[dict[str, Any]]:
        """Return list of ARP entry dicts."""

    @abstractmethod
    def get_recent_logs(
        self, device_id: str, minutes: int = 60, topics: list[str] | None = None
    ) -> list[dict[str, Any]]:
        """Return list of log entry dicts."""

    @abstractmethod
    def get_qos_queues(self, device_id: str) -> list[dict[str, Any]]:
        """Return list of QoS queue dicts."""

    @abstractmethod
    def get_queue_tree(self, device_id: str) -> list[dict[str, Any]]:
        """Return list of queue tree dicts."""

    @abstractmethod
    def get_queue_types(self, device_id: str) -> list[dict[str, Any]]:
        """Return list of queue type dicts."""

    @abstractmethod
    def get_wireguard_interfaces(self, device_id: str) -> list[dict[str, Any]]:
        """Return list of WireGuard interface dicts."""

    @abstractmethod
    def get_wireguard_peers(self, device_id: str) -> list[dict[str, Any]]:
        """Return list of WireGuard peer dicts."""

    @abstractmethod
    def get_ip_services(self, device_id: str) -> list[dict[str, Any]]:
        """Return list of RouterOS management service dicts."""

    @abstractmethod
    def get_dhcp_servers(self, device_id: str) -> list[dict[str, Any]]:
        """Return list of DHCP server config dicts."""

    @abstractmethod
    def get_backup_info(self, device_id: str) -> list[dict[str, Any]]:
        """Return list of backup metadata dicts."""

    @abstractmethod
    def get_dns_config(self, device_id: str) -> dict[str, Any]:
        """Return DNS configuration dict."""

    @abstractmethod
    def get_firmware_version(self, device_id: str) -> str:
        """Return firmware version string."""

    @abstractmethod
    def get_snmp_config(self, device_id: str) -> dict[str, Any]:
        """Return SNMP configuration dict."""
