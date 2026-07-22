"""Operation registry for allowed internal operations.

Every operation has a name, backend path, read_only flag, sensitivity,
and timeout class. No operation accepts free-form command text.
v1 contains zero write/destructive operations.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

ALLOWED_TIMEOUTS = {"fast", "normal", "slow"}


class Operation(BaseModel):
    """A single allowed operation."""

    name: str
    description: str
    backend_method: str = Field(
        description="Method name on the backend to call"
    )
    read_only: bool = Field(default=True)
    sensitive: bool = Field(default=False)
    timeout_class: str = Field(default="normal")


# Canonical registry — v1 is read-only only
REGISTRY: dict[str, Operation] = {
    "get_system_summary": Operation(
        name="get_system_summary",
        description="Get device system summary (uptime, version, model)",
        backend_method="get_system_summary",
        read_only=True,
    ),
    "get_interfaces": Operation(
        name="get_interfaces",
        description="List network interfaces",
        backend_method="get_interfaces",
        read_only=True,
    ),
    "get_bridge_ports": Operation(
        name="get_bridge_ports",
        description="List bridge port memberships",
        backend_method="get_bridge_ports",
        read_only=True,
    ),
    "get_bridge_vlans": Operation(
        name="get_bridge_vlans",
        description="List bridge VLAN configurations",
        backend_method="get_bridge_vlans",
        read_only=True,
    ),
    "get_routes": Operation(
        name="get_routes",
        description="List routing table entries",
        backend_method="get_routes",
        timeout_class="normal",
        read_only=True,
    ),

    "get_routing_tables": Operation(
        name="get_routing_tables",
        description="List RouterOS routing tables",
        backend_method="get_routing_tables",
        timeout_class="normal",
        read_only=True,
    ),
    "get_routing_rules": Operation(
        name="get_routing_rules",
        description="List RouterOS routing rules",
        backend_method="get_routing_rules",
        timeout_class="normal",
        read_only=True,
    ),
    "get_firewall_filter": Operation(
        name="get_firewall_filter",
        description="List firewall filter rules",
        backend_method="get_firewall_filter",
        timeout_class="normal",
        read_only=True,
    ),
    "get_firewall_nat": Operation(
        name="get_firewall_nat",
        description="List NAT rules",
        backend_method="get_firewall_nat",
        timeout_class="normal",
        read_only=True,
    ),
    "get_firewall_mangle": Operation(
        name="get_firewall_mangle",
        description="List mangle rules",
        backend_method="get_firewall_mangle",
        timeout_class="normal",
        read_only=True,
    ),
    "get_address_lists": Operation(
        name="get_address_lists",
        description="List firewall address lists",
        backend_method="get_address_lists",
        read_only=True,
    ),
    "get_dhcp_leases": Operation(
        name="get_dhcp_leases",
        description="List DHCP lease entries",
        backend_method="get_dhcp_leases",
        read_only=True,
    ),
    "get_arp": Operation(
        name="get_arp",
        description="List ARP table entries",
        backend_method="get_arp",
        read_only=True,
    ),
    "get_recent_logs": Operation(
        name="get_recent_logs",
        description="Get recent system log entries",
        backend_method="get_recent_logs",
        timeout_class="slow",
        read_only=True,
    ),
    "get_qos_queues": Operation(
        name="get_qos_queues",
        description="List QSimple queue entries",
        backend_method="get_qos_queues",
        read_only=True,
    ),

    "get_queue_tree": Operation(
        name="get_queue_tree",
        description="List queue tree entries",
        backend_method="get_queue_tree",
        timeout_class="normal",
        read_only=True,
    ),
    "get_queue_types": Operation(
        name="get_queue_types",
        description="List queue type definitions",
        backend_method="get_queue_types",
        timeout_class="normal",
        read_only=True,
    ),
    "get_wireguard_interfaces": Operation(
        name="get_wireguard_interfaces",
        description="List WireGuard interfaces",
        backend_method="get_wireguard_interfaces",
        sensitive=True,
        read_only=True,
    ),
    "get_wireguard_peers": Operation(
        name="get_wireguard_peers",
        description="List WireGuard peers",
        backend_method="get_wireguard_peers",
        sensitive=True,
        read_only=True,
    ),
    "get_ip_services": Operation(
        name="get_ip_services",
        description="List RouterOS management service configuration",
        backend_method="get_ip_services",
        sensitive=True,
        read_only=True,
    ),
    "get_dhcp_servers": Operation(
        name="get_dhcp_servers",
        description="List DHCP server configuration",
        backend_method="get_dhcp_servers",
        read_only=True,
    ),
    "get_backup_info": Operation(
        name="get_backup_info",
        description="Get backup file metadata (no content download)",
        backend_method="get_backup_info",
        read_only=True,
    ),
    "get_dns_config": Operation(
        name="get_dns_config",
        description="Get DNS configuration",
        backend_method="get_dns_config",
        read_only=True,
    ),
    "get_firmware_version": Operation(
        name="get_firmware_version",
        description="Get RouterOS firmware version",
        backend_method="get_firmware_version",
        read_only=True,
    ),
    "get_snmp_config": Operation(
        name="get_snmp_config",
        description="Get SNMP configuration",
        backend_method="get_snmp_config",
        sensitive=True,
        read_only=True,
    ),
}


def get_operation(name: str) -> Operation:
    """Look up an operation by name. Raises ValueError if unknown."""
    op = REGISTRY.get(name)
    if op is None:
        raise ValueError(f"Unknown or denied operation: {name!r}")
    if not op.read_only:
        raise ValueError(f"Operation {name!r} is not read-only and denied in v1")
    return op


def list_operations() -> list[str]:
    """Return sorted list of all operation names."""
    return sorted(REGISTRY.keys())
