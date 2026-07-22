"""FastMCP server — exposes read-only tools and audits.

No tool accepts host/IP or command text. All tools return JSON-serializable
dicts. All outputs are redacted.
"""

from __future__ import annotations

import argparse
import pathlib
from typing import Any

from fastmcp import FastMCP

from . import __version__
from .audit_log import AuditLogger
from .audits.backup_retention import audit_backup_retention
from .audits.base import AuditResult
from .audits.dead_mangle import audit_dead_mangle_rules
from .audits.dscp import audit_dscp_policy
from .audits.encrypted_dns import audit_encrypted_dns
from .audits.mangle_queue_correlation import audit_mangle_queue_correlation
from .audits.policy_backed import (
    audit_default_route_sanity,
    audit_firmware_drift,
    audit_route_ownership,
    audit_snmp_scope,
    audit_stp_edge,
    audit_trunk_vlan_sanity,
    audit_vlan_consistency,
    audit_wan_failover_state,
)
from .audits.qos import audit_qos_state
from .redaction import safe_error_label
from .service import Service

# ── Audit registry ─────────────────────────────────────────────────────

MAX_AUDIT_FANOUT = 128
EXAMPLES_DIR = pathlib.Path(__file__).resolve().parent / "examples"

AUDIT_REGISTRY: dict[str, Any] = {
    "qos_state": audit_qos_state,
    "dead_mangle_rules": audit_dead_mangle_rules,
    "dscp_policy": audit_dscp_policy,
    "encrypted_dns": audit_encrypted_dns,
    "backup_retention": audit_backup_retention,
    "mangle_queue_correlation": audit_mangle_queue_correlation,
    "firmware_drift": audit_firmware_drift,
    "snmp_scope": audit_snmp_scope,
    "stp_edge": audit_stp_edge,
    "vlan_consistency": audit_vlan_consistency,
    "trunk_vlan_sanity": audit_trunk_vlan_sanity,
    "route_ownership": audit_route_ownership,
    "default_route_sanity": audit_default_route_sanity,
    "wan_failover_state": audit_wan_failover_state,
}

# ── Server factory ─────────────────────────────────────────────────────


def create_server(
    devices_path: pathlib.Path | None = None,
    fixture_dir: pathlib.Path | None = None,
    policy_path: pathlib.Path | None = None,
    audit_log_path: pathlib.Path | None = None,
    fixture_only: bool = True,
) -> FastMCP:
    """Create and configure the FastMCP server."""
    app = FastMCP(
        name="routeros-inspector",
        instructions="Read-only MCP for MikroTik RouterOS fleet inspection and audits. No mutations.",
    )

    # Defaults if not specified
    if devices_path is None:
        devices_path = EXAMPLES_DIR / "devices.yaml"
    if fixture_dir is None:
        fixture_dir = EXAMPLES_DIR / "fixtures"
    if policy_path is None:
        policy_path = EXAMPLES_DIR / "policy.yaml"
    if audit_log_path is None:
        audit_log_path = pathlib.Path.cwd() / "logs" / "audit.jsonl"

    service = Service.from_config(
        devices_path,
        fixture_dir,
        policy_path,
        transport_override="fixture" if fixture_only else None,
    )
    logger = AuditLogger(audit_log_path)

    # ── Core tools ───────────────────────────────────────────────────

    @app.tool(description="List available capabilities (read-only tools and audits). Read-only.")
    def get_capabilities() -> dict:
        return {
            "version": __version__,
            "mode": "read-only",
            "devices_count": len(service.inventory.devices),
            "max_audit_fanout": MAX_AUDIT_FANOUT,
            "collectors": [
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
                "get_routing_tables",
                "get_routing_rules",
                "get_queue_tree",
                "get_queue_types",
                "get_wireguard_interfaces",
                "get_wireguard_peers",
                "get_ip_services",
                "get_dhcp_servers",
            ],
            "audits": list(AUDIT_REGISTRY.keys()),
        }

    @app.tool(description="List all devices in the inventory. Read-only.")
    def list_devices() -> list[dict]:
        with logger.track("list_devices"):
            return service.list_devices()

    @app.tool(description="Get system summary for a device. Read-only.")
    def get_device_summary(device: str) -> dict:
        with logger.track("get_device_summary", [device]):
            return service.get_device_summary(device)

    @app.tool(description="List network interfaces. Read-only.")
    def get_interfaces(device: str) -> list[dict]:
        with logger.track("get_interfaces", [device]):
            return service.get_interfaces(device)

    @app.tool(description="List bridge port memberships. Read-only.")
    def get_bridge_ports(device: str) -> list[dict]:
        with logger.track("get_bridge_ports", [device]):
            return service.get_bridge_ports(device)

    @app.tool(description="List bridge VLAN configurations. Read-only.")
    def get_bridge_vlans(device: str) -> list[dict]:
        with logger.track("get_bridge_vlans", [device]):
            return service.get_bridge_vlans(device)

    @app.tool(description="List routing table entries. Read-only.")
    def get_routes(device: str) -> list[dict]:
        with logger.track("get_routes", [device]):
            return service.get_routes(device)

    @app.tool(description="List routing tables. Read-only.")
    def get_routing_tables(device: str) -> list[dict]:
        with logger.track("get_routing_tables", [device]):
            return service.get_routing_tables(device)

    @app.tool(description="List routing rules. Read-only.")
    def get_routing_rules(device: str) -> list[dict]:
        with logger.track("get_routing_rules", [device]):
            return service.get_routing_rules(device)

    @app.tool(description="List firewall filter rules. Read-only.")
    def get_firewall_filter(device: str) -> list[dict]:
        with logger.track("get_firewall_filter", [device]):
            return service.get_firewall_filter(device)

    @app.tool(description="List NAT rules. Read-only.")
    def get_firewall_nat(device: str) -> list[dict]:
        with logger.track("get_firewall_nat", [device]):
            return service.get_firewall_nat(device)

    @app.tool(description="List mangle rules. Read-only.")
    def get_firewall_mangle(device: str) -> list[dict]:
        with logger.track("get_firewall_mangle", [device]):
            return service.get_firewall_mangle(device)

    @app.tool(description="List firewall address lists. Read-only.")
    def get_address_lists(device: str) -> list[dict]:
        with logger.track("get_address_lists", [device]):
            return service.get_address_lists(device)

    @app.tool(description="List DHCP lease entries. Read-only.")
    def get_dhcp_leases(device: str) -> list[dict]:
        with logger.track("get_dhcp_leases", [device]):
            return service.get_dhcp_leases(device)

    @app.tool(description="List ARP table entries. Read-only.")
    def get_arp(device: str) -> list[dict]:
        with logger.track("get_arp", [device]):
            return service.get_arp(device)

    @app.tool(description="Get recent system log entries. Read-only.")
    def get_recent_logs(
        device: str, minutes: int = 60, topics: list[str] | None = None
    ) -> list[dict]:
        with logger.track("get_recent_logs", [device]):
            return service.get_recent_logs(device, minutes=minutes, topics=topics)

    @app.tool(description="List queue tree entries. Read-only.")
    def get_queue_tree(device: str) -> list[dict]:
        with logger.track("get_queue_tree", [device]):
            return service.get_queue_tree(device)

    @app.tool(description="List queue type definitions. Read-only.")
    def get_queue_types(device: str) -> list[dict]:
        with logger.track("get_queue_types", [device]):
            return service.get_queue_types(device)

    @app.tool(description="List WireGuard interfaces with secrets redacted. Read-only.")
    def get_wireguard_interfaces(device: str) -> list[dict]:
        with logger.track("get_wireguard_interfaces", [device]):
            return service.get_wireguard_interfaces(device)

    @app.tool(description="List WireGuard peers with secrets redacted. Read-only.")
    def get_wireguard_peers(device: str) -> list[dict]:
        with logger.track("get_wireguard_peers", [device]):
            return service.get_wireguard_peers(device)

    @app.tool(
        description="List RouterOS management IP services with sensitive fields redacted. Read-only."
    )
    def get_ip_services(device: str) -> list[dict]:
        with logger.track("get_ip_services", [device]):
            return service.get_ip_services(device)

    @app.tool(description="List DHCP server configuration. Read-only.")
    def get_dhcp_servers(device: str) -> list[dict]:
        with logger.track("get_dhcp_servers", [device]):
            return service.get_dhcp_servers(device)

    # ── Audit tools ──────────────────────────────────────────────────

    @app.tool(description="List available audits. Read-only.")
    def list_audits() -> list[str]:
        return sorted(AUDIT_REGISTRY.keys())

    @app.tool(
        description="Run one or more audits on one or more devices. Read-only. Pass audits as a list of audit names, device_ids as a list of device IDs. Omit either to run all."
    )
    def run_audit(
        audits: list[str] | None = None, device_ids: list[str] | None = None
    ) -> list[dict]:
        audit_names = list(dict.fromkeys(audits or AUDIT_REGISTRY.keys()))
        targets = list(dict.fromkeys(device_ids or service.inventory.devices.keys()))
        if any(audit_name not in AUDIT_REGISTRY for audit_name in audit_names):
            raise ValueError("Unknown audit requested")
        if any(device_id not in service.inventory.devices for device_id in targets):
            raise ValueError("Unknown device requested")

        fanout = len(audit_names) * len(targets)
        if fanout > MAX_AUDIT_FANOUT:
            raise ValueError(f"Audit fan-out {fanout} exceeds limit {MAX_AUDIT_FANOUT}")

        results: list[dict] = []
        with logger.track("run_audit", targets):
            for dev_id in targets:
                for audit_name in audit_names:
                    audit_fn = AUDIT_REGISTRY[audit_name]
                    try:
                        result: AuditResult = audit_fn(service, dev_id)
                        results.append(result.to_dict())
                    except Exception as exc:
                        results.append(
                            {
                                "audit_name": audit_name,
                                "device_id": dev_id,
                                "error": safe_error_label(exc),
                            }
                        )

        return results

    return app


# ── CLI entry point ────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    """Build the MCP server CLI parser."""
    parser = argparse.ArgumentParser(description="Run the read-only RouterOS Inspector MCP server.")
    parser.add_argument(
        "--devices-path",
        type=pathlib.Path,
        default=EXAMPLES_DIR / "devices.yaml",
        help="Path to device inventory YAML (synthetic example by default)",
    )
    parser.add_argument(
        "--policy-path",
        type=pathlib.Path,
        default=EXAMPLES_DIR / "policy.yaml",
        help="Path to policy baseline YAML (synthetic example by default)",
    )
    parser.add_argument(
        "--fixture-dir",
        type=pathlib.Path,
        default=EXAMPLES_DIR / "fixtures",
        help="Path to purpose-built synthetic RouterOS fixture JSON directory",
    )
    parser.add_argument(
        "--audit-log-path",
        type=pathlib.Path,
        default=pathlib.Path.cwd() / "logs" / "audit.jsonl",
        help="Path to audit JSONL log file",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "http", "streamable-http"],
        default="stdio",
        help="FastMCP transport. Hermes stdio integration uses stdio.",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Use each inventory device's live transport. Default is fixture-only.",
    )
    parser.add_argument(
        "--allow-loopback-http",
        action="store_true",
        help="Allow HTTP transport bound to 127.0.0.1. Remote binding is unsupported.",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    """Run the MCP server."""
    parser = build_parser()
    args = parser.parse_args(argv)
    network_transport = args.transport != "stdio"
    if network_transport and not args.allow_loopback_http:
        parser.error("non-stdio transport requires --allow-loopback-http")

    app = create_server(
        devices_path=args.devices_path,
        fixture_dir=args.fixture_dir,
        policy_path=args.policy_path,
        audit_log_path=args.audit_log_path,
        fixture_only=not args.live,
    )
    run_kwargs = {"host": "127.0.0.1"} if network_transport else {}
    app.run(transport=args.transport, show_banner=False, **run_kwargs)


if __name__ == "__main__":
    main()
