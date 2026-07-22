"""Live RouterOS API backend — read-only access via librouteros.

Connects to MikroTik devices over the structured RouterOS API (TCP 8728).
Only performs read operations (print/get). No mutation calls.

Credentials are resolved from the credential resolver module.
"""

from __future__ import annotations

import ssl
from functools import partial
from pathlib import Path
from typing import Any

import librouteros

from ..config import DeviceEntry
from ..credentials import resolve_credentials
from .base import (
    ERROR_AUTH,
    ERROR_UNREACHABLE,
    BackendError,
    BackendProtocol,
)

# Timeout classes in seconds
TIMEOUTS = {"fast": 5, "normal": 15, "slow": 30}

# RouterOS API paths mapped to backend methods
# Each maps to a tuple of path segments (librouteros conn.path(*segments)("print"))
API_PATHS: dict[str, tuple[str, ...]] = {
    "get_system_summary": ("system", "resource"),
    "get_interfaces": ("interface",),
    "get_bridge_ports": ("interface", "bridge", "port"),
    "get_bridge_vlans": ("interface", "bridge", "vlan"),
    "get_routes": ("ip", "route"),
    "get_routing_tables": ("ip", "routing", "table"),
    "get_routing_rules": ("ip", "routing", "rule"),
    "get_firewall_filter": ("ip", "firewall", "filter"),
    "get_firewall_nat": ("ip", "firewall", "nat"),
    "get_firewall_mangle": ("ip", "firewall", "mangle"),
    "get_address_lists": ("ip", "firewall", "address-list"),
    "get_dhcp_leases": ("ip", "dhcp", "lease"),
    "get_arp": ("ip", "arp"),
    "get_recent_logs": ("log",),
    "get_qos_queues": ("queue", "simple"),
    "get_queue_tree": ("queue", "tree"),
    "get_queue_types": ("queue", "type"),
    "get_wireguard_interfaces": ("interface", "wireguard"),
    "get_wireguard_peers": ("interface", "wireguard", "peers"),
    "get_ip_services": ("ip", "service"),
    "get_dhcp_servers": ("ip", "dhcp", "server"),
    "get_backup_info": ("file",),
    "get_dns_config": ("ip", "dns"),
    "get_firmware_version": ("system", "resource"),
    "get_snmp_config": ("snmp",),
}


def _dict_from_api_item(item) -> dict[str, Any]:
    """Convert a librouteros response item to a plain dict.

    librouteros returns ReDict objects where keys use '.' as path separator.
    We convert to plain dicts with '/' separators for consistency.
    Non-ASCII values are decoded with errors='replace'.
    """
    d: dict[str, Any] = {}
    for key, value in item.items():
        k = key.replace(".", "/")
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        elif isinstance(value, str):
            # Some values may contain non-UTF-8 bytes that slipped through
            try:
                value.encode("utf-8")
            except UnicodeEncodeError:
                value = value.encode("latin-1", errors="replace").decode("utf-8", errors="replace")
        elif hasattr(value, "__iter__") and not isinstance(value, (str, bytes)):
            value = list(value)
        d[k] = value
    return d


class RouterOSAPIBackend(BackendProtocol):
    """Live read-only backend using RouterOS API over TCP.

    Each method connects, queries, and disconnects. No persistent connections
    to limit blast radius if the process is compromised.
    """

    def __init__(self, device_inventory: dict[str, DeviceEntry]):
        """Initialize with the live API device inventory."""
        self._devices = device_inventory

    def _resolve_creds(self, entry: DeviceEntry) -> tuple[str, str]:
        """Extract (username, password) from a DeviceEntry's credential_ref.

        credential_ref example: vault:routeros:vault_routeros_readonly
        The resolver needs only the final variable prefix: vault_routeros_readonly
        """
        # Parse credential_ref to extract the vault variable prefix
        ref = entry.credential_ref
        if ":" in ref:
            # Namespaced references use the final segment as the Vault variable prefix.
            var_prefix = ref.rsplit(":", 1)[-1]
        else:
            var_prefix = ref

        creds = resolve_credentials(var_prefix)
        return creds.username, creds.password

    def _connect_kwargs(
        self,
        entry: DeviceEntry,
        username: str,
        password: str,
        *,
        encoding: str,
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "host": entry.host,
            "username": username,
            "password": password,
            "port": entry.routeros_api_port,
            "timeout": 10,
            "encoding": encoding,
        }
        if not entry.routeros_api_tls:
            return kwargs

        certificate = Path(entry.routeros_api_certificate)
        if not certificate.is_file() or certificate.stat().st_size == 0:
            raise BackendError(
                ERROR_UNREACHABLE,
                f"Pinned RouterOS TLS certificate is missing or empty for {entry.host}",
            )
        context = ssl.create_default_context(cafile=str(certificate))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        kwargs["ssl_wrapper"] = partial(
            context.wrap_socket,
            server_hostname=entry.routeros_api_server_name,
        )
        return kwargs

    def _connect(self, device_id: str) -> librouteros.RouterOS:
        """Connect to a device via API. Returns the connection."""
        entry = self._devices[device_id]
        username, password = self._resolve_creds(entry)
        port = entry.routeros_api_port

        try:
            conn = librouteros.connect(
                **self._connect_kwargs(entry, username, password, encoding="UTF-8")
            )
        except librouteros.exceptions.ConnectionClosed:
            raise BackendError(
                ERROR_UNREACHABLE, f"Cannot reach {device_id} at {entry.host}:{port}"
            )
        except librouteros.exceptions.FatalError:
            raise BackendError(ERROR_AUTH, f"Auth failed for {device_id}")
        except Exception as e:
            err_cls = ERROR_UNREACHABLE
            raise BackendError(err_cls, f"Connection failed for {device_id}: {e}") from e

        return conn

    def _query(
        self, device_id: str, path_segments: tuple[str, ...], timeout_class: str = "normal"
    ) -> list[dict[str, Any]]:
        """Run a read-only API query and return a list of dicts."""
        conn: librouteros.RouterOS | None = self._connect(device_id)
        try:
            try:
                items = list(conn.path(*path_segments)("print"))
            except UnicodeDecodeError:
                # Some RouterOS responses contain non-UTF-8 bytes (e.g. binary
                # filenames in /file). Close the UTF-8 connection and retry with
                # latin-1 which maps all byte values to valid characters.
                conn.close()
                conn = None
                conn = self._connect_latin1(device_id)
                items = list(conn.path(*path_segments)("print"))
        except Exception as e:
            raise BackendError(
                ERROR_UNREACHABLE,
                f"Query failed for {device_id} on {'/'.join(path_segments)}: {e}",
            ) from e
        finally:
            if conn is not None:
                conn.close()

        return [_dict_from_api_item(item) for item in items]

    def _connect_latin1(self, device_id: str) -> librouteros.RouterOS:
        """Connect with latin-1 encoding as fallback for non-UTF-8 data."""
        entry = self._devices[device_id]
        username, password = self._resolve_creds(entry)
        try:
            return librouteros.connect(
                **self._connect_kwargs(entry, username, password, encoding="latin-1")
            )
        except Exception as e:
            raise BackendError(ERROR_UNREACHABLE, f"Connection failed for {device_id}: {e}") from e

    def _query_single(self, device_id: str, path_segments: tuple[str, ...]) -> dict[str, Any]:
        """Run a query that returns a single item (e.g. system resource)."""
        items = self._query(device_id, path_segments)
        return items[0] if items else {}

    # ── Protocol implementation ──────────────────────────────────────

    def get_system_summary(self, device_id: str) -> dict[str, Any]:
        raw = self._query_single(device_id, ("system", "resource"))
        # Normalize to the shape fixtures expect
        return {
            "name": raw.get("name", ""),
            "uptime": raw.get("uptime", ""),
            "version": raw.get("version", ""),
            "model": raw.get("board-name", raw.get("model", "")),
            "architecture": raw.get("architecture-name", ""),
            "cpu": raw.get("cpu", ""),
            "cpu-count": raw.get("cpu-count", 0),
            "cpu-load": raw.get("cpu-load", ""),
            "free-memory": raw.get("free-memory", ""),
            "total-memory": raw.get("total-memory", ""),
            "free-hdd-space": raw.get("free-hdd-space", ""),
            "total-hdd-space": raw.get("total-hdd-space", ""),
            "boot-clock-speed": raw.get("boot-clock-speed", ""),
            "bad-blocks": raw.get("bad-blocks", 0),
        }

    def get_interfaces(self, device_id: str) -> list[dict[str, Any]]:
        return self._query(device_id, ("interface",))

    def get_bridge_ports(self, device_id: str) -> list[dict[str, Any]]:
        return self._query(device_id, ("interface", "bridge", "port"))

    def get_bridge_vlans(self, device_id: str) -> list[dict[str, Any]]:
        return self._query(device_id, ("interface", "bridge", "vlan"))

    def get_routes(self, device_id: str) -> list[dict[str, Any]]:
        return self._query(device_id, ("ip", "route"))

    def get_routing_tables(self, device_id: str) -> list[dict[str, Any]]:
        return self._query(device_id, ("ip", "routing", "table"))

    def get_routing_rules(self, device_id: str) -> list[dict[str, Any]]:
        return self._query(device_id, ("ip", "routing", "rule"))

    def get_firewall_filter(self, device_id: str) -> list[dict[str, Any]]:
        return self._query(device_id, ("ip", "firewall", "filter"))

    def get_firewall_nat(self, device_id: str) -> list[dict[str, Any]]:
        return self._query(device_id, ("ip", "firewall", "nat"))

    def get_firewall_mangle(self, device_id: str) -> list[dict[str, Any]]:
        return self._query(device_id, ("ip", "firewall", "mangle"))

    def get_address_lists(self, device_id: str) -> list[dict[str, Any]]:
        return self._query(device_id, ("ip", "firewall", "address-list"))

    def get_dhcp_leases(self, device_id: str) -> list[dict[str, Any]]:
        return self._query(device_id, ("ip", "dhcp", "lease"))

    def get_arp(self, device_id: str) -> list[dict[str, Any]]:
        return self._query(device_id, ("ip", "arp"))

    def get_recent_logs(
        self, device_id: str, minutes: int = 60, topics: list[str] | None = None
    ) -> list[dict[str, Any]]:
        all_logs = self._query(device_id, ("log",))

        if minutes is not None:
            # RouterOS log time format makes precise filtering hard client-side.
            # Return last N entries as a practical limit.
            all_logs = all_logs[-500:]

        if topics:
            all_logs = [
                log_entry
                for log_entry in all_logs
                if any(t in log_entry.get("topics", "") for t in topics)
            ]

        return all_logs

    def get_qos_queues(self, device_id: str) -> list[dict[str, Any]]:
        return self._query(device_id, ("queue", "simple"))

    def get_queue_tree(self, device_id: str) -> list[dict[str, Any]]:
        return self._query(device_id, ("queue", "tree"))

    def get_queue_types(self, device_id: str) -> list[dict[str, Any]]:
        return self._query(device_id, ("queue", "type"))

    def get_wireguard_interfaces(self, device_id: str) -> list[dict[str, Any]]:
        return self._query(device_id, ("interface", "wireguard"))

    def get_wireguard_peers(self, device_id: str) -> list[dict[str, Any]]:
        return self._query(device_id, ("interface", "wireguard", "peers"))

    def get_ip_services(self, device_id: str) -> list[dict[str, Any]]:
        return self._query(device_id, ("ip", "service"))

    def get_dhcp_servers(self, device_id: str) -> list[dict[str, Any]]:
        return self._query(device_id, ("ip", "dhcp", "server"))

    def get_backup_info(self, device_id: str) -> list[dict[str, Any]]:
        files = self._query(device_id, ("file",))
        return [f for f in files if f.get("name", "").endswith((".backup", ".rsc", ".netrc"))]

    def get_dns_config(self, device_id: str) -> dict[str, Any]:
        return self._query_single(device_id, ("ip", "dns"))

    def get_firmware_version(self, device_id: str) -> str:
        raw = self._query_single(device_id, ("system", "resource"))
        return raw.get("version", "unknown")

    def get_snmp_config(self, device_id: str) -> dict[str, Any]:
        main = self._query_single(device_id, ("snmp",))
        communities = self._query(device_id, ("snmp", "community"))
        return {**main, "communities": communities}
