"""Service layer — validates device IDs, routes to backends, applies redaction.

Device IDs must exist in inventory and be allowed. Fleet calls return partial
results; one failed device does not fail the whole call. All returned payloads
are redacted.

Transport dispatch: each device's `transport` field determines which backend
handles the call. Supported transports: fixture, api, ssh.
"""

from __future__ import annotations

import logging
import pathlib
from typing import Any

from .backends.base import BackendProtocol
from .backends.fixture import FixtureBackend
from .config import DeviceInventory, PolicyBaseline, load_inventory, load_policy
from .redaction import redact, safe_error_label
from .registry import get_operation

logger = logging.getLogger(__name__)


class ServiceError(Exception):
    """Sanitized service-boundary error safe to expose to MCP clients."""

    def __init__(self, error_class: str):
        self.error_class = error_class
        super().__init__(error_class)


class Service:
    """Central service coordinating inventory, backends, and redaction."""

    def __init__(
        self,
        inventory: DeviceInventory,
        backends: dict[str, BackendProtocol],
        policy: PolicyBaseline | None = None,
        transport_override: str | None = None,
    ):
        self.inventory = inventory
        self.backends = backends  # transport name -> BackendProtocol
        self.policy = policy
        self.transport_override = transport_override

    @classmethod
    def from_config(
        cls,
        devices_path: pathlib.Path,
        fixture_dir: pathlib.Path,
        policy_path: pathlib.Path | None = None,
        transport_override: str | None = None,
    ) -> Service:
        """Build a Service from config paths.

        Creates both a fixture backend and (if available) a live API backend.
        Devices are dispatched to the appropriate backend based on their
        `transport` field in the inventory.
        """
        inventory = load_inventory(devices_path)
        policy = load_policy(policy_path) if policy_path else None

        backends: dict[str, BackendProtocol] = {}

        # Always create fixture backend
        fixture = FixtureBackend(fixture_dir)
        backends["fixture"] = fixture

        # Fixture-only mode must not construct a live backend. Live access is
        # available only when callers explicitly select inventory transports.
        if transport_override != "fixture":
            try:
                from .backends.routeros_api import RouterOSAPIBackend  # noqa: PLC0414

                live = RouterOSAPIBackend(inventory.devices)
                backends["api"] = live
            except ImportError:
                pass  # librouteros not installed, live transport unavailable

        return cls(inventory, backends, policy, transport_override=transport_override)

    def _get_backend(self, device_id: str) -> BackendProtocol:
        """Select the backend for a device based on its transport field."""
        entry = self.inventory.devices.get(device_id)
        if entry is None:
            raise ValueError(f"Unknown device ID: {device_id!r}")

        transport = self.transport_override or entry.transport
        if transport in self.backends:
            return self.backends[transport]

        raise ValueError(
            f"No backend available for transport {transport!r} on device {device_id!r}. "
            f"Available: {list(self.backends.keys())}"
        )

    def _validate_device(self, device_id: str) -> dict[str, Any]:
        """Validate that a device exists and is allowed. Raises ValueError."""
        entry = self.inventory.devices.get(device_id)
        if entry is None:
            raise ValueError(f"Unknown device ID: {device_id!r}")
        if not entry.allowed:
            raise ValueError(f"Device {device_id!r} is not allowed for MCP access")
        return entry.model_dump()

    def _call_backend(self, device_id: str, method_name: str, **kwargs: Any) -> Any:
        """Call a backend method for a device, applying redaction."""
        self._validate_device(device_id)
        operation = get_operation(method_name)
        if not operation.read_only:
            raise ValueError(f"Operation {method_name!r} is not read-only and is denied")

        backend = self._get_backend(device_id)
        method = getattr(backend, method_name)
        try:
            result = method(device_id, **kwargs)
            return redact(result)
        except Exception as exc:
            error_class = safe_error_label(exc)
            logger.error(
                "backend operation failed",
                extra={
                    "device_id": device_id,
                    "operation": method_name,
                    "exception_class": exc.__class__.__name__,
                    "error_class": error_class,
                },
            )
            raise ServiceError(error_class) from None

    # ── Single-device collectors ─────────────────────────────────────

    def get_device_summary(self, device_id: str) -> dict[str, Any]:
        summary = self._call_backend(device_id, "get_system_summary")
        entry = self._validate_device(device_id)
        return {"device_id": device_id, "role": entry["role"], **summary}

    def get_device_role(self, device_id: str) -> str:
        """Return the inventory role for a validated device."""
        return str(self._validate_device(device_id)["role"])

    def device_has_tag(self, device_id: str, tag: str) -> bool:
        """Return whether a validated device has a specific inventory tag."""
        entry = self._validate_device(device_id)
        return tag in set(entry.get("tags", []))

    def get_interfaces(self, device_id: str) -> list[dict[str, Any]]:
        return self._call_backend(device_id, "get_interfaces")

    def get_bridge_ports(self, device_id: str) -> list[dict[str, Any]]:
        return self._call_backend(device_id, "get_bridge_ports")

    def get_bridge_vlans(self, device_id: str) -> list[dict[str, Any]]:
        return self._call_backend(device_id, "get_bridge_vlans")

    def get_routes(self, device_id: str) -> list[dict[str, Any]]:
        return self._call_backend(device_id, "get_routes")

    def get_routing_tables(self, device_id: str) -> list[dict[str, Any]]:
        return self._call_backend(device_id, "get_routing_tables")

    def get_routing_rules(self, device_id: str) -> list[dict[str, Any]]:
        return self._call_backend(device_id, "get_routing_rules")

    def get_firewall_filter(self, device_id: str) -> list[dict[str, Any]]:
        return self._call_backend(device_id, "get_firewall_filter")

    def get_firewall_nat(self, device_id: str) -> list[dict[str, Any]]:
        return self._call_backend(device_id, "get_firewall_nat")

    def get_firewall_mangle(self, device_id: str) -> list[dict[str, Any]]:
        return self._call_backend(device_id, "get_firewall_mangle")

    def get_address_lists(self, device_id: str) -> list[dict[str, Any]]:
        return self._call_backend(device_id, "get_address_lists")

    def get_dhcp_leases(self, device_id: str) -> list[dict[str, Any]]:
        return self._call_backend(device_id, "get_dhcp_leases")

    def get_arp(self, device_id: str) -> list[dict[str, Any]]:
        return self._call_backend(device_id, "get_arp")

    def get_recent_logs(
        self, device_id: str, minutes: int = 60, topics: list[str] | None = None
    ) -> list[dict[str, Any]]:
        return self._call_backend(device_id, "get_recent_logs", minutes=minutes, topics=topics)

    def get_qos_queues(self, device_id: str) -> list[dict[str, Any]]:
        return self._call_backend(device_id, "get_qos_queues")

    def get_queue_tree(self, device_id: str) -> list[dict[str, Any]]:
        return self._call_backend(device_id, "get_queue_tree")

    def get_queue_types(self, device_id: str) -> list[dict[str, Any]]:
        return self._call_backend(device_id, "get_queue_types")

    def get_wireguard_interfaces(self, device_id: str) -> list[dict[str, Any]]:
        return self._call_backend(device_id, "get_wireguard_interfaces")

    def get_wireguard_peers(self, device_id: str) -> list[dict[str, Any]]:
        return self._call_backend(device_id, "get_wireguard_peers")

    def get_ip_services(self, device_id: str) -> list[dict[str, Any]]:
        return self._call_backend(device_id, "get_ip_services")

    def get_dhcp_servers(self, device_id: str) -> list[dict[str, Any]]:
        return self._call_backend(device_id, "get_dhcp_servers")

    def get_backup_info(self, device_id: str) -> list[dict[str, Any]]:
        return self._call_backend(device_id, "get_backup_info")

    def get_dns_config(self, device_id: str) -> dict[str, Any]:
        return self._call_backend(device_id, "get_dns_config")

    def get_firmware_version(self, device_id: str) -> str:
        return self._call_backend(device_id, "get_firmware_version")

    def get_snmp_config(self, device_id: str) -> dict[str, Any]:
        return self._call_backend(device_id, "get_snmp_config")

    # ── Fleet methods ────────────────────────────────────────────────

    def list_devices(self) -> list[dict[str, Any]]:
        """Return redacted device list (no secrets)."""
        return [
            {
                "device_id": dev_id,
                "role": entry.role,
                "risk": entry.risk,
                "transport": entry.transport,
                "allowed": entry.allowed,
                "tags": entry.tags,
            }
            for dev_id, entry in self.inventory.devices.items()
        ]

    def fleet_call(
        self, method_name: str, device_ids: list[str] | None = None, **kwargs: Any
    ) -> dict[str, Any]:
        """Call a backend method across multiple devices, returning partial results."""
        targets = device_ids or list(self.inventory.devices.keys())
        results: dict[str, Any] = {}
        errors: dict[str, str] = {}

        for dev_id in targets:
            try:
                results[dev_id] = self._call_backend(dev_id, method_name, **kwargs)
            except Exception as exc:
                errors[dev_id] = safe_error_label(exc)

        return {
            "results": results,
            "errors": errors,
            "total": len(targets),
            "succeeded": len(results),
            "failed": len(errors),
        }

    # ── Audit helpers ────────────────────────────────────────────────

    def get_policy(self) -> PolicyBaseline | None:
        """Return loaded policy (may be None)."""
        return self.policy
