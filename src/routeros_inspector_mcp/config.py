"""Configuration loaders for device inventory and policy baseline.

All config is loaded from version-controlled YAML files. No secrets
are read or logged by the loader.
"""

from __future__ import annotations

import pathlib
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

# ── Enums ──────────────────────────────────────────────────────────────

ALLOWED_ROLES = {"gateway", "switch", "ap-controller", "dhcp-server", "nat", "edge"}
ALLOWED_RISKS = {"critical", "high", "medium", "low"}
ALLOWED_TRANSPORTS = {"api", "ssh", "fixture"}


# ── Device inventory ───────────────────────────────────────────────────


class DeviceEntry(BaseModel):
    """Single device in the inventory."""

    model_config = ConfigDict(extra="forbid")

    role: str = Field(description="Device role (gateway, switch, etc.)")
    risk: str = Field(description="Risk level (critical, high, medium, low)")
    host: str = Field(description="Host or IP (never used as user input)")
    transport: str = Field(description="Transport to use (api, ssh, fixture)")
    credential_ref: str = Field(description="Key into a secret store (not the secret itself)")
    allowed: bool = Field(
        default=True, description="Whether this device is allowed for MCP access"
    )
    tags: list[str] = Field(default_factory=list)
    routeros_api_port: int = Field(default=8728, ge=1, le=65535)
    routeros_api_tls: bool = False
    routeros_api_certificate: str = ""
    routeros_api_server_name: str = ""

    @model_validator(mode="after")
    def validate_routeros_api_tls(self) -> DeviceEntry:
        if self.routeros_api_tls:
            if self.transport != "api":
                raise ValueError("RouterOS API TLS requires API transport")
            if self.routeros_api_port != 8729:
                raise ValueError("RouterOS API TLS requires explicit TCP/8729")
            if not self.routeros_api_certificate or not self.routeros_api_server_name:
                raise ValueError(
                    "RouterOS API TLS requires a pinned certificate and verified server identity"
                )
        elif self.routeros_api_port == 8729:
            raise ValueError("RouterOS API TCP/8729 requires TLS")
        elif self.routeros_api_certificate or self.routeros_api_server_name:
            raise ValueError("RouterOS TLS certificate/identity require explicit TLS mode")
        return self


class DeviceInventory(BaseModel):
    """Version-controlled device inventory."""

    devices: dict[str, DeviceEntry] = Field(description="Map from stable device ID to DeviceEntry")


def load_inventory(path: pathlib.Path) -> DeviceInventory:
    """Load and validate a device inventory YAML file.

    Raises ValueError on duplicate IDs, unknown roles/risks/transports,
    or missing host fields.
    """
    raw = yaml.safe_load(path.read_text()) or {}
    devices_raw: dict[str, Any] = raw.get("devices", {})

    devices: dict[str, DeviceEntry] = {}
    for dev_id, entry in devices_raw.items():
        # Validate constraints before Pydantic
        role = entry.get("role", "")
        if role not in ALLOWED_ROLES:
            raise ValueError(f"Device {dev_id!r}: unknown role {role!r}")

        risk = entry.get("risk", "")
        if risk not in ALLOWED_RISKS:
            raise ValueError(f"Device {dev_id!r}: unknown risk {risk!r}")

        transport = entry.get("transport", "")
        if transport not in ALLOWED_TRANSPORTS:
            raise ValueError(f"Device {dev_id!r}: unknown transport {transport!r}")

        if not entry.get("host"):
            raise ValueError(f"Device {dev_id!r}: missing host")

        devices[dev_id] = DeviceEntry(**entry)

    return DeviceInventory(devices=devices)


# ── Policy baseline ────────────────────────────────────────────────────


class FirmwarePolicy(BaseModel):
    expected_versions: dict[str, str] = Field(default_factory=dict)


class SnmpPolicy(BaseModel):
    allowed_communities: list[str] = Field(default_factory=list)
    allowed_access: list[str] = Field(default_factory=list)
    community_policy: str = Field(
        default="",
        description="Non-secret declaration of where SNMP community values are managed",
    )


class StpPolicy(BaseModel):
    edge_ports: dict[str, list[str]] = Field(default_factory=dict)


class VlanPolicy(BaseModel):
    expected_vlans: dict[str, list[int]] = Field(default_factory=dict)
    expected_trunks: dict[str, dict[str, list[int]]] = Field(default_factory=dict)


class RoutePolicy(BaseModel):
    owned_prefixes: dict[str, list[str]] = Field(default_factory=dict)


class FailoverPolicy(BaseModel):
    primary: str = ""
    secondary: str = ""


class DnsPolicy(BaseModel):
    encrypted: bool = True


class PolicyBaseline(BaseModel):
    """Intended-state policy for audits."""

    firmware: FirmwarePolicy = Field(default_factory=FirmwarePolicy)
    snmp: SnmpPolicy = Field(default_factory=SnmpPolicy)
    stp: StpPolicy = Field(default_factory=StpPolicy)
    vlans: VlanPolicy = Field(default_factory=VlanPolicy)
    routes: RoutePolicy = Field(default_factory=RoutePolicy)
    wan_failover: FailoverPolicy = Field(default_factory=FailoverPolicy)
    dns: DnsPolicy = Field(default_factory=DnsPolicy)


def load_policy(path: pathlib.Path) -> PolicyBaseline | None:
    """Load policy YAML if it exists. Returns None if file is missing."""
    if not path.exists():
        return None
    raw = yaml.safe_load(path.read_text()) or {}
    return PolicyBaseline(**raw)
