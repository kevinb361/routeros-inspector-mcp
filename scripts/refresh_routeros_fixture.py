#!/usr/bin/env python3
"""Capture a private, credential-redacted RouterOS fixture via a read-only wrapper.

The result still reveals topology and policy and must not be committed. Use
--from-artifacts to regenerate from an existing artifact directory without touching devices.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FIXTURE_DIR = ROOT / "artifacts" / "private-fixtures"
REDACTED = "***REDACTED***"

COMMANDS = {
    "system-resource": "/system resource print",
    "system-identity": "/system identity print",
    "system-routerboard": "/system routerboard print",
    "interfaces": "/interface print",
    "bridge-ports": "/interface bridge port print",
    "bridge-vlans": "/interface bridge vlan print",
    "routes": "/ip route print",
    "routing-tables": "/routing table print",
    "routing-rules": "/routing rule print",
    "firewall-filter": "/ip firewall filter print",
    "firewall-nat": "/ip firewall nat print",
    "firewall-mangle": "/ip firewall mangle print",
    "address-lists": "/ip firewall address-list print",
    "dhcp-leases": "/ip dhcp-server lease print",
    "arp": "/ip arp print",
    "recent-logs": "/log print",
    "qos-queues": "/queue simple print",
    "queue-tree": "/queue tree print",
    "queue-types": "/queue type print",
    "wireguard-interfaces": "/interface wireguard print",
    "wireguard-peers": "/interface wireguard peers print",
    "ip-services": "/ip service print",
    "dhcp-servers": "/ip dhcp-server print",
    "backup-info": "/file print",
    "dns-config": "/ip dns print",
    "snmp-config": "/snmp print",
    "snmp-community": "/snmp community print",
}

MAC_RE = re.compile(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b")
STRIP_KEYS = {".id", ".nextid", "debug-info", "debug_info", "engine-id", "engine_id"}
SECRET_VALUE_KEYS = {
    "mac_address",
    "mac-address",
    "serial_number",
    "serial-number",
    "authentication_password",
    "authentication-password",
    "encryption_password",
    "encryption-password",
    "password",
    "secret",
    "private_key",
    "private-key",
    "pre_shared_key",
    "pre-shared-key",
    "public_key",
    "public-key",
}


def capture_artifacts(args: argparse.Namespace) -> Path:
    run_id = args.run_id or f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_routeros_inspector_mcp_{args.device_id}_live"
    artifact_dir = args.ansible_root / args.artifact_root / run_id

    for suffix, command in COMMANDS.items():
        vars_data = {
            "network_readonly_command": command,
            "network_readonly_run_id": run_id,
            "network_readonly_output_suffix": suffix,
            "routeros_readonly_transport": "api",
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as var_file:
            json.dump(vars_data, var_file)
            var_path = Path(var_file.name)
        try:
            cmd = [
                "ansible-playbook",
                "-i",
                str(args.inventory_path),
                str(args.playbook_path),
                "--limit",
                args.device_id,
                "-e",
                f"@{var_path}",
                "--vault-password-file",
                args.vault_password_file,
            ]
            print(f"capture {args.device_id}: {suffix}: {command}", flush=True)
            subprocess.run(cmd, cwd=args.ansible_root, check=True)
        finally:
            var_path.unlink(missing_ok=True)

    return artifact_dir


def load_json_artifact(artifact_dir: Path, device_id: str, suffix: str) -> list[dict[str, Any]]:
    path = artifact_dir / f"{device_id}__{suffix}.txt"
    text = path.read_text()
    text = re.sub(r"^# Command:.*\n\n", "", text, count=1)
    payload = json.loads(text)
    if not isinstance(payload, list):
        raise TypeError(f"{path} did not contain a JSON list")
    return payload


def first(artifact_dir: Path, device_id: str, suffix: str) -> dict[str, Any]:
    rows = load_json_artifact(artifact_dir, device_id, suffix)
    return rows[0] if rows else {}


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            normalized = key.lower().replace("-", "_")
            if key in STRIP_KEYS or normalized in STRIP_KEYS:
                continue
            if key in SECRET_VALUE_KEYS or normalized in SECRET_VALUE_KEYS:
                out[key] = REDACTED
            else:
                out[key] = redact(item)
        return out
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        value = MAC_RE.sub(REDACTED, value)
        if value == "public":
            return REDACTED
        return value
    return value


def pick(row: dict[str, Any], keys: list[tuple[str, str]]) -> dict[str, Any]:
    return {out_key: redact(row[src_key]) for src_key, out_key in keys if src_key in row}


def simple_rules(artifact_dir: Path, device_id: str, suffix: str) -> list[dict[str, Any]]:
    return [
        pick(
            row,
            [
                ("chain", "chain"),
                ("action", "action"),
                ("src-address", "src_address"),
                ("dst-address", "dst_address"),
                ("protocol", "protocol"),
                ("dst-port", "dst_port"),
                ("disabled", "disabled"),
                ("comment", "comment"),
                ("connection-state", "connection_state"),
                ("connection-mark", "connection_mark"),
                ("new-connection-mark", "new_connection_mark"),
                ("packet-mark", "packet_mark"),
                ("new-packet-mark", "new_packet_mark"),
                ("routing-mark", "routing_mark"),
                ("new-routing-mark", "new_routing_mark"),
                ("new-routing-table", "new_routing_table"),
                ("dscp", "dscp"),
                ("new-dscp", "new_dscp"),
                ("passthrough", "passthrough"),
                ("in-interface", "in_interface"),
                ("out-interface", "out_interface"),
                ("src-address-list", "src_address_list"),
                ("dst-address-list", "dst_address_list"),
            ],
        )
        for row in load_json_artifact(artifact_dir, device_id, suffix)
    ]


def build_fixture(artifact_dir: Path, device_id: str) -> dict[str, Any]:
    resource = first(artifact_dir, device_id, "system-resource")
    identity = first(artifact_dir, device_id, "system-identity")
    routerboard = first(artifact_dir, device_id, "system-routerboard")
    dns = first(artifact_dir, device_id, "dns-config")
    snmp = first(artifact_dir, device_id, "snmp-config")
    snmp_community = first(artifact_dir, device_id, "snmp-community")

    backup_info = []
    for row in load_json_artifact(artifact_dir, device_id, "backup-info"):
        name = str(row.get("name", ""))
        if row.get("type") in {"backup", "script"} or name.endswith((".backup", ".rsc")):
            backup_info.append(
                {
                    "name": name,
                    "size": str(row.get("size", "")),
                    "created": row.get("creation-time") or row.get("last-modified", ""),
                    "type": row.get("type"),
                }
            )

    fixture = {
        "_provenance": {
            "source": "private read-only RouterOS capture via operator-supplied wrapper",
            "artifact_dir": str(artifact_dir),
            "source_note": f"{device_id} live capture",
            "last_verified": datetime.now().date().isoformat(),
            "sanitized": True,
            "redactions": [
                "mac_addresses",
                "serial_numbers",
                "snmp_community",
                "snmp_authentication",
                "snmp_encryption",
                "wireguard_keys",
                "routeros_service_certificates",
            ],
        },
        "system_summary": {
            "name": identity.get("name", device_id),
            "device_id_hint": device_id,
            "uptime": resource.get("uptime", ""),
            "version": str(resource.get("version", "")).split()[0],
            "model": routerboard.get("model") or resource.get("board-name", ""),
            "board": resource.get("board-name", ""),
            "cpu": resource.get("cpu", ""),
            "memory_total": resource.get("total-memory"),
            "memory_free": resource.get("free-memory"),
        },
        "interfaces": [
            pick(row, [("name", "name"), ("type", "type"), ("disabled", "disabled"), ("running", "running"), ("comment", "comment")])
            for row in load_json_artifact(artifact_dir, device_id, "interfaces")
        ],
        "bridge_ports": [
            pick(
                row,
                [
                    ("bridge", "bridge"),
                    ("interface", "interface"),
                    ("pvid", "pvid"),
                    ("edge", "edge"),
                    ("frame-types", "frame_types"),
                    ("trusted", "trusted"),
                    ("disabled", "disabled"),
                    ("comment", "comment"),
                ],
            )
            for row in load_json_artifact(artifact_dir, device_id, "bridge-ports")
        ],
        "bridge_vlans": [
            pick(
                row,
                [
                    ("bridge", "bridge"),
                    ("vlan-ids", "vlan_ids"),
                    ("tagged", "tagged"),
                    ("untagged", "untagged"),
                    ("disabled", "disabled"),
                    ("dynamic", "dynamic"),
                    ("comment", "comment"),
                ],
            )
            for row in load_json_artifact(artifact_dir, device_id, "bridge-vlans")
        ],
        "routes": [
            pick(
                row,
                [
                    ("dst-address", "dst_address"),
                    ("gateway", "gateway"),
                    ("distance", "distance"),
                    ("routing-table", "routing_table"),
                    ("disabled", "disabled"),
                    ("dynamic", "dynamic"),
                    ("active", "active"),
                    ("comment", "comment"),
                ],
            )
            for row in load_json_artifact(artifact_dir, device_id, "routes")
        ],
        "routing_tables": [
            pick(row, [("name", "name"), ("fib", "fib"), ("disabled", "disabled"), ("comment", "comment")])
            for row in load_json_artifact(artifact_dir, device_id, "routing-tables")
        ],
        "routing_rules": [
            pick(
                row,
                [
                    ("action", "action"),
                    ("src-address", "src_address"),
                    ("dst-address", "dst_address"),
                    ("interface", "interface"),
                    ("routing-mark", "routing_mark"),
                    ("table", "table"),
                    ("min-prefix", "min_prefix"),
                    ("disabled", "disabled"),
                    ("comment", "comment"),
                ],
            )
            for row in load_json_artifact(artifact_dir, device_id, "routing-rules")
        ],
        "firewall_filter": simple_rules(artifact_dir, device_id, "firewall-filter"),
        "firewall_nat": simple_rules(artifact_dir, device_id, "firewall-nat"),
        "firewall_mangle": simple_rules(artifact_dir, device_id, "firewall-mangle"),
        "address_lists": [
            pick(row, [("list", "list"), ("address", "address"), ("disabled", "disabled"), ("comment", "comment")])
            for row in load_json_artifact(artifact_dir, device_id, "address-lists")
        ],
        "dhcp_leases": [
            pick(
                row,
                [
                    ("address", "address"),
                    ("active-address", "active_address"),
                    ("server", "server"),
                    ("host-name", "host_name"),
                    ("status", "status"),
                    ("dynamic", "dynamic"),
                    ("disabled", "disabled"),
                    ("mac-address", "mac_address"),
                ],
            )
            for row in load_json_artifact(artifact_dir, device_id, "dhcp-leases")
        ],
        "arp": [
            pick(row, [("interface", "interface"), ("address", "ip_address"), ("mac-address", "mac_address"), ("dynamic", "dynamic"), ("complete", "complete")])
            for row in load_json_artifact(artifact_dir, device_id, "arp")
        ],
        "recent_logs": [],
        "qos_queues": [
            pick(row, [("name", "name"), ("target", "target"), ("queue", "queue"), ("priority", "priority"), ("max-limit", "max_limit"), ("disabled", "disabled"), ("comment", "comment")])
            for row in load_json_artifact(artifact_dir, device_id, "qos-queues")
        ],
        "queue_tree": [
            pick(row, [("name", "name"), ("parent", "parent"), ("packet-mark", "packet_mark"), ("queue", "queue"), ("priority", "priority"), ("max-limit", "max_limit"), ("disabled", "disabled"), ("invalid", "invalid"), ("comment", "comment")])
            for row in load_json_artifact(artifact_dir, device_id, "queue-tree")
        ],
        "queue_types": [
            pick(row, [("name", "name"), ("kind", "kind"), ("cake-bandwidth", "cake_bandwidth"), ("cake-diffserv", "cake_diffserv"), ("cake-flowmode", "cake_flowmode"), ("cake-nat", "cake_nat"), ("disabled", "disabled"), ("comment", "comment")])
            for row in load_json_artifact(artifact_dir, device_id, "queue-types")
        ],
        "wireguard_interfaces": [
            pick(row, [("name", "name"), ("mtu", "mtu"), ("listen-port", "listen_port"), ("private-key", "private_key"), ("public-key", "public_key"), ("disabled", "disabled"), ("running", "running"), ("comment", "comment")])
            for row in load_json_artifact(artifact_dir, device_id, "wireguard-interfaces")
        ],
        "wireguard_peers": [
            pick(row, [("interface", "interface"), ("public-key", "public_key"), ("preshared-key", "preshared_key"), ("allowed-address", "allowed_address"), ("endpoint-address", "endpoint_address"), ("endpoint-port", "endpoint_port"), ("persistent-keepalive", "persistent_keepalive"), ("last-handshake", "last_handshake"), ("disabled", "disabled"), ("comment", "comment")])
            for row in load_json_artifact(artifact_dir, device_id, "wireguard-peers")
        ],
        "ip_services": [
            pick(row, [("name", "name"), ("port", "port"), ("address", "address"), ("certificate", "certificate"), ("tls-version", "tls_version"), ("vrf", "vrf"), ("disabled", "disabled")])
            for row in load_json_artifact(artifact_dir, device_id, "ip-services")
        ],
        "dhcp_servers": [
            pick(row, [("name", "name"), ("interface", "interface"), ("address-pool", "address_pool"), ("lease-time", "lease_time"), ("disabled", "disabled"), ("comment", "comment")])
            for row in load_json_artifact(artifact_dir, device_id, "dhcp-servers")
        ],
        "backup_info": backup_info,
        "dns_config": {
            "servers": dns.get("servers", ""),
            "use_dns_servers": bool(dns.get("servers")),
            "allow_remote_requests": dns.get("allow-remote-requests", False),
            "dns_over_https": "on" if dns.get("use-doh-server") else "off",
            "dnssec": dns.get("verify-doh-cert", False),
        },
        "firmware_version": str(resource.get("version", "")).split()[0],
        "snmp_config": {
            "enabled": snmp.get("enabled", False),
            "community": REDACTED,
            "community_redacted": True,
            "allowed_addresses": snmp_community.get("addresses", ""),
            "read_access": snmp_community.get("read-access", False),
            "write_access": snmp_community.get("write-access", False),
        },
    }
    return redact(fixture)


def write_fixture(fixture: dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(fixture, indent=2, sort_keys=True) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("device_id", help="Inventory device ID, for example edge-router")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--from-artifacts", type=Path, help="Existing private artifact directory; no network access"
    )
    source.add_argument(
        "--capture-live",
        action="store_true",
        help="Explicitly allow read-only capture through an external Ansible wrapper",
    )
    parser.add_argument("--fixture-dir", type=Path, default=DEFAULT_FIXTURE_DIR)
    parser.add_argument("--ansible-root", type=Path, help="Required with --capture-live")
    parser.add_argument("--inventory-path", type=Path, help="Required with --capture-live")
    parser.add_argument("--playbook-path", type=Path, help="Required with --capture-live")
    parser.add_argument(
        "--artifact-root", type=Path, default=Path("artifacts/network-readonly")
    )
    parser.add_argument("--run-id", help="Optional artifact run id for live capture")
    parser.add_argument("--vault-password-file", help="Required with --capture-live")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.capture_live:
        required = {
            "--ansible-root": args.ansible_root,
            "--inventory-path": args.inventory_path,
            "--playbook-path": args.playbook_path,
            "--vault-password-file": args.vault_password_file,
        }
        missing = [option for option, value in required.items() if value is None]
        if missing:
            parser.error(f"--capture-live requires {', '.join(missing)}")
        artifact_dir = capture_artifacts(args)
    else:
        artifact_dir = args.from_artifacts
        if artifact_dir is None:  # argparse enforces this; retain a fail-closed type guard.
            parser.error("--from-artifacts is required unless --capture-live is set")
    fixture = build_fixture(artifact_dir, args.device_id)
    output_path = args.fixture_dir / f"{args.device_id}.json"
    write_fixture(fixture, output_path)
    print(json.dumps({"ok": True, "device_id": args.device_id, "artifact_dir": str(artifact_dir), "fixture": str(output_path)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
