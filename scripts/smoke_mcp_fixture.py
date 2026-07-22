#!/usr/bin/env python3
"""Smoke-test the fixture-backed FastMCP server in-process.

This deliberately uses create_server(...) directly instead of spawning a long-lived
stdio process. It exercises the same FastMCP tool surface Hermes will discover,
while keeping the test fast and fixture-only.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import pathlib
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from fastmcp import Client  # noqa: E402

from routeros_inspector_mcp.server import create_server  # noqa: E402

DEFAULT_DEVICES_PATH = ROOT / "config" / "devices.example.yaml"
DEFAULT_POLICY_PATH = ROOT / "config" / "policy.example.yaml"
DEFAULT_FIXTURE_DIR = ROOT / "tests" / "fixtures" / "routeros"
DEFAULT_AUDIT_LOG = ROOT / "logs" / "audit-smoke.jsonl"
REQUIRED_TOOLS = {"list_devices", "list_audits", "run_audit"}


def _json_payload(result: Any) -> Any:
    """Extract JSON payload from a FastMCP CallToolResult."""
    data = getattr(result, "data", None)
    if data is not None:
        return data

    content = getattr(result, "content", [])
    if not content:
        return None
    text = getattr(content[0], "text", None)
    if text is None:
        return None
    return json.loads(text)


async def _run(args: argparse.Namespace) -> dict[str, Any]:
    server = create_server(
        devices_path=args.devices_path,
        fixture_dir=args.fixture_dir,
        policy_path=args.policy_path,
        audit_log_path=args.audit_log_path,
    )

    async with Client(server) as client:
        tools = await client.list_tools()
        tool_names = {tool.name for tool in tools}
        missing = sorted(REQUIRED_TOOLS - tool_names)
        if missing:
            raise RuntimeError(f"Missing required MCP tools: {', '.join(missing)}")

        devices_result = await client.call_tool("list_devices", {})
        devices = _json_payload(devices_result)
        device_ids = {device["device_id"] for device in devices}
        expected_devices = {"edge-router", "core-switch", "branch-switch", "access-switch"}
        missing_devices = sorted(expected_devices - device_ids)
        if missing_devices:
            raise RuntimeError(f"Missing expected fixture devices: {', '.join(missing_devices)}")

        audits_result = await client.call_tool("list_audits", {})
        audits = set(_json_payload(audits_result))
        expected_audits = {
            "default_route_sanity",
            "encrypted_dns",
            "snmp_scope",
            "trunk_vlan_sanity",
            "vlan_consistency",
            "wan_failover_state",
        }
        missing_audits = sorted(expected_audits - audits)
        if missing_audits:
            raise RuntimeError(f"Missing expected audits: {', '.join(missing_audits)}")

        audit_result = await client.call_tool(
            "run_audit",
            {
                "device_ids": ["edge-router", "core-switch", "branch-switch", "access-switch"],
                "audits": sorted(expected_audits),
            },
        )
        audit_payload = _json_payload(audit_result)
        statuses = [
            finding["status"]
            for result in audit_payload
            for finding in result.get("findings", [])
        ]
        if "fail" in statuses or "warn" in statuses:
            raise RuntimeError(f"Unexpected warn/fail audit statuses: {statuses}")

        return {
            "ok": True,
            "tool_count": len(tool_names),
            "required_tools": sorted(REQUIRED_TOOLS),
            "device_count": len(devices),
            "audit_count": len(audits),
            "status_counts": {status: statuses.count(status) for status in sorted(set(statuses))},
        }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Smoke-test fixture-backed MCP tool surface.")
    parser.add_argument("--devices-path", type=pathlib.Path, default=DEFAULT_DEVICES_PATH)
    parser.add_argument("--policy-path", type=pathlib.Path, default=DEFAULT_POLICY_PATH)
    parser.add_argument("--fixture-dir", type=pathlib.Path, default=DEFAULT_FIXTURE_DIR)
    parser.add_argument("--audit-log-path", type=pathlib.Path, default=DEFAULT_AUDIT_LOG)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    result = asyncio.run(_run(args))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
