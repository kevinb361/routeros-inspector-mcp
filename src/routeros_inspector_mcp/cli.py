"""Operator CLI for local fixture-backed smoke checks.

The CLI is intentionally fixture-first. It does not open network connections and
never accepts RouterOS commands or host/IP targets.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from collections.abc import Iterable
from typing import Any

from .audits.base import AuditResult
from .backends.fixture import FixtureBackend
from .config import load_inventory, load_policy
from .server import AUDIT_REGISTRY
from .service import Service

EXAMPLES_DIR = pathlib.Path(__file__).resolve().parent / "examples"
DEFAULT_DEVICES_PATH = EXAMPLES_DIR / "devices.yaml"
DEFAULT_POLICY_PATH = EXAMPLES_DIR / "policy.yaml"
DEFAULT_FIXTURE_DIR = EXAMPLES_DIR / "fixtures"
BASELINE_AUDITS = [
    "vlan_consistency",
    "trunk_vlan_sanity",
    "default_route_sanity",
    "wan_failover_state",
    "snmp_scope",
    "encrypted_dns",
    "firmware_drift",
    "dead_mangle_rules",
    "dscp_policy",
]
STATUS_ORDER = ("pass", "warn", "fail", "unknown", "skip")
ACTIONABLE_STATUSES = {"warn", "fail", "unknown"}


def _split_csv(value: str | None) -> list[str] | None:
    if value is None:
        return None
    values = [part.strip() for part in value.split(",") if part.strip()]
    return values or []


def _build_service(args: argparse.Namespace) -> Service:
    inventory = load_inventory(args.devices_path)
    policy = load_policy(args.policy_path)
    return Service(
        inventory,
        {"fixture": FixtureBackend(args.fixture_dir)},
        policy,
        transport_override="fixture",
    )


def _write_json(data: Any) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def _device_ids(service: Service, requested: list[str] | None) -> list[str]:
    targets = requested or list(service.inventory.devices.keys())
    unknown = [device_id for device_id in targets if device_id not in service.inventory.devices]
    if unknown:
        raise ValueError(f"Unknown device ID(s): {', '.join(unknown)}")
    return targets


def _audit_names(requested: list[str] | None) -> list[str]:
    names = requested or sorted(AUDIT_REGISTRY)
    unknown = [name for name in names if name not in AUDIT_REGISTRY]
    if unknown:
        raise ValueError(f"Unknown audit(s): {', '.join(unknown)}")
    return names


def _run_audits(
    service: Service, targets: list[str], audit_names: list[str]
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for device_id in targets:
        for audit_name in audit_names:
            audit_fn = AUDIT_REGISTRY[audit_name]
            result: AuditResult = audit_fn(service, device_id)
            results.append(result.to_dict())
    return results


def _summarize_audit_results(results: Iterable[dict[str, Any]]) -> dict[str, Any]:
    counts = dict.fromkeys(STATUS_ORDER, 0)
    rows: list[dict[str, Any]] = []
    for result in results:
        statuses: list[str] = []
        for finding in result.get("findings", []):
            status = str(finding.get("status", "unknown"))
            statuses.append(status)
            if status in counts:
                counts[status] += 1
            else:
                counts["unknown"] += 1
        rows.append(
            {
                "device_id": result.get("device_id"),
                "audit_name": result.get("audit_name"),
                "statuses": statuses,
            }
        )
    return {"counts": counts, "results": rows}


def _finding_row(result: dict[str, Any], finding: dict[str, Any]) -> dict[str, Any]:
    status = str(finding.get("status", "unknown"))
    if status not in STATUS_ORDER:
        status = "unknown"
    return {
        "audit_name": result.get("audit_name"),
        "status": status,
        "severity": finding.get("severity"),
        "finding": finding.get("finding"),
        "evidence": finding.get("evidence", []),
        "recommendation": finding.get("recommendation", ""),
    }


def _baseline_report(
    results: list[dict[str, Any]],
    devices: list[str],
    audit_names: list[str],
    *,
    include_pass: bool = False,
) -> dict[str, Any]:
    summary = _summarize_audit_results(results)
    by_device: dict[str, dict[str, Any]] = {}
    for device_id in devices:
        by_device[device_id] = {
            "counts": dict.fromkeys(STATUS_ORDER, 0),
            "findings": [],
        }

    for result in results:
        device_id = str(result.get("device_id", "unknown"))
        device_entry = by_device.setdefault(
            device_id,
            {"counts": dict.fromkeys(STATUS_ORDER, 0), "findings": []},
        )
        for finding in result.get("findings", []):
            row = _finding_row(result, finding)
            status = row["status"]
            device_entry["counts"][status] += 1
            if include_pass or status in ACTIONABLE_STATUSES:
                device_entry["findings"].append(row)

    return {
        "baseline": "fixture",
        "devices": devices,
        "audits": audit_names,
        "counts": summary["counts"],
        "by_device": by_device,
    }


def _format_operator_report(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "MikroTik fixture baseline",
        f"devices: {len(report['devices'])}  audits: {len(report['audits'])}",
        (
            f"pass: {counts['pass']}  warn: {counts['warn']}  "
            f"fail: {counts['fail']}  unknown: {counts['unknown']}  skip: {counts['skip']}"
        ),
    ]

    for device_id in report["devices"]:
        findings = report["by_device"].get(device_id, {}).get("findings", [])
        if not findings:
            continue
        lines.extend(["", str(device_id)])
        for finding in findings:
            status = str(finding.get("status", "unknown")).upper()
            audit_name = finding.get("audit_name", "unknown")
            lines.append(f"  {status} {audit_name}")
            if finding.get("finding"):
                lines.append(f"    {finding['finding']}")
            recommendation = finding.get("recommendation")
            if recommendation:
                lines.append(f"    recommendation: {recommendation}")
    return "\n".join(lines)


def cmd_list_devices(args: argparse.Namespace) -> int:
    service = _build_service(args)
    devices = service.list_devices()
    if args.summary:
        for device in devices:
            print(
                f"{device['device_id']}\trole={device['role']}\trisk={device['risk']}\ttransport={device['transport']}"
            )
    else:
        _write_json(devices)
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    service = _build_service(args)
    targets = _device_ids(service, _split_csv(args.devices))
    audit_names = _audit_names(_split_csv(args.audits))
    results = _run_audits(service, targets, audit_names)

    if args.summary:
        _write_json(_summarize_audit_results(results))
    else:
        _write_json(results)
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    service = _build_service(args)
    targets = _device_ids(service, _split_csv(args.devices))
    audit_names = _audit_names(_split_csv(args.audits) or BASELINE_AUDITS)
    results = _run_audits(service, targets, audit_names)
    report = _baseline_report(results, targets, audit_names)

    if args.fail_on_warn and (report["counts"]["warn"] or report["counts"]["fail"]):
        _write_json(report)
        return 1
    if args.fail_on_fail and report["counts"]["fail"]:
        _write_json(report)
        return 1

    _write_json(report)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    service = _build_service(args)
    targets = _device_ids(service, _split_csv(args.devices))
    audit_names = _audit_names(_split_csv(args.audits) or BASELINE_AUDITS)
    results = _run_audits(service, targets, audit_names)
    report = _baseline_report(results, targets, audit_names, include_pass=args.all)

    if args.json:
        _write_json(report)
    else:
        print(_format_operator_report(report))

    if args.fail_on_warn and (report["counts"]["warn"] or report["counts"]["fail"]):
        return 1
    if args.fail_on_fail and report["counts"]["fail"]:
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="routeros-inspector",
        description="Read-only local smoke CLI for routeros-inspector-mcp fixture audits.",
    )
    parser.add_argument("--devices-path", type=pathlib.Path, default=DEFAULT_DEVICES_PATH)
    parser.add_argument("--policy-path", type=pathlib.Path, default=DEFAULT_POLICY_PATH)
    parser.add_argument("--fixture-dir", type=pathlib.Path, default=DEFAULT_FIXTURE_DIR)

    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list-devices", help="List versioned device inventory")
    list_parser.add_argument("--summary", action="store_true", help="Print compact tabular output")
    list_parser.set_defaults(func=cmd_list_devices)

    audit_parser = subparsers.add_parser("audit", help="Run fixture-backed audits")
    audit_parser.add_argument(
        "--devices", help="Comma-separated device IDs. Omit for all devices."
    )
    audit_parser.add_argument("--audits", help="Comma-separated audit names. Omit for all audits.")
    audit_parser.add_argument(
        "--summary", action="store_true", help="Print compact JSON status counts"
    )
    audit_parser.set_defaults(func=cmd_audit)

    baseline_parser = subparsers.add_parser(
        "baseline",
        help="Run the default fixture baseline report for operator/regression checks",
    )
    baseline_parser.add_argument(
        "--devices", help="Comma-separated device IDs. Omit for all devices."
    )
    baseline_parser.add_argument(
        "--audits",
        help="Comma-separated audit names. Omit for the curated baseline audit set.",
    )
    baseline_parser.add_argument(
        "--fail-on-fail",
        action="store_true",
        help="Exit 1 when any finding has status=fail",
    )
    baseline_parser.add_argument(
        "--fail-on-warn",
        action="store_true",
        help="Exit 1 when any finding has status=warn or fail",
    )
    baseline_parser.set_defaults(func=cmd_baseline)

    report_parser = subparsers.add_parser(
        "report",
        help="Print a human-readable fixture baseline report for operators",
    )
    report_parser.add_argument(
        "--devices", help="Comma-separated device IDs. Omit for all devices."
    )
    report_parser.add_argument(
        "--audits",
        help="Comma-separated audit names. Omit for the curated baseline audit set.",
    )
    report_parser.add_argument(
        "--all",
        action="store_true",
        help="Include pass findings. Default output shows only warn/fail/unknown findings.",
    )
    report_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the report as structured JSON instead of human-readable text.",
    )
    report_parser.add_argument(
        "--fail-on-fail",
        action="store_true",
        help="Exit 1 when any finding has status=fail",
    )
    report_parser.add_argument(
        "--fail-on-warn",
        action="store_true",
        help="Exit 1 when any finding has status=warn or fail",
    )
    report_parser.set_defaults(func=cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
