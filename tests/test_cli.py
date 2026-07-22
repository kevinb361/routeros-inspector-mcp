"""Tests for local operator CLI."""

from __future__ import annotations

import json

from routeros_inspector_mcp.cli import main


def test_cli_list_devices_json(capsys):
    code = main(["list-devices"])

    assert code == 0
    data = json.loads(capsys.readouterr().out)
    device_ids = {device["device_id"] for device in data}
    assert {
        "edge-router",
        "core-switch",
        "access-switch",
        "branch-switch",
        "access-switch",
    } <= device_ids
    assert all("credential_ref" not in device for device in data)


def test_cli_list_devices_summary(capsys):
    code = main(["list-devices", "--summary"])

    assert code == 0
    output = capsys.readouterr().out
    assert "edge-router\trole=gateway" in output
    assert "core-switch\trole=switch" in output


def test_cli_audit_selected_device_and_audits(capsys):
    code = main(
        [
            "audit",
            "--devices",
            "edge-router",
            "--audits",
            "vlan_consistency,wan_failover_state,snmp_scope,encrypted_dns",
        ]
    )

    assert code == 0
    results = json.loads(capsys.readouterr().out)
    assert {result["audit_name"] for result in results} == {
        "vlan_consistency",
        "wan_failover_state",
        "snmp_scope",
        "encrypted_dns",
    }
    statuses = [
        finding["status"]
        for result in results
        for finding in result["findings"]
        if finding["finding"] != "SNMP community name policy intentionally not versioned"
    ]
    assert set(statuses) == {"pass"}


def test_cli_audit_summary_counts(capsys):
    code = main(
        [
            "audit",
            "--devices",
            "edge-router,core-switch",
            "--audits",
            "vlan_consistency,wan_failover_state",
            "--summary",
        ]
    )

    assert code == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["counts"]["fail"] == 0
    assert summary["counts"]["warn"] == 0
    assert summary["counts"]["pass"] == 3
    assert summary["counts"]["unknown"] == 0
    assert summary["counts"]["skip"] == 1


def test_cli_baseline_report_default_scope(capsys):
    code = main(["baseline", "--devices", "edge-router,core-switch,branch-switch,access-switch"])

    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["baseline"] == "fixture"
    assert "trunk_vlan_sanity" in report["audits"]
    assert "default_route_sanity" in report["audits"]
    assert report["counts"]["fail"] == 0
    assert report["by_device"]["edge-router"]["counts"]["pass"] >= 1
    assert report["by_device"]["core-switch"]["counts"]["skip"] >= 1
    assert report["by_device"]["branch-switch"]["counts"]["pass"] >= 1
    assert report["by_device"]["access-switch"]["counts"]["pass"] >= 1


def test_cli_baseline_fail_on_warn_returns_nonzero(capsys):
    code = main(
        [
            "baseline",
            "--devices",
            "edge-router",
            "--audits",
            "dscp_policy",
            "--fail-on-warn",
        ]
    )

    assert code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["counts"]["warn"] >= 1


def test_cli_report_human_defaults_to_non_pass_findings(capsys):
    code = main(["report", "--devices", "access-switch"])

    assert code == 0
    output = capsys.readouterr().out
    assert "MikroTik fixture baseline" in output
    assert "devices: 1  audits: 9" in output
    assert "pass: 8  warn: 0  fail: 0  unknown: 0  skip: 2" in output
    assert "access-switch" not in output
    assert "UNKNOWN wan_failover_state" not in output
    assert "UNKNOWN snmp_scope" not in output
    assert "PASS vlan_consistency" not in output


def test_cli_report_all_includes_pass_findings(capsys):
    code = main(["report", "--devices", "access-switch", "--all"])

    assert code == 0
    output = capsys.readouterr().out
    assert "PASS vlan_consistency" in output
    assert "SKIP wan_failover_state" in output
    assert "PASS snmp_scope" in output


def test_cli_report_json_and_fail_on_warn(capsys):
    code = main(
        [
            "report",
            "--devices",
            "edge-router",
            "--audits",
            "dscp_policy",
            "--json",
            "--fail-on-warn",
        ]
    )

    assert code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["counts"]["warn"] >= 1
    assert report["by_device"]["edge-router"]["findings"][0]["audit_name"] == "dscp_policy"


def test_cli_invalid_device_exits_nonzero(capsys):
    code = main(["audit", "--devices", "not-a-device", "--audits", "vlan_consistency"])

    captured = capsys.readouterr()
    assert code == 2
    assert "Unknown device ID" in captured.err


def test_cli_unknown_audit_exits_nonzero(capsys):
    code = main(["audit", "--devices", "edge-router", "--audits", "not_an_audit"])

    captured = capsys.readouterr()
    assert code == 2
    assert "Unknown audit" in captured.err
