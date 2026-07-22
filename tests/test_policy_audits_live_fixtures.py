"""Policy-backed audit behavior against purpose-built synthetic fixtures."""

from __future__ import annotations

import pathlib

import pytest

from routeros_inspector_mcp.audits.encrypted_dns import audit_encrypted_dns
from routeros_inspector_mcp.audits.policy_backed import (
    audit_default_route_sanity,
    audit_snmp_scope,
    audit_trunk_vlan_sanity,
    audit_vlan_consistency,
    audit_wan_failover_state,
)
from routeros_inspector_mcp.backends.fixture import FixtureBackend
from routeros_inspector_mcp.config import load_inventory, load_policy
from routeros_inspector_mcp.service import Service

ROOT = pathlib.Path(__file__).parent.parent
CONFIG_DIR = ROOT / "config"
FIXTURE_DIR = pathlib.Path(__file__).parent / "fixtures" / "routeros"


@pytest.fixture
def synthetic_fixture_service():
    return Service(
        load_inventory(CONFIG_DIR / "devices.example.yaml"),
        {"fixture": FixtureBackend(FIXTURE_DIR)},
        load_policy(CONFIG_DIR / "policy.example.yaml"),
        transport_override="fixture",
    )


def statuses(result):
    return [finding.status for finding in result.findings]


def findings(result):
    return [finding.finding for finding in result.findings]


def test_vlan_audit_ignores_default_and_dynamic_vlan_noise(synthetic_fixture_service):
    main = audit_vlan_consistency(synthetic_fixture_service, "edge-router")
    core = audit_vlan_consistency(synthetic_fixture_service, "core-switch")
    office = audit_vlan_consistency(synthetic_fixture_service, "branch-switch")
    livingroom = audit_vlan_consistency(synthetic_fixture_service, "access-switch")

    assert statuses(main) == ["pass"]
    assert statuses(core) == ["pass"]
    assert statuses(office) == ["pass"]
    assert statuses(livingroom) == ["pass"]


def test_wan_failover_audit_is_gateway_scoped(synthetic_fixture_service):
    main = audit_wan_failover_state(synthetic_fixture_service, "edge-router")
    core = audit_wan_failover_state(synthetic_fixture_service, "core-switch")

    assert statuses(main) == ["pass"]
    assert statuses(core) == ["skip"]
    assert "does not apply" in findings(core)[0]


def test_trunk_vlan_sanity_uses_policy_trunks(synthetic_fixture_service):
    main = audit_trunk_vlan_sanity(synthetic_fixture_service, "edge-router")
    core = audit_trunk_vlan_sanity(synthetic_fixture_service, "core-switch")
    office = audit_trunk_vlan_sanity(synthetic_fixture_service, "branch-switch")
    livingroom = audit_trunk_vlan_sanity(synthetic_fixture_service, "access-switch")

    assert statuses(main) == ["pass"]
    assert statuses(core) == ["pass"]
    assert statuses(office) == ["pass"]
    assert statuses(livingroom) == ["pass"]
    assert findings(core) == ["Expected trunk VLAN membership matches policy"]


def test_default_route_sanity_treats_switches_as_management_devices(synthetic_fixture_service):
    main = audit_default_route_sanity(synthetic_fixture_service, "edge-router")
    core = audit_default_route_sanity(synthetic_fixture_service, "core-switch")
    office = audit_default_route_sanity(synthetic_fixture_service, "branch-switch")
    livingroom = audit_default_route_sanity(synthetic_fixture_service, "access-switch")

    assert statuses(main) == ["pass"]
    assert statuses(core) == ["pass"]
    assert statuses(office) == ["pass"]
    assert statuses(livingroom) == ["pass"]
    assert findings(main) == ["Gateway default route shape is sane"]
    assert findings(core) == ["Switch has a single management default route"]
    assert findings(office) == ["Switch has a single management default route"]


def test_snmp_audit_validates_access_without_versioned_community(synthetic_fixture_service):
    result = audit_snmp_scope(synthetic_fixture_service, "edge-router")
    office = audit_snmp_scope(synthetic_fixture_service, "branch-switch")
    livingroom = audit_snmp_scope(synthetic_fixture_service, "access-switch")

    assert statuses(result) == ["pass", "pass"]
    assert "SNMP access scope matches policy" in findings(result)
    assert "SNMP community value is managed by declared secret-store policy" in findings(result)
    assert statuses(office) == ["pass", "pass"]
    assert statuses(livingroom) == ["pass", "pass"]
    assert "SNMP access scope matches policy" in findings(office)


def test_encrypted_dns_audit_respects_policy_false(synthetic_fixture_service):
    result = audit_encrypted_dns(synthetic_fixture_service, "edge-router")

    assert statuses(result) == ["pass"]
    assert findings(result) == ["Encrypted DNS is not required by policy for this device"]
