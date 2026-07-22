"""Tests for config loader — inventory and policy validation."""

import pathlib
import re

import pytest
import yaml

from routeros_inspector_mcp.config import (
    PolicyBaseline,
    load_inventory,
    load_policy,
)

ROOT = pathlib.Path(__file__).parent.parent
CONFIG_DIR = ROOT / "config"
PACKAGE_EXAMPLES_DIR = ROOT / "src" / "routeros_inspector_mcp" / "examples"
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "routeros"


@pytest.fixture
def tmpdir(tmp_path):
    return tmp_path


def _write_yaml(path: pathlib.Path, data: dict) -> None:
    path.write_text(yaml.dump(data))


def test_load_inventory_success(tmpdir):
    _write_yaml(tmpdir / "devices.yaml", {
        "devices": {
            "router1": {
                "role": "gateway",
                "risk": "critical",
                "host": "192.0.2.1",
                "transport": "fixture",
                "credential_ref": "vault:router1",
                "allowed": True,
            }
        }
    })
    inv = load_inventory(tmpdir / "devices.yaml")
    assert "router1" in inv.devices
    assert inv.devices["router1"].role == "gateway"
    assert inv.devices["router1"].risk == "critical"


def test_load_inventory_unknown_role(tmpdir):
    _write_yaml(tmpdir / "devices.yaml", {
        "devices": {
            "bad": {
                "role": "notarealrole",
                "risk": "low",
                "host": "1.2.3.4",
                "transport": "fixture",
                "credential_ref": "x",
            }
        }
    })
    with pytest.raises(ValueError, match="unknown role"):
        load_inventory(tmpdir / "devices.yaml")


def test_load_inventory_unknown_risk(tmpdir):
    _write_yaml(tmpdir / "devices.yaml", {
        "devices": {
            "bad": {
                "role": "gateway",
                "risk": "extreme",
                "host": "1.2.3.4",
                "transport": "fixture",
                "credential_ref": "x",
            }
        }
    })
    with pytest.raises(ValueError, match="unknown risk"):
        load_inventory(tmpdir / "devices.yaml")


def test_load_inventory_unknown_transport(tmpdir):
    _write_yaml(tmpdir / "devices.yaml", {
        "devices": {
            "bad": {
                "role": "gateway",
                "risk": "low",
                "host": "1.2.3.4",
                "transport": "telepathy",
                "credential_ref": "x",
            }
        }
    })
    with pytest.raises(ValueError, match="unknown transport"):
        load_inventory(tmpdir / "devices.yaml")


def test_load_inventory_missing_host(tmpdir):
    _write_yaml(tmpdir / "devices.yaml", {
        "devices": {
            "bad": {
                "role": "gateway",
                "risk": "low",
                "transport": "fixture",
                "credential_ref": "x",
            }
        }
    })
    with pytest.raises(ValueError, match="missing host"):
        load_inventory(tmpdir / "devices.yaml")


def test_load_inventory_empty(tmpdir):
    _write_yaml(tmpdir / "devices.yaml", {"devices": {}})
    inv = load_inventory(tmpdir / "devices.yaml")
    assert len(inv.devices) == 0


def test_load_policy_success(tmpdir):
    _write_yaml(tmpdir / "policy.yaml", {
        "firmware": {"expected_versions": {"r1": "7.17"}},
        "snmp": {"allowed_communities": ["monitoring-ro"], "community_policy": "secret_store"},
        "dns": {"encrypted": True},
    })
    policy = load_policy(tmpdir / "policy.yaml")
    assert policy is not None
    assert policy.firmware.expected_versions["r1"] == "7.17"
    assert policy.snmp.community_policy == "secret_store"
    assert policy.dns.encrypted is True


def test_load_policy_missing_file(tmpdir):
    result = load_policy(tmpdir / "nonexistent.yaml")
    assert result is None


def test_load_policy_empty(tmpdir):
    _write_yaml(tmpdir / "policy.yaml", {})
    policy = load_policy(tmpdir / "policy.yaml")
    assert policy is not None
    assert isinstance(policy, PolicyBaseline)


def test_example_inventory_loads():
    inv = load_inventory(CONFIG_DIR / "devices.example.yaml")
    assert set(inv.devices) == {
        "edge-router",
        "core-switch",
        "access-switch",
        "branch-switch",
    }
    assert all(device.transport == "fixture" for device in inv.devices.values())
    assert inv.devices["edge-router"].credential_ref.startswith("example:")


def test_packaged_examples_match_repository_examples():
    assert (PACKAGE_EXAMPLES_DIR / "devices.yaml").read_bytes() == (
        CONFIG_DIR / "devices.example.yaml"
    ).read_bytes()
    assert (PACKAGE_EXAMPLES_DIR / "policy.yaml").read_bytes() == (
        CONFIG_DIR / "policy.example.yaml"
    ).read_bytes()
    packaged_fixtures = PACKAGE_EXAMPLES_DIR / "fixtures"
    assert {path.name for path in packaged_fixtures.glob("*.json")} == {
        path.name for path in FIXTURE_DIR.glob("*.json")
    }
    for fixture in FIXTURE_DIR.glob("*.json"):
        assert (packaged_fixtures / fixture.name).read_bytes() == fixture.read_bytes()


def test_example_policy_loads_without_versioned_secrets():
    policy_path = CONFIG_DIR / "policy.example.yaml"
    policy = load_policy(policy_path)
    assert policy is not None
    assert policy.firmware.expected_versions["edge-router"] == "7.20"
    assert policy.snmp.allowed_communities == []
    assert policy.snmp.community_policy == "secret_store"

    text = policy_path.read_text()
    forbidden = [
        r"(?i)password\s*:",
        r"(?i)secret\s*:",
        r"(?i)private[-_ ]?key",
        r"(?i)pre[-_ ]?shared",
        r"(?i)community\s*:\s*public",
    ]
    assert not any(re.search(pattern, text) for pattern in forbidden)
