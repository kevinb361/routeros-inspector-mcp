"""Tests for redaction module."""

from routeros_inspector_mcp.backends.base import ERROR_UNREACHABLE, BackendError
from routeros_inspector_mcp.redaction import _REDACTED, redact, safe_error_label


def test_safe_error_label_preserves_allowlisted_backend_class():
    error = BackendError(ERROR_UNREACHABLE, "password=hunter2")

    assert safe_error_label(error) == "unreachable"


def test_safe_error_label_hides_arbitrary_exception_details():
    error = RuntimeError("password=hunter2")

    assert safe_error_label(error) == "internal_error"


def test_redact_password_value():
    data = {"host": "192.0.2.1", "password": "s3cret123"}
    result = redact(data)
    assert result["password"] == _REDACTED
    assert result["host"] == "192.0.2.1"


def test_redact_token_value():
    data = {"api_key": "tok_abc123", "name": "test"}
    result = redact(data)
    assert result["api_key"] == _REDACTED
    assert result["name"] == "test"


def test_redact_nested():
    data = {
        "level1": {
            "password": "nested_secret",
            "level2": {
                "token": "deep_token",
                "safe": "keep_me",
            },
        }
    }
    result = redact(data)
    assert result["level1"]["password"] == _REDACTED
    assert result["level1"]["level2"]["token"] == _REDACTED
    assert result["level1"]["level2"]["safe"] == "keep_me"


def test_redact_list():
    data = [{"password": "a"}, {"name": "safe"}, {"secret": "b"}]
    result = redact(data)
    assert result[0]["password"] == _REDACTED
    assert result[1]["name"] == "safe"
    assert result[2]["secret"] == _REDACTED


def test_redact_preserves_private_ips():
    data = {"host": "192.0.2.1", "gateway": "192.0.2.254"}
    result = redact(data)
    assert result["host"] == "192.0.2.1"
    assert result["gateway"] == "192.0.2.254"


def test_redact_public_ips_in_strings():
    data = {
        "gateway": "8.8.8.8",
        "cidr": "8.8.8.0/24",
        "evidence": "default route: gw=8.8.8.8, distance=1",
    }
    result = redact(data)
    assert result["gateway"] == _REDACTED
    assert result["cidr"] == f"{_REDACTED}/24"
    assert result["evidence"] == f"default route: gw={_REDACTED}, distance=1"


def test_redact_preserves_macs():
    data = {"mac": "AA:BB:CC:DD:EE:FF"}
    result = redact(data)
    assert result["mac"] == "AA:BB:CC:DD:EE:FF"


def test_redact_preserves_integers():
    data = {"count": 42, "port": 80}
    result = redact(data)
    assert result["count"] == 42
    assert result["port"] == 80


def test_redact_preserves_none():
    data = {"value": None}
    result = redact(data)
    assert result["value"] is None


def test_redact_private_key():
    data = {"private_key": "key_data_here"}
    result = redact(data)
    assert result["private_key"] == _REDACTED


def test_redact_certificate():
    data = {"cert": "cert_data"}
    result = redact(data)
    assert result["cert"] == _REDACTED


def test_redact_snmp_community():
    data = {"snmp_community": "public"}
    result = redact(data)
    assert result["snmp_community"] == _REDACTED


def test_redact_wireguard_key():
    data = {"wireguard_private_key": "abc123"}
    result = redact(data)
    assert result["wireguard_private_key"] == _REDACTED


def test_redact_plain_string():
    result = redact("just a normal string")
    assert result == "just a normal string"


def test_redact_idempotent():
    data = {"password": "secret"}
    r1 = redact(data)
    r2 = redact(r1)
    assert r1 == r2
