"""Tests for audit logging."""

import pytest

from routeros_inspector_mcp.audit_log import AuditLogger


@pytest.fixture
def logger(tmp_path):
    path = tmp_path / "audit.jsonl"
    return AuditLogger(path)


def test_log_success(logger):
    with logger.track("test_op", ["dev1"]):
        pass

    entries = logger.get_entries()
    assert len(entries) == 1
    assert entries[0].status == "success"
    assert entries[0].operation == "test_op"
    assert entries[0].device_ids == ["dev1"]
    assert entries[0].duration_ms >= 0


def test_log_error(logger):
    with pytest.raises(RuntimeError):
        with logger.track("fail_op", ["dev1"]):
            raise RuntimeError("boom")

    entries = logger.get_entries()
    assert len(entries) == 1
    assert entries[0].status == "error"
    assert entries[0].error_class == "RuntimeError"


def test_log_no_secrets(logger):
    """Ensure audit log never contains secret values."""
    with logger.track("get_config", ["dev1"]):
        pass

    raw = logger.log_path.read_text()
    assert "password" not in raw.lower()
    assert "secret" not in raw.lower()
    assert "token" not in raw.lower()


def test_multiple_entries(logger):
    with logger.track("op1"):
        pass
    with logger.track("op2", ["a", "b"]):
        pass

    entries = logger.get_entries()
    assert len(entries) == 2
    assert entries[0].operation == "op1"
    assert entries[1].operation == "op2"


def test_empty_log(tmp_path):
    path = tmp_path / "empty.jsonl"
    log = AuditLogger(path)
    assert log.get_entries() == []
