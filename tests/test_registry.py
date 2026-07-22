"""Tests for operation registry."""

from routeros_inspector_mcp.registry import REGISTRY, get_operation, list_operations


def test_registry_has_operations():
    assert len(REGISTRY) > 0


def test_all_operations_read_only():
    for name, op in REGISTRY.items():
        assert op.read_only is True, f"{name} is not read-only"


def test_get_operation_valid():
    op = get_operation("get_interfaces")
    assert op.name == "get_interfaces"
    assert op.read_only is True


def test_get_operation_unknown():
    import pytest
    with pytest.raises(ValueError, match="Unknown or denied"):
        get_operation("nonexistent_operation")


def test_list_operations_sorted():
    ops = list_operations()
    assert ops == sorted(ops)


def test_no_write_operations():
    """Confirm no operation is write/destructive."""
    for name, op in REGISTRY.items():
        assert op.read_only is True
        # Double-check the name doesn't hint at mutation
        assert "write" not in name.lower()
        assert "delete" not in name.lower()
        assert "reboot" not in name.lower()
        assert "import" not in name.lower()
