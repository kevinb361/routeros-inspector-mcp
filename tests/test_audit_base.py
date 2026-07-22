"""Tests for audit base classes."""

from routeros_inspector_mcp.audits.base import AuditResult, Finding


def test_finding_to_dict():
    f = Finding(
        status="pass",
        severity="info",
        finding="Test finding",
        evidence=["evidence1"],
        recommendation="Do nothing",
    )
    d = f.to_dict()
    assert d["status"] == "pass"
    assert d["severity"] == "info"
    assert d["finding"] == "Test finding"
    assert d["evidence"] == ["evidence1"]


def test_audit_result_to_dict():
    f = Finding(status="warn", severity="medium", finding="Warning")
    r = AuditResult(audit_name="test", device_id="dev1", findings=[f])
    d = r.to_dict()
    assert d["audit_name"] == "test"
    assert d["device_id"] == "dev1"
    assert len(d["findings"]) == 1
    assert d["findings"][0]["status"] == "warn"


def test_finding_default_values():
    f = Finding(status="unknown", severity="info", finding="Default test")
    assert f.evidence == []
    assert f.recommendation == ""
    assert f.confidence == "medium"
    assert f.artifact_path == ""
