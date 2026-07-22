"""Audit base — standardized output shape for all audits.

Every audit returns a list of Finding objects. Status is one of:
pass, warn, fail, unknown, skip. Missing policy or evidence yields unknown;
intentionally inapplicable checks yield skip.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Finding:
    """Single audit finding."""

    status: str  # pass | warn | fail | unknown
    severity: str  # info | low | medium | high
    finding: str
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""
    confidence: str = "medium"  # low | medium | high
    artifact_path: str = ""

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "severity": self.severity,
            "finding": self.finding,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
            "artifact_path": self.artifact_path,
        }


@dataclass
class AuditResult:
    """Result of running a single audit on a device."""

    audit_name: str
    device_id: str
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "audit_name": self.audit_name,
            "device_id": self.device_id,
            "findings": [f.to_dict() for f in self.findings],
        }
