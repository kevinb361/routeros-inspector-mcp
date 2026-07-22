"""Dead mangle rules audit — find possibly unused or disabled mangle rules.

Policy-light: flags disabled mangle rules and rules with suspicious comments.
Words findings as 'possibly unused' unless proven dead.
"""

from __future__ import annotations

from ..service import Service
from .base import AuditResult, Finding


def audit_dead_mangle_rules(service: Service, device_id: str) -> AuditResult:
    """Check for disabled or possibly unused mangle rules.

    - PASS: no suspicious rules found.
    - WARN: disabled rules or rules with suspicious comments found.
    - UNKNOWN: unable to determine (empty data and no evidence).
    """
    rules = service.get_firewall_mangle(device_id)
    result = AuditResult(audit_name="dead_mangle_rules", device_id=device_id)

    if not rules:
        role = service.get_device_role(device_id)
        if role not in {"gateway", "edge"}:
            result.findings.append(
                Finding(
                    status="pass",
                    severity="info",
                    finding="No mangle rules on non-gateway device",
                    evidence=[f"role: {role}"],
                    confidence="high",
                )
            )
            return result
        result.findings.append(
            Finding(
                status="unknown",
                severity="info",
                finding="No mangle rules data available",
                recommendation="Verify device is reachable and mangle data can be collected",
                confidence="low",
            )
        )
        return result

    disabled_rules = [r for r in rules if r.get("disabled", False)]
    suspicious_comments = [
        r for r in rules
        if any(kw in (r.get("comment", "") or "").lower()
               for kw in ["old", "leftover", "stale", "unused", "2022", "2023", "ref"])
    ]

    if not disabled_rules and not suspicious_comments:
        result.findings.append(
            Finding(
                status="pass",
                severity="info",
                finding="No suspicious mangle rules detected",
                evidence=[f"{len(rules)} total rules, none flagged"],
                confidence="high",
            )
        )
        return result

    # Collect evidence for warnings
    evidences: list[str] = []
    for r in disabled_rules:
        evidences.append(
            f"disabled rule: {r.get('chain', '?')} - {r.get('comment', 'no comment')}"
        )
    for r in suspicious_comments:
        comment = r.get("comment", "")
        evidences.append(
            f"possibly unused rule (comment: {comment!r}): chain={r.get('chain', '?')}"
        )

    result.findings.append(
        Finding(
            status="warn",
            severity="medium",
            finding="Possibly unused mangle rules detected",
            evidence=evidences,
            recommendation="Review disabled and suspicious mangle rules; remove stale entries to reduce complexity",
            confidence="medium",
        )
    )
    return result
