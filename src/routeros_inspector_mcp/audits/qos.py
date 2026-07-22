"""QoS state audit — check if QoS queues are configured and reasonable.

Policy-light: does not require policy.yaml, just inspects live/fixture state.
"""

from __future__ import annotations

from ..service import Service
from .base import AuditResult, Finding


def audit_qos_state(service: Service, device_id: str) -> AuditResult:
    """Check QoS queue configuration.

    - PASS: queues exist and at least one has a non-zero limit.
    - WARN: queues exist but all are unlimite (0 or empty max_limit).
    - FAIL: no queues configured at all.
    """
    queues = service.get_qos_queues(device_id)
    result = AuditResult(audit_name="qos_state", device_id=device_id)

    if not queues:
        result.findings.append(
            Finding(
                status="fail",
                severity="medium",
                finding="No QoS queues configured",
                recommendation="Configure QoS queues for traffic shaping and priority queuing",
                confidence="high",
            )
        )
        return result

    # Check if any queue has a meaningful limit
    has_limit = False
    for q in queues:
        ml = q.get("max_limit", "")
        if ml and ml != "0" and ml != "unlimited":
            has_limit = True
            break

    if not has_limit:
        result.findings.append(
            Finding(
                status="warn",
                severity="low",
                finding="QoS queues exist but none have rate limits",
                evidence=[f"{q.get('name', 'unnamed')}: max_limit={q.get('max_limit', 'empty')}" for q in queues],
                recommendation="Set rate limits on QoS queues for meaningful traffic shaping",
                confidence="high",
            )
        )
        return result

    result.findings.append(
        Finding(
            status="pass",
            severity="info",
            finding=f"QoS queues configured with {len(queues)} queue(s)",
            evidence=[f"{q.get('name', 'unnamed')}: {q.get('max_limit', '')}" for q in queues],
            confidence="high",
        )
    )
    return result
