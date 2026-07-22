"""Mangle/queue correlation audit.

Policy-light: correlate mangle-produced packet marks with queue-tree packet
marks. This turns disabled mangle/queue cleanup from a raw list into actionable
relationships without making changes.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..service import Service
from .base import AuditResult, Finding

_MARK_FIELDS = ("new_packet_mark", "new_connection_mark", "new_routing_mark")


def _is_disabled(item: dict[str, Any]) -> bool:
    return bool(item.get("disabled", False))


def _mark_label(rule: dict[str, Any], mark: str) -> str:
    comment = rule.get("comment") or "no comment"
    chain = rule.get("chain") or "?"
    action = rule.get("action") or "?"
    state = "disabled" if _is_disabled(rule) else "enabled"
    return f"{mark}: {state} {chain}/{action} - {comment}"


def audit_mangle_queue_correlation(service: Service, device_id: str) -> AuditResult:
    """Correlate mangle-produced packet marks with queue-tree consumers."""

    result = AuditResult(audit_name="mangle_queue_correlation", device_id=device_id)
    rules = service.get_firewall_mangle(device_id)
    queues = service.get_queue_tree(device_id) or service.get_qos_queues(device_id)

    if not rules and not queues:
        role = service.get_device_role(device_id)
        if role not in {"gateway", "edge"}:
            result.findings.append(
                Finding(
                    status="pass",
                    severity="info",
                    finding="No mangle or QoS queue state on non-gateway device",
                    evidence=[f"role: {role}"],
                    confidence="high",
                )
            )
            return result
        result.findings.append(
            Finding(
                status="unknown",
                severity="info",
                finding="No mangle or QoS queue data available",
                recommendation="Verify mangle and queue tree data can be collected for this gateway",
                confidence="low",
            )
        )
        return result

    packet_producers: dict[str, list[dict[str, Any]]] = defaultdict(list)
    disabled_packet_producers: dict[str, list[dict[str, Any]]] = defaultdict(list)
    connection_marks: dict[str, list[dict[str, Any]]] = defaultdict(list)
    routing_marks: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for rule in rules:
        packet_mark = rule.get("new_packet_mark")
        if packet_mark:
            packet_producers[str(packet_mark)].append(rule)
            if _is_disabled(rule):
                disabled_packet_producers[str(packet_mark)].append(rule)
        connection_mark = rule.get("new_connection_mark")
        if connection_mark:
            connection_marks[str(connection_mark)].append(rule)
        routing_mark = rule.get("new_routing_mark") or rule.get("new_routing_table")
        if routing_mark:
            routing_marks[str(routing_mark)].append(rule)

    queue_consumers: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for queue in queues:
        packet_mark = queue.get("packet_mark")
        if packet_mark:
            queue_consumers[str(packet_mark)].append(queue)

    evidence: list[str] = []

    disabled_or_invalid_queues = [
        q for q in queues if bool(q.get("disabled", False)) or bool(q.get("invalid", False))
    ]
    if disabled_or_invalid_queues:
        for q in disabled_or_invalid_queues[:10]:
            flags = []
            if q.get("disabled"):
                flags.append("disabled")
            if q.get("invalid"):
                flags.append("invalid")
            evidence.append(
                f"queue {q.get('name', 'unnamed')} ({q.get('packet_mark', 'no-mark')}) is {','.join(flags)}"
            )

    for mark, consumers in sorted(queue_consumers.items()):
        producers = packet_producers.get(mark, [])
        enabled_producers = [r for r in producers if not _is_disabled(r)]
        disabled_producers = [r for r in producers if _is_disabled(r)]
        if consumers and not enabled_producers:
            evidence.append(
                f"queue packet mark {mark!r} has {len(consumers)} queue consumer(s) but no enabled mangle producer"
            )
            for rule in disabled_producers[:3]:
                evidence.append(f"  disabled producer: {_mark_label(rule, mark)}")

    for mark, producers in sorted(packet_producers.items()):
        if mark not in queue_consumers:
            enabled_count = sum(1 for r in producers if not _is_disabled(r))
            disabled_count = len(producers) - enabled_count
            evidence.append(
                f"packet mark {mark!r} is produced by {enabled_count} enabled/{disabled_count} disabled rule(s) but no queue consumes it"
            )

    disabled_referenced = sorted(set(disabled_packet_producers) & set(queue_consumers))
    if disabled_referenced:
        evidence.append(
            "disabled mangle-produced packet marks still referenced by queues: "
            + ", ".join(repr(mark) for mark in disabled_referenced)
        )

    if evidence:
        result.findings.append(
            Finding(
                status="warn",
                severity="medium",
                finding="Mangle packet marks and QoS queues are not fully aligned",
                evidence=evidence[:30],
                recommendation=(
                    "Review queue packet marks against enabled mangle rules; remove or enable only after "
                    "confirming current QoS design intent. Disabled/invalid queues should not be counted as active shaping."
                ),
                confidence="high",
            )
        )
        return result

    result.findings.append(
        Finding(
            status="pass",
            severity="info",
            finding="Mangle packet marks and QoS queues are aligned",
            evidence=[
                f"packet_marks_consumed_by_queues: {sorted(queue_consumers)}",
                f"connection_marks_seen: {sorted(connection_marks)}",
                f"routing_marks_seen: {sorted(routing_marks)}",
            ],
            confidence="high",
        )
    )
    return result
