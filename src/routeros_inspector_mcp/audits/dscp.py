"""DSCP policy audit — inspect mangle DSCP trust/wash/set rules.

Policy-light and read-only. This audit focuses on rules that affect DSCP
classification for upstream CAKE/SQM devices. It intentionally does not require
router-side queue trees to be active.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..service import Service
from .base import AuditResult, Finding

WAN_INTERFACE_TOKENS = ("WAN", "wan", "ether1-WAN", "ether2-WAN")
TRUSTED_DSCP = {46: "EF", 34: "AF41", 36: "AF42", 38: "AF43"}


def _is_disabled(rule: dict[str, Any]) -> bool:
    return bool(rule.get("disabled", False))


def _rule_label(rule: dict[str, Any]) -> str:
    comment = rule.get("comment") or "no comment"
    return f"{rule.get('chain', '?')} {rule.get('action', '?')}: {comment}"


def _dscp_value(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _rule_matches_wan(rule: dict[str, Any]) -> bool:
    fields = [
        str(rule.get("in_interface", "")),
        str(rule.get("out_interface", "")),
        str(rule.get("comment", "")),
    ]
    return any(token in field for field in fields for token in WAN_INTERFACE_TOKENS)


def _trust_rule_may_include_wan(rule: dict[str, Any]) -> bool:
    """Return True when a trust rule is not narrowly scoped away from WAN ingress."""
    in_interface = str(rule.get("in_interface", ""))
    if not in_interface:
        return True
    if in_interface.startswith("!"):
        return True
    return _rule_matches_wan(rule)


def _enabled_mark_producers(rules: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    producers: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for rule in rules:
        if _is_disabled(rule):
            continue
        mark = rule.get("new_connection_mark")
        if mark:
            producers[str(mark)].append(rule)
    return producers


def audit_dscp_policy(service: Service, device_id: str) -> AuditResult:
    """Audit DSCP mangle rules for trust/wash/set consistency.

    Checks:
    - DSCP-affecting rules exist on gateway/edge devices.
    - Trust accept rules should have explicit DSCP matches.
    - WAN/IoT DSCP wash rules should exist before DSCP trust exceptions can leak.
    - Enabled DSCP set rules should consume marks with enabled producers.
    - DSCP class values should be in the intended CAKE diffserv4 vocabulary.
    """
    result = AuditResult(audit_name="dscp_policy", device_id=device_id)
    rules = service.get_firewall_mangle(device_id)

    if not rules:
        role = service.get_device_role(device_id)
        if role not in {"gateway", "edge"}:
            result.findings.append(
                Finding(
                    status="skip",
                    severity="info",
                    finding="No DSCP audit needed on non-gateway device",
                    evidence=[f"role: {role}"],
                    confidence="high",
                )
            )
            return result
        result.findings.append(
            Finding(
                status="unknown",
                severity="info",
                finding="No mangle rules data available for DSCP audit",
                recommendation="Collect /ip firewall mangle data including dscp, new-dscp, and passthrough fields.",
                confidence="low",
            )
        )
        return result

    enabled = [r for r in rules if not _is_disabled(r)]
    dscp_rules = [
        r for r in rules
        if r.get("action") in {"change-dscp", "set-priority"}
        or r.get("dscp") not in (None, "")
        or r.get("new_dscp") not in (None, "")
        or "dscp" in str(r.get("comment", "")).lower()
        or str(r.get("comment", "")).lower().startswith("trust ")
    ]
    enabled_dscp = [r for r in dscp_rules if not _is_disabled(r)]

    if not dscp_rules:
        result.findings.append(
            Finding(
                status="warn",
                severity="medium",
                finding="No DSCP-related mangle rules detected",
                recommendation="If upstream CAKE relies on diffserv classification, add explicit DSCP wash/classification policy or document why DSCP is not used.",
                confidence="medium",
            )
        )
        return result

    # 1. Trust rules must be narrow: action=accept can stop later mangle processing.
    broad_trust = []
    trust_evidence = []
    for rule in enabled:
        comment = str(rule.get("comment", ""))
        if rule.get("action") == "accept" and comment.lower().startswith("trust"):
            dscp = _dscp_value(rule.get("dscp"))
            if dscp is None:
                broad_trust.append(rule)
            else:
                name = TRUSTED_DSCP.get(dscp, f"DSCP {dscp}")
                trust_evidence.append(f"trust rule: {comment} matches {name} ({dscp}) on {rule.get('in_interface', '?')}")

    if broad_trust:
        result.findings.append(
            Finding(
                status="fail",
                severity="high",
                finding="Broad DSCP trust accept rule can bypass later mangle processing",
                evidence=[_rule_label(r) for r in broad_trust],
                recommendation="Constrain trust accept rules with explicit dscp=... matches and trusted ingress interfaces only.",
                confidence="high",
            )
        )
    elif trust_evidence:
        result.findings.append(
            Finding(
                status="pass",
                severity="info",
                finding="DSCP trust rules are constrained by explicit DSCP matches",
                evidence=trust_evidence,
                confidence="high",
            )
        )

    # 2. Wash coverage: inbound WAN and IoT should be washed to CS0 before classification.
    wash_rules = [
        r for r in enabled
        if r.get("action") == "change-dscp"
        and _dscp_value(r.get("new_dscp")) == 0
        and (r.get("chain") == "prerouting" or "wash" in str(r.get("comment", "")).lower())
    ]
    wan_wash = [r for r in wash_rules if _rule_matches_wan(r)]
    iot_wash = [r for r in wash_rules if "iot" in str(r.get("in_interface", "") + " " + r.get("comment", "")).lower()]
    wash_evidence = [f"wash rule: {_rule_label(r)} -> DSCP 0" for r in wash_rules]
    if wan_wash and iot_wash:
        result.findings.append(
            Finding(
                status="pass",
                severity="info",
                finding="DSCP wash rules cover WAN ingress and IoT ingress",
                evidence=wash_evidence,
                confidence="high",
            )
        )
    else:
        missing = []
        if not wan_wash:
            missing.append("WAN ingress wash")
        if not iot_wash:
            missing.append("IoT ingress wash")
        result.findings.append(
            Finding(
                status="warn",
                severity="medium",
                finding="DSCP wash coverage may be incomplete",
                evidence=wash_evidence or ["no enabled DSCP wash-to-zero rules found"],
                recommendation=f"Verify/add: {', '.join(missing)}.",
                confidence="medium",
            )
        )

    # 2b. Rule order matters: broad trust accept before WAN wash lets WAN-supplied
    # EF/AF4x bypass the wash rule. This is especially important when the upstream
    # shaper also trusts non-zero DSCP on download.
    if wan_wash:
        first_wan_wash = min(rules.index(r) for r in wan_wash)
        trust_before_wash = [
            r for r in enabled
            if rules.index(r) < first_wan_wash
            and r.get("action") == "accept"
            and str(r.get("comment", "")).lower().startswith("trust")
            and r.get("dscp") not in (None, "")
            and _trust_rule_may_include_wan(r)
        ]
        if trust_before_wash:
            result.findings.append(
                Finding(
                    status="warn",
                    severity="medium",
                    finding="DSCP trust rules can run before WAN wash",
                    evidence=[
                        f"trust-before-wash: {_rule_label(r)} dscp={r.get('dscp')} in_interface={r.get('in_interface', '<unset>')}"
                        for r in trust_before_wash
                    ] + [f"first WAN wash: {_rule_label(rules[first_wan_wash])}"],
                    recommendation="Move WAN DSCP wash before broad trust rules, or scope trust rules to explicit trusted LAN/input interfaces instead of a negated IoT match.",
                    confidence="high",
                )
            )
        else:
            result.findings.append(
                Finding(
                    status="pass",
                    severity="info",
                    finding="WAN DSCP wash is ordered before broad trust exceptions",
                    confidence="high",
                )
            )

    # 3. DSCP set rules should consume produced connection marks and use expected values.
    producers = _enabled_mark_producers(rules)
    set_rules = [
        r for r in enabled
        if r.get("action") == "change-dscp" and r.get("connection_mark")
    ]
    orphaned = []
    set_evidence = []
    unexpected = []
    expected_values = {0, 8, 26, 34, 36, 38, 46}
    for rule in set_rules:
        mark = str(rule.get("connection_mark"))
        new_dscp = _dscp_value(rule.get("new_dscp"))
        producer_count = len(producers.get(mark, []))
        set_evidence.append(
            f"{mark} -> DSCP {new_dscp} via {rule.get('comment', 'no comment')} ({producer_count} enabled producer(s))"
        )
        if producer_count == 0:
            orphaned.append(rule)
        if new_dscp not in expected_values:
            unexpected.append(rule)

    if set_rules:
        if unexpected:
            result.findings.append(
                Finding(
                    status="warn",
                    severity="medium",
                    finding="DSCP set rules use values outside the expected policy vocabulary",
                    evidence=[_rule_label(r) + f" new_dscp={r.get('new_dscp')!r}" for r in unexpected],
                    recommendation="Confirm these DSCP values map to the intended CAKE diffserv tins.",
                    confidence="medium",
                )
            )
        if orphaned:
            result.findings.append(
                Finding(
                    status="warn",
                    severity="low",
                    finding="DSCP set rule consumes a connection mark with no enabled producer",
                    evidence=[_rule_label(r) + f" connection_mark={r.get('connection_mark')!r}" for r in orphaned],
                    recommendation="Remove stale DSCP set rules or add/enable the intended mark producer.",
                    confidence="high",
                )
            )
        if not orphaned and not unexpected:
            result.findings.append(
                Finding(
                    status="pass",
                    severity="info",
                    finding="Enabled DSCP set rules use expected values and have enabled mark producers",
                    evidence=set_evidence,
                    confidence="high",
                )
            )
    else:
        result.findings.append(
            Finding(
                status="warn",
                severity="medium",
                finding="No enabled connection-mark to DSCP set rules found",
                recommendation="If upstream CAKE is diffserv-aware, ensure router classification stamps DSCP before traffic reaches the shaper.",
                confidence="medium",
            )
        )

    # 4. Surface disabled DSCP-affecting rules as low-severity hygiene.
    disabled_dscp = [r for r in dscp_rules if _is_disabled(r)]
    if disabled_dscp:
        result.findings.append(
            Finding(
                status="warn",
                severity="low",
                finding="Disabled DSCP-related rules remain configured",
                evidence=[_rule_label(r) for r in disabled_dscp],
                recommendation="Document intentionally dormant DSCP rules or remove stale rules to reduce audit noise.",
                confidence="medium",
            )
        )

    if not result.findings:
        result.findings.append(
            Finding(
                status="pass",
                severity="info",
                finding=f"DSCP policy appears present and internally consistent ({len(enabled_dscp)} enabled DSCP-related rules)",
                confidence="high",
            )
        )

    return result
