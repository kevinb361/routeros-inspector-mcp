"""Policy-backed audits — compare device state to policy.yaml.

Missing policy yields 'unknown', never false pass/fail.
"""

from __future__ import annotations

from ..service import Service
from .base import AuditResult, Finding


def _split_csv(value: object) -> set[str]:
    """Split RouterOS comma-separated fields into a normalized string set."""
    if value is None:
        return set()
    if isinstance(value, list):
        return {str(item).strip() for item in value if str(item).strip()}
    return {part.strip() for part in str(value).split(",") if part.strip()}


def _parse_vlan_ids(value: object) -> set[int]:
    """Parse RouterOS vlan_ids fields, including comma-separated rows."""
    vlan_ids: set[int] = set()
    for part in _split_csv(value):
        try:
            vlan_ids.add(int(part))
        except ValueError:
            continue
    return vlan_ids


def _is_truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "yes", "1", "on"}


def audit_firmware_drift(service: Service, device_id: str) -> AuditResult:
    """Check if device firmware matches policy expected version.

    Returns unknown if policy firmware section is empty for this device.
    """
    result = AuditResult(audit_name="firmware_drift", device_id=device_id)
    policy = service.get_policy()
    current = service.get_firmware_version(device_id)

    if not policy or not policy.firmware.expected_versions.get(device_id):
        result.findings.append(
            Finding(
                status="unknown",
                severity="info",
                finding=f"No firmware policy for {device_id}",
                evidence=[f"current_version: {current}"],
                recommendation="Add expected firmware version for this device in policy.yaml",
                confidence="low",
            )
        )
        return result

    expected = policy.firmware.expected_versions[device_id]
    # Compare major.minor (e.g., "7.17" matches "7.17.3")
    if current.startswith(expected) or current == expected:
        result.findings.append(
            Finding(
                status="pass",
                severity="info",
                finding=f"Firmware matches expected version {expected}",
                evidence=[f"current: {current}", f"expected: {expected}"],
                confidence="high",
            )
        )
    else:
        result.findings.append(
            Finding(
                status="fail",
                severity="high",
                finding="Firmware drift detected",
                evidence=[f"current: {current}", f"expected: {expected}"],
                recommendation=f"Upgrade firmware to {expected}",
                confidence="high",
            )
        )
    return result


def audit_snmp_scope(service: Service, device_id: str) -> AuditResult:
    """Check SNMP configuration against non-secret policy.

    Community names are credentials and may be intentionally omitted from policy.
    When omitted, this audit still validates allowed access scopes if configured.
    """
    result = AuditResult(audit_name="snmp_scope", device_id=device_id)
    policy = service.get_policy()
    snmp = service.get_snmp_config(device_id)

    if not policy or (
        not policy.snmp.allowed_communities
        and not policy.snmp.allowed_access
        and not policy.snmp.community_policy
    ):
        result.findings.append(
            Finding(
                status="unknown",
                severity="info",
                finding="No SNMP policy configured",
                recommendation="Populate snmp.allowed_access in policy.yaml",
                confidence="low",
            )
        )
        return result

    if not snmp:
        result.findings.append(
            Finding(
                status="unknown",
                severity="info",
                finding="No SNMP configuration data available",
                recommendation="Verify SNMP data can be collected",
                confidence="low",
            )
        )
        return result

    findings: list[Finding] = []

    if policy.snmp.allowed_access:
        expected_access = set(policy.snmp.allowed_access)
        actual_access = _split_csv(snmp.get("allowed_addresses", ""))
        extra_access = actual_access - expected_access
        missing_access = expected_access - actual_access

        if extra_access:
            findings.append(
                Finding(
                    status="fail",
                    severity="high",
                    finding="SNMP permits access outside policy",
                    evidence=[
                        f"allowed_access: {sorted(expected_access)}",
                        f"actual_access: {sorted(actual_access)}",
                        f"extra_access: {sorted(extra_access)}",
                    ],
                    recommendation="Restrict SNMP address scope to policy-approved collectors/subnets",
                    confidence="high",
                )
            )
        elif missing_access:
            findings.append(
                Finding(
                    status="pass",
                    severity="info",
                    finding="SNMP access scope is within policy and narrower than baseline",
                    evidence=[
                        f"allowed_access: {sorted(expected_access)}",
                        f"actual_access: {sorted(actual_access)}",
                        f"omitted_access: {sorted(missing_access)}",
                    ],
                    recommendation="No action needed unless the omitted scope is required for monitoring",
                    confidence="high",
                )
            )
        else:
            findings.append(
                Finding(
                    status="pass",
                    severity="info",
                    finding="SNMP access scope matches policy",
                    evidence=[f"allowed_access: {sorted(actual_access)}"],
                    confidence="high",
                )
            )

    if not policy.snmp.allowed_communities:
        if policy.snmp.community_policy == "secret_store":
            findings.append(
                Finding(
                    status="pass",
                    severity="info",
                    finding="SNMP community value is managed by declared secret-store policy",
                    evidence=["community_policy: secret_store", "community_redacted: true"],
                    recommendation="Keep SNMP community names out of versioned policy; audit access scopes here",
                    confidence="high",
                )
            )
        else:
            findings.append(
                Finding(
                    status="unknown",
                    severity="info",
                    finding="SNMP community name policy intentionally not versioned",
                    evidence=["community_redacted: true"],
                    recommendation=(
                        "Set snmp.community_policy: secret_store when community values are "
                        "managed outside versioned policy"
                    ),
                    confidence="medium",
                )
            )
        result.findings.extend(findings)
        return result

    community = snmp.get("community", "")
    if community not in policy.snmp.allowed_communities:
        findings.append(
            Finding(
                status="fail",
                severity="high",
                finding="SNMP community is not in allowed list",
                evidence=[
                    f"community: {community} (not in allowed: {policy.snmp.allowed_communities})"
                ],
                recommendation="Change SNMP community to an allowed value from policy",
                confidence="high",
            )
        )
        result.findings.extend(findings)
        return result

    findings.append(
        Finding(
            status="pass",
            severity="info",
            finding="SNMP community matches policy",
            evidence=[f"community: {community}"],
            confidence="high",
        )
    )
    result.findings.extend(findings)
    return result


def audit_stp_edge(service: Service, device_id: str) -> AuditResult:
    """Check STP edge port configuration against policy.

    Returns unknown if policy STP section is empty for this device.
    """
    result = AuditResult(audit_name="stp_edge", device_id=device_id)
    policy = service.get_policy()

    if not policy or not policy.stp.edge_ports.get(device_id):
        result.findings.append(
            Finding(
                status="unknown",
                severity="info",
                finding=f"No STP edge policy for {device_id}",
                recommendation="Add stp.edge_ports for this device in policy.yaml",
                confidence="low",
            )
        )
        return result

    expected_ports = set(policy.stp.edge_ports[device_id])
    bridge_ports = service.get_bridge_ports(device_id)
    actual_ports = {bp.get("interface", "") for bp in bridge_ports}

    missing = expected_ports - actual_ports
    if missing:
        result.findings.append(
            Finding(
                status="fail",
                severity="high",
                finding="STP edge ports missing from bridge configuration",
                evidence=[f"expected: {expected_ports}", f"actual: {actual_ports}", f"missing: {missing}"],
                recommendation="Add missing ports to bridge configuration with STP edge enabled",
                confidence="high",
            )
        )
    else:
        result.findings.append(
            Finding(
                status="pass",
                severity="info",
                finding="STP edge ports match policy",
                evidence=[f"expected_ports: {expected_ports}"],
                confidence="high",
            )
        )
    return result


def audit_vlan_consistency(service: Service, device_id: str) -> AuditResult:
    """Check VLAN configuration against policy.

    Returns unknown if policy VLAN section is empty for this device.
    """
    result = AuditResult(audit_name="vlan_consistency", device_id=device_id)
    policy = service.get_policy()

    if not policy or not policy.vlans.expected_vlans.get(device_id):
        result.findings.append(
            Finding(
                status="unknown",
                severity="info",
                finding=f"No VLAN policy for {device_id}",
                recommendation="Add vlans.expected_vlans for this device in policy.yaml",
                confidence="low",
            )
        )
        return result

    expected = set(policy.vlans.expected_vlans[device_id])
    vlans = service.get_bridge_vlans(device_id)

    # Collect all configured/static VLAN IDs from bridge_vlans. RouterOS may
    # synthesize dynamic/default VLAN 1 rows; ignore those unless policy names
    # VLAN 1 explicitly.
    actual: set[int] = set()
    for v in vlans:
        if v.get("dynamic", False) and 1 not in expected:
            continue
        for vlan_id in _parse_vlan_ids(v.get("vlan_ids", "")):
            if vlan_id == 1 and 1 not in expected:
                continue
            actual.add(vlan_id)

    missing = expected - actual
    extra = actual - expected

    if missing or extra:
        evidences: list[str] = [f"expected: {sorted(expected)}", f"actual: {sorted(actual)}"]
        if missing:
            evidences.append(f"missing: {sorted(missing)}")
        if extra:
            evidences.append(f"extra: {sorted(extra)}")

        result.findings.append(
            Finding(
                status="fail" if missing else "warn",
                severity="medium",
                finding="VLAN inconsistency detected",
                evidence=evidences,
                recommendation="Align bridge VLAN configuration with policy",
                confidence="high",
            )
        )
    else:
        result.findings.append(
            Finding(
                status="pass",
                severity="info",
                finding="VLAN configuration matches policy",
                evidence=[f"vlans: {sorted(actual)}"],
                confidence="high",
            )
        )
    return result


def audit_trunk_vlan_sanity(service: Service, device_id: str) -> AuditResult:
    """Check expected trunk ports carry expected VLANs and are not access-port shaped."""
    result = AuditResult(audit_name="trunk_vlan_sanity", device_id=device_id)
    policy = service.get_policy()

    expected_trunks = policy.vlans.expected_trunks.get(device_id, {}) if policy else {}
    if not expected_trunks:
        result.findings.append(
            Finding(
                status="unknown",
                severity="info",
                finding=f"No trunk VLAN policy for {device_id}",
                recommendation="Add vlans.expected_trunks for this device in policy.yaml",
                confidence="low",
            )
        )
        return result

    bridge_ports = service.get_bridge_ports(device_id)
    bridge_vlans = service.get_bridge_vlans(device_id)
    ports_by_name = {str(port.get("interface", "")): port for port in bridge_ports}
    tagged_by_port: dict[str, set[int]] = {port_name: set() for port_name in expected_trunks}

    for row in bridge_vlans:
        if _is_truthy(row.get("disabled", False)):
            continue
        vlan_ids = _parse_vlan_ids(row.get("vlan_ids", ""))
        tagged_ports = _split_csv(row.get("tagged", ""))
        for port_name in tagged_by_port:
            if port_name in tagged_ports:
                tagged_by_port[port_name].update(vlan_ids)

    findings: list[Finding] = []
    for port_name, vlan_list in expected_trunks.items():
        expected_vlans = set(vlan_list)
        port = ports_by_name.get(port_name)
        if port is None:
            findings.append(
                Finding(
                    status="fail",
                    severity="high",
                    finding="Expected trunk port is missing from bridge ports",
                    evidence=[f"port: {port_name}"],
                    recommendation="Restore the expected bridge trunk port or update policy if decommissioned",
                    confidence="high",
                )
            )
            continue

        missing_vlans = expected_vlans - tagged_by_port[port_name]
        evidence = [
            f"port: {port_name}",
            f"expected_vlans: {sorted(expected_vlans)}",
            f"tagged_vlans: {sorted(tagged_by_port[port_name])}",
            f"pvid: {port.get('pvid')}",
            f"edge: {port.get('edge')}",
        ]
        if missing_vlans:
            findings.append(
                Finding(
                    status="fail",
                    severity="high",
                    finding="Expected trunk is missing tagged VLANs",
                    evidence=[*evidence, f"missing_vlans: {sorted(missing_vlans)}"],
                    recommendation="Align bridge VLAN tagged membership with policy before relying on this trunk",
                    confidence="high",
                )
            )
        elif port.get("pvid") not in {1, "1", None} and port.get("frame_types") != "admit-only-vlan-tagged":
            findings.append(
                Finding(
                    status="warn",
                    severity="medium",
                    finding="Expected trunk has non-default PVID",
                    evidence=[*evidence, f"frame_types: {port.get('frame_types')}"],
                    recommendation="Verify this is an intentional hybrid trunk; otherwise set trunk PVID to 1",
                    confidence="medium",
                )
            )

    if findings:
        result.findings.extend(findings)
        return result

    result.findings.append(
        Finding(
            status="pass",
            severity="info",
            finding="Expected trunk VLAN membership matches policy",
            evidence=[
                f"trunks: {sorted(expected_trunks)}",
                f"checked_ports: {len(expected_trunks)}",
            ],
            confidence="high",
        )
    )
    return result


def audit_default_route_sanity(service: Service, device_id: str) -> AuditResult:
    """Check default-route shape without treating switches like WAN gateways."""
    result = AuditResult(audit_name="default_route_sanity", device_id=device_id)
    role = service.get_device_role(device_id)
    routes = service.get_routes(device_id)
    default_routes = [r for r in routes if r.get("dst_address") == "0.0.0.0/0"]
    active_defaults = [r for r in default_routes if not _is_truthy(r.get("disabled", False))]
    evidence = [
        f"role: {role}",
        f"default_routes: {len(default_routes)}",
        f"active_default_routes: {len(active_defaults)}",
    ]

    if not default_routes:
        result.findings.append(
            Finding(
                status="fail" if role in {"gateway", "edge"} else "warn",
                severity="high" if role in {"gateway", "edge"} else "medium",
                finding="No default route configured",
                evidence=evidence,
                recommendation="Verify management reachability and routing policy for this device",
                confidence="high",
            )
        )
        return result

    if role in {"gateway", "edge"}:
        if len(active_defaults) < 2 and service.device_has_tag(device_id, "dual-wan"):
            result.findings.append(
                Finding(
                    status="warn",
                    severity="medium",
                    finding="Dual-WAN gateway has fewer than two active default routes",
                    evidence=[
                        *evidence,
                        *[
                            f"default route: gw={r.get('gateway', '?')}, distance={r.get('distance', '?')}"
                            for r in default_routes
                        ],
                    ],
                    recommendation="Verify both WAN default routes are present and intentionally enabled",
                    confidence="high",
                )
            )
            return result

        result.findings.append(
            Finding(
                status="pass",
                severity="info",
                finding="Gateway default route shape is sane",
                evidence=evidence,
                confidence="high",
            )
        )
        return result

    if len(active_defaults) == 1:
        result.findings.append(
            Finding(
                status="pass",
                severity="info",
                finding="Switch has a single management default route",
                evidence=[
                    *evidence,
                    f"gateway: {active_defaults[0].get('gateway', '?')}",
                ],
                confidence="high",
            )
        )
    else:
        result.findings.append(
            Finding(
                status="warn",
                severity="medium",
                finding="Switch default route count is unusual",
                evidence=evidence,
                recommendation="Switches should usually have one management default route, not WAN failover shape",
                confidence="medium",
            )
        )
    return result


def audit_route_ownership(service: Service, device_id: str) -> AuditResult:
    """Check that device routes match policy-owned prefixes.

    Returns unknown if policy route section is empty.
    """
    result = AuditResult(audit_name="route_ownership", device_id=device_id)
    policy = service.get_policy()

    if not policy or not policy.routes.owned_prefixes.get(device_id):
        result.findings.append(
            Finding(
                status="unknown",
                severity="info",
                finding=f"No route ownership policy for {device_id}",
                recommendation="Add routes.owned_prefixes for this device in policy.yaml",
                confidence="low",
            )
        )
        return result

    expected_prefixes = set(policy.routes.owned_prefixes[device_id])
    routes = service.get_routes(device_id)
    actual_prefixes = {r.get("dst_address", "") for r in routes}

    missing = expected_prefixes - actual_prefixes
    if missing:
        result.findings.append(
            Finding(
                status="fail",
                severity="high",
                finding="Owned prefixes missing from routing table",
                evidence=[f"expected: {sorted(expected_prefixes)}", f"actual: {sorted(actual_prefixes)}", f"missing: {sorted(missing)}"],
                recommendation="Investigate missing routes — check gateway connectivity and route configuration",
                confidence="high",
            )
        )
    else:
        result.findings.append(
            Finding(
                status="pass",
                severity="info",
                finding="Route ownership matches policy",
                evidence=[f"owned_prefixes: {sorted(expected_prefixes)}"],
                confidence="high",
            )
        )
    return result


def audit_wan_failover_state(service: Service, device_id: str) -> AuditResult:
    """Check WAN failover configuration.

    Returns unknown if policy failover section is incomplete.
    """
    result = AuditResult(audit_name="wan_failover_state", device_id=device_id)
    policy = service.get_policy()

    role = service.get_device_role(device_id)
    if role not in {"gateway", "edge"}:
        result.findings.append(
            Finding(
                status="skip",
                severity="info",
                finding="WAN failover audit does not apply to this device role",
                evidence=[f"role: {role}"],
                recommendation="No action needed; run WAN failover audit only on gateway/edge devices",
                confidence="high",
            )
        )
        return result

    if not policy or not policy.wan_failover.primary:
        result.findings.append(
            Finding(
                status="unknown",
                severity="info",
                finding="No WAN failover policy configured",
                recommendation="Configure wan_failover.primary (and optionally secondary) in policy.yaml",
                confidence="low",
            )
        )
        return result

    routes = service.get_routes(device_id)
    default_routes = [r for r in routes if r.get("dst_address") == "0.0.0.0/0"]

    if not default_routes:
        result.findings.append(
            Finding(
                status="fail",
                severity="high",
                finding="No default route found — WAN connectivity may be broken",
                recommendation="Check gateway configuration and ensure default route exists",
                confidence="high",
            )
        )
        return result

    evidences = [f"default route: gw={r.get('gateway', '?')}, distance={r.get('distance', '?')}" for r in default_routes]

    if len(default_routes) < 2 and policy.wan_failover.secondary:
        result.findings.append(
            Finding(
                status="warn",
                severity="medium",
                finding="Only one default route — failover may not be active",
                evidence=evidences,
                recommendation="Ensure both primary and secondary default routes are configured for failover",
                confidence="high",
            )
        )
        return result

    result.findings.append(
        Finding(
            status="pass",
            severity="info",
            finding="WAN failover routes are configured",
            evidence=evidences,
            confidence="high",
        )
    )
    return result
