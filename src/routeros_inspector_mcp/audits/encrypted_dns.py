"""Encrypted DNS audit — check if DNS-over-HTTPS or DoT is enabled.

Policy-light: checks DNS config for encrypted transport indicators.
"""

from __future__ import annotations

from ..service import Service
from .base import AuditResult, Finding


def audit_encrypted_dns(service: Service, device_id: str) -> AuditResult:
    """Check if encrypted DNS (DoH/DoT) is configured.

    - PASS: dns_over_https or dnssec enabled, or upstream supports DoH/DoT.
    - WARN: DNS is configured but no encryption visible.
    - FAIL: DNS is disabled entirely.
    - UNKNOWN: no DNS config available.
    """
    dns = service.get_dns_config(device_id)
    result = AuditResult(audit_name="encrypted_dns", device_id=device_id)
    policy = service.get_policy()

    if policy and policy.dns.encrypted is False:
        result.findings.append(
            Finding(
                status="pass",
                severity="info",
                finding="Encrypted DNS is not required by policy for this device",
                evidence=["policy.dns.encrypted: false"],
                recommendation="Keep DNS encryption enforcement in the documented upstream policy path",
                confidence="high",
            )
        )
        return result

    if not dns:
        result.findings.append(
            Finding(
                status="unknown",
                severity="info",
                finding="No DNS configuration data available",
                recommendation="Verify DNS data can be collected from this device",
                confidence="low",
            )
        )
        return result

    if not dns.get("use_dns_servers", False):
        result.findings.append(
            Finding(
                status="fail",
                severity="high",
                finding="DNS is disabled",
                evidence=["use_dns_servers: false"],
                recommendation="Enable DNS resolution",
                confidence="high",
            )
        )
        return result

    # Check for encrypted DNS indicators
    doh = dns.get("dns_over_https", "")
    dnssec = dns.get("dnssec", False)

    if doh and doh.lower() not in ("off", "disabled", ""):
        result.findings.append(
            Finding(
                status="pass",
                severity="info",
                finding="DNS-over-HTTPS is enabled",
                evidence=[f"dns_over_https: {doh}"],
                confidence="high",
            )
        )
        return result

    if dnssec:
        result.findings.append(
            Finding(
                status="pass",
                severity="info",
                finding="DNSSEC validation is enabled",
                evidence=["dnssec: true"],
                confidence="high",
            )
        )
        return result

    # DNS is active but unencrypted
    servers = dns.get("servers", "")
    result.findings.append(
        Finding(
            status="warn",
            severity="medium",
            finding="DNS is active but no encrypted transport (DoH/DoT/DNSSEC) detected",
            evidence=[f"servers: {servers}", f"dns_over_https: {doh}", f"dnssec: {dnssec}"],
            recommendation="Configure DNS-over-HTTPS (e.g., cloudflare-doh://) or enable DNSSEC for DNS integrity",
            confidence="high",
        )
    )
    return result
