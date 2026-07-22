# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0] - 2026-07-21

### Added

- Initial public release of the fixture-first RouterOS inspection MCP server.
- Fixed read-only collectors for interfaces, bridge VLANs, routes, firewall state, DHCP/ARP, queues, WireGuard metadata, IP services, and related RouterOS state.
- Policy-backed audits for firmware, SNMP scope, STP, VLANs, trunks, route ownership, WAN failover, DNS, QoS/DSCP, mangle correlation, and backup metadata.
- Purpose-built synthetic inventory, policy, and RouterOS fixtures for offline use.
- Local stdio deployment documentation and explicit loopback-only HTTP opt-in.
- MIT license, security policy, contribution guide, and Python 3.11/3.12 CI.

### Security

- Fixture-only dispatch by default; live access requires `--live`.
- No mutation tools, arbitrary RouterOS commands, or caller-supplied hosts.
- Fail-closed transport dispatch with no backend substitution.
- Verified API-SSL support with pinned CA trust, hostname verification, TLS 1.2+, and no plaintext downgrade.
- Allowlisted client errors, sensitive-field redaction, private structured diagnostics, and deterministic connection cleanup.
- Deduplicated audit requests with a 128-operation fan-out limit validated before execution.
- HTTP transports disabled by default and restricted to `127.0.0.1` when explicitly enabled.
- Private fixture capture requires explicit source selection; live capture additionally requires `--capture-live` and operator-supplied wrapper paths.

### Known limitations

- Remote network deployment is unsupported; the server has no remote authentication contract.
- The bundled credential provider targets an operator-configured Ansible Vault.
- Write capability is intentionally out of scope and belongs in a separate service with independent credentials and approval controls.

[Unreleased]: https://github.com/kevinb361/routeros-inspector-mcp/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/kevinb361/routeros-inspector-mcp/releases/tag/v0.3.0
