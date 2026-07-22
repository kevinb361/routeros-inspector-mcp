# routeros-inspector-mcp

A constrained, read-only MCP server for MikroTik RouterOS inventory inspection and policy-backed audits.

The server is fixture-only by default. Live access requires an explicit `--live` flag, inventory-defined devices, read-only credentials, and fail-closed transport configuration. It does not expose arbitrary RouterOS commands or mutation tools.

## Safety model

- No arbitrary command execution
- No mutation, reboot, restore, firmware, or user-management tools
- No caller-supplied hosts or IP addresses; callers select inventory device IDs only
- Fixture-only operation unless `--live` is explicitly supplied
- Verified API-SSL with pinned CA trust, hostname verification, and TLS 1.2+
- No plaintext downgrade when TLS is configured
- Allowlisted client errors and redacted outputs
- Bounded audit fan-out
- Stdio by default; optional HTTP is forced to `127.0.0.1`

See [docs/deployment.md](docs/deployment.md) for the complete deployment boundary and [CHANGELOG.md](CHANGELOG.md) for release history.

## Requirements

- Python 3.11+
- RouterOS 7 for live API use
- `ansible-vault` only when using the included Vault credential provider

## Installation

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test]'
```

## Fixture-first quick start

The checked-in inventory, policy, and RouterOS data are purpose-built synthetic examples.
They contain no live-derived topology.

```bash
routeros-inspector list-devices --summary
routeros-inspector audit \
  --devices edge-router,core-switch \
  --audits vlan_consistency,wan_failover_state,snmp_scope \
  --summary
python scripts/smoke_mcp_fixture.py
python -m routeros_inspector_mcp.server --transport stdio
```

Fixture mode never constructs a live RouterOS backend, even if an explicitly supplied inventory declares live transports.

## Configuration

Copy the synthetic examples before configuring live access:

```bash
cp config/devices.example.yaml config/devices.yaml
cp config/policy.example.yaml config/policy.yaml
```

`config/devices.yaml` and `config/policy.yaml` are ignored because real inventories and policies reveal operational details. Keep certificates and live captures outside the repository.

A verified API-SSL inventory entry looks like:

```yaml
devices:
  edge-router:
    role: gateway
    risk: critical
    host: router.example.net
    transport: api
    credential_ref: vault_mikrotik_readonly
    allowed: true
    routeros_api_port: 8729
    routeros_api_tls: true
    routeros_api_certificate: /absolute/path/to/router-ca.pem
    routeros_api_server_name: router.example.net
```

TLS mode requires TCP/8729, a readable CA/certificate path, and a nonempty DNS name or IP SAN identity. Configuration errors fail closed and never trigger plaintext fallback.

## Credential provider

The included provider resolves `<credential_ref>_username` and `<credential_ref>_password` from an Ansible Vault without logging values. Configure it with:

```bash
export ROUTEROS_INSPECTOR_VAULT_DIR="$HOME/.config/routeros-inspector-mcp"
export ROUTEROS_INSPECTOR_VAULT_FILE="vault.yml"
export ROUTEROS_INSPECTOR_VAULT_PASSWORD_FILE=".vault_pass"
```

The two file variables may also be absolute paths. Use a dedicated RouterOS read-only identity. Do not use a personal administrator or write-capable credential.

## MCP tools

The server exposes fixed collectors such as device summaries, interfaces, bridge VLANs, routes, firewall tables, DHCP/ARP state, queues, WireGuard metadata, and IP services. It also exposes named audits for firmware, SNMP scope, STP, VLAN/trunk consistency, route ownership, WAN failover, encrypted DNS, QoS/DSCP, and backup metadata.

Tool responses omit connection details and credential references. Sensitive RouterOS fields are redacted.

## Private fixture capture

`scripts/refresh_routeros_fixture.py` can transform an existing private artifact directory without network access. Live collection additionally requires the explicit `--capture-live` flag and explicit Ansible root, inventory, playbook, and Vault password paths. Captures still reveal topology and policy and default to the ignored `artifacts/private-fixtures/` directory. Never copy them into `tests/fixtures/routeros/` or commit them. Public tests must use purpose-built synthetic fixtures.

## Development

```bash
make ci
```

Equivalent commands:

```bash
ruff check .
pytest -n auto -q
python -m compileall -q src tests
```

## Security

Please read [SECURITY.md](SECURITY.md) before enabling live mode. Report vulnerabilities privately rather than opening a public issue.

## License

MIT — see [LICENSE](LICENSE).
