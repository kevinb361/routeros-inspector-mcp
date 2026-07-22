# Hermes fixture integration

Use fixture mode for initial MCP discovery and smoke testing. It cannot contact RouterOS devices and does not require credentials.

## Install

```bash
python -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
```

## Verify in-process

```bash
.venv/bin/python scripts/smoke_mcp_fixture.py
```

The smoke test verifies discovery of `list_devices`, `list_audits`, and `run_audit`, then runs policy-backed audits against synthetic fixtures.

## Configure Hermes

Adapt this entry to the Hermes MCP configuration format in use:

```yaml
routeros-inspector:
  command: /absolute/path/to/routeros-inspector-mcp/.venv/bin/python
  args:
    - -m
    - routeros_inspector_mcp.server
    - --transport
    - stdio
    - --devices-path
    - /absolute/path/to/routeros-inspector-mcp/config/devices.example.yaml
    - --policy-path
    - /absolute/path/to/routeros-inspector-mcp/config/policy.example.yaml
    - --fixture-dir
    - /absolute/path/to/routeros-inspector-mcp/tests/fixtures/routeros
```

Do not add `--live` during fixture validation. Fixture-only composition is tested to ensure the live backend is never constructed.

## Expected synthetic inventory

- `edge-router`
- `core-switch`
- `access-switch`
- `branch-switch`

The checked-in fixtures use RFC 5737 documentation addresses and redacted placeholder secrets. They are purpose-built examples, not transformed production captures.

## Promotion to live mode

Treat live mode as a separate deployment:

1. Create ignored `config/devices.yaml` and `config/policy.yaml` files.
2. Provision a dedicated read-only RouterOS identity.
3. Configure pinned API-SSL trust and verify SAN identity.
4. Validate one device outside the agent client.
5. Add explicit file paths and `--live` to the client configuration.
6. Confirm the MCP tool surface remains fixed and read-only.

Never commit live inventory, policy, certificates, audit logs, or capture artifacts.
