# RouterOS Inspector MCP

## Purpose

A constrained, read-only MCP facade for MikroTik RouterOS inspection and policy-backed audits.

## Hard safety boundary

- Read-only only: never add mutation, reboot, restore, firmware, or user-management tools.
- Never expose arbitrary RouterOS commands.
- Accept inventory device IDs only; never accept caller-supplied hosts or IP addresses.
- Fixture-only by default; live mode requires explicit `--live`.
- Fail closed when the configured backend is unavailable.
- API-SSL requires pinned trust, hostname verification, and TLS 1.2+ with no plaintext downgrade.
- Keep stdio as the default. Network transports require explicit opt-in and bind only to loopback.
- Redact secrets from tool output, logs, tests, and artifacts.
- Bound multi-device and multi-audit fan-out before performing work.

## Public-repository hygiene

- Checked-in fixtures must be purpose-built synthetic data, not production captures.
- Use RFC 5737 addresses and `example.*` names in examples.
- Never commit `config/devices.yaml`, `config/policy.yaml`, certificates, live captures, audit logs, credentials, personal paths, or operational planning evidence.
- Private credential and inventory integration belongs in ignored local configuration.

## References

Use <https://manual.mikrotik.com/llms.txt> as the primary index for RouterOS API behavior.

## Validation

```bash
make ci
```

The equivalent gate is:

```bash
ruff check .
pytest -n auto -q
python -m compileall -q src tests
git diff --check
```

Keep implementation small, inspectable, and conservative. Audits return `unknown` rather than claiming pass/fail when evidence or policy is missing.
