# Contributing

Contributions are welcome when they preserve the project's read-only security boundary.

## Before opening a pull request

1. Create a focused branch.
2. Add or update tests.
3. Run `make ci`.
4. Run `gitleaks git . --log-opts='--all'` when changing configuration, fixtures, or documentation.
5. Confirm the diff contains no live-derived network data, personal paths, credentials, certificates, logs, or operational artifacts.

## Design constraints

Pull requests must not add:

- arbitrary RouterOS command execution;
- mutation, reboot, restore, firmware, or user-management tools;
- caller-supplied hosts or addresses;
- write-capable credential requirements;
- plaintext fallback from configured TLS;
- remote HTTP binding without a separately reviewed authentication design;
- production-derived fixtures, even when credential fields are redacted.

Return `unknown` when an audit lacks sufficient evidence or policy. Keep tools fixed, outputs redacted, and fan-out bounded.

## Fixtures

Checked-in fixtures must be purpose-built synthetic data using documentation addresses and placeholder identities. Private captures belong under ignored local paths and must never be copied into the test fixture directory.
