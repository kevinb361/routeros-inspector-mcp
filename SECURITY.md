# Security policy

## Supported versions

Only the latest release on the default branch receives security fixes.

## Reporting a vulnerability

Do not open a public issue for vulnerabilities that could expose credentials, network configuration, or a route to RouterOS devices. Use GitHub's private vulnerability reporting feature when available, or contact the maintainer privately through the address listed on their GitHub profile.

Include the affected version, reproduction steps, impact, and any suggested remediation. Do not test against devices or networks you do not own or have explicit permission to assess.

## Deployment boundary

This project is read-only by design, but read access to router configuration is still sensitive.

- Use a dedicated least-privilege RouterOS identity.
- Prefer verified API-SSL with pinned trust.
- Keep inventory, policy, certificates, Vault files, logs, and captures outside Git.
- Use local stdio. HTTP is loopback-only and has no remote-deployment authentication contract.
- Do not add write-capable credentials or mutation tools to this service.

A future write-capable service must be a separate process and project with independent credentials, approvals, rollback controls, and deployment policy.

## Disclosure handling

Confirmed vulnerabilities will be triaged privately. A fix and advisory will be prepared before public disclosure when practical.
