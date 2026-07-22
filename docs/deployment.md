# Safe deployment

## Default: local fixture-backed stdio

Stdio creates no listening socket. Without `--live`, the server forces fixture dispatch regardless of inventory transport declarations.

```bash
python -m routeros_inspector_mcp.server \
  --transport stdio \
  --devices-path config/devices.example.yaml \
  --policy-path config/policy.example.yaml \
  --fixture-dir tests/fixtures/routeros
```

## Live local stdio

Prepare ignored local inventory/policy files, a dedicated read-only RouterOS identity, and pinned API-SSL trust before enabling live mode:

```bash
python -m routeros_inspector_mcp.server \
  --transport stdio \
  --devices-path config/devices.yaml \
  --policy-path config/policy.yaml \
  --live
```

Live mode is not a transport fallback. Each inventory device must have its configured backend available. API-SSL configuration errors and connection failures do not downgrade to plaintext.

## Loopback HTTP only

HTTP transports are disabled unless `--allow-loopback-http` is supplied. The server forces the bind address to `127.0.0.1`; no CLI option permits a broader bind.

```bash
python -m routeros_inspector_mcp.server \
  --transport http \
  --allow-loopback-http
```

Use stdio unless a local multi-client workflow specifically requires HTTP.

## Unsupported deployments

Do not expose this server on a LAN, VPN, public interface, container-published port, or reverse proxy without a separate design providing authentication, TLS, exact Host/Origin policy, rate limits, and a firewall boundary. The current server intentionally has no remote-bind option.

SSE is not offered. Streamable HTTP is subject to the same explicit loopback-only opt-in.

## Client configuration

Configure MCP clients with an absolute interpreter path when they do not activate your virtual environment. Keep `--live` out of client configuration until the inventory, credentials, TLS trust, and read-only device permissions have been independently verified.

Example fixture-backed command:

```json
{
  "command": "/absolute/path/to/.venv/bin/python",
  "args": [
    "-m",
    "routeros_inspector_mcp.server",
    "--transport",
    "stdio",
    "--devices-path",
    "/absolute/path/to/config/devices.example.yaml",
    "--policy-path",
    "/absolute/path/to/config/policy.example.yaml",
    "--fixture-dir",
    "/absolute/path/to/tests/fixtures/routeros"
  ]
}
```

## References

- RouterOS behavior and API semantics: <https://manual.mikrotik.com/llms.txt>
- FastMCP local transports: <https://gofastmcp.com/deployment/running-server>
- FastMCP HTTP authentication and Host/Origin protection: <https://gofastmcp.com/deployment/http>
