# Agent Integration Templates

This directory contains agent-neutral instructions for using packaged `epan-cli` artifacts.

Recommended usage:

- CLI-only agents: read `pcap-analysis-rules.md` and call `bin/epan-env`.
- MCP-capable agents: copy `mcp.json.template` into the host-specific config location and replace absolute paths.
- Claude Code: copy `.mcp.json.template` to the project root as `.mcp.json` if you want project-scoped MCP.
- Codex: keep `AGENTS.md` in the project root for instructions; configure MCP in your user/project Codex config as supported by your Codex runtime.

## MCP Transport Modes

### stdio (default)

Local, secure, no authentication needed. The MCP server communicates via stdin/stdout.

```json
{
  "epan": {
    "command": "/path/to/bin/epan-mcp-env",
    "args": [],
    "env": { ... }
  }
}
```

### HTTP

Remote/cross-process access with Bearer token authentication. Use `--transport=http`.

```json
{
  "epan-http": {
    "command": "/path/to/bin/epan-mcp-env",
    "args": ["--transport=http", "--listen=127.0.0.1:8002", "--endpoint=/mcp", "--token=your-secure-token"],
    "env": { ... }
  }
}
```

Health check endpoint: `GET http://127.0.0.1:8002/healthz` (no auth required).

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `EPAN_BIN` | `epan` | Path to the epan CLI binary |
| `EPAN_PCAP_DIR` | (none) | Allowed directory for PCAP file access (path sandbox) |
| `EPAN_OUTPUT_DIR` | system temp | Allowed directory for output files (path sandbox) |
| `EPAN_TIMEOUT` | `120s` | Command execution timeout |
| `EPAN_MAX_OUTPUT_BYTES` | `2097152` (2MB) | Max output before truncation |

### Security & Debug

| Variable | Description |
|---|---|
| `MCP_CALL_LOG_PATH` | Write JSONL audit log with tool name, duration, status per call |
| `MCP_TRACE_ID` | Override auto-generated trace ID |

## Security Features

- **Path sandbox**: `EPAN_PCAP_DIR` and `EPAN_OUTPUT_DIR` restrict file access to whitelist directories. Path traversal and symlink escapes are rejected.
- **Rate limiting**: HTTP mode enforces a sliding-window limit of 30 requests/second.
- **Token authentication**: HTTP mode supports `--token` with Bearer token validation. Unauthenticated requests receive 401.
- **Input validation**: Filter expressions, field names, and paths have length limits to prevent abuse.
- **Subprocess isolation**: Each `epan` invocation runs in its own process group; timeouts kill the entire process tree.
- **Audit logging**: Enable `MCP_CALL_LOG_PATH` to record every tool call with tool name, duration, and status.

Never commit real local paths, tokens, extracted files, or large PCAPs.