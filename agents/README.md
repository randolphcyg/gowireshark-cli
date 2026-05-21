# Agent Integration Templates

This directory contains agent-neutral instructions for using packaged `gowireshark-cli` artifacts.

Recommended usage:

- CLI-only agents: read `pcap-analysis-rules.md` and call `bin/gowireshark-env`.
- MCP-capable agents: copy `mcp.json.template` into the host-specific config location and replace absolute paths.
- Claude Code: copy `.mcp.json.template` to the project root as `.mcp.json` if you want project-scoped MCP.
- Codex: keep `AGENTS.md` in the project root for instructions; configure MCP in your user/project Codex config as supported by your Codex runtime.

Never commit real local paths, tokens, extracted files, or large PCAPs.
