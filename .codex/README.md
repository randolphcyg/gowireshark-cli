# Codex Integration

Codex project guidance should normally live in a root `AGENTS.md`. This package also ships `.codex/AGENTS.md` as a copyable template for projects that keep agent assets grouped by tool.

Recommended setup in a target project:

```bash
cp /path/to/gowireshark-cli-<target>/.codex/AGENTS.md ./AGENTS.md
```

If your Codex runtime supports MCP configuration, point it at:

```bash
/path/to/gowireshark-cli-<target>/bin/gowireshark-mcp-env
```

Keep real MCP config local unless your team intentionally shares it.
