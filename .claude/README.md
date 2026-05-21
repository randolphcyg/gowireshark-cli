# Claude Code Integration

Claude Code reads project instructions from `CLAUDE.md`. This package includes a root `CLAUDE.md` template and an MCP template.

Project-scoped MCP setup:

```bash
cp /path/to/gowireshark-cli-<target>/.mcp.json.template ./.mcp.json
# edit absolute paths
claude --debug mcp
```

Claude Code may prompt for approval before using project-scoped MCP servers. Keep `.claude/settings.local.json` and other personal approvals out of git.
