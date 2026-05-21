# gowireshark Codex Rules

Use the packaged wrapper, not the raw binary:

```bash
/path/to/gowireshark-cli-<target>/bin/gowireshark-env version
```

For PCAP work, follow `agents/pcap-analysis-rules.md`:

1. `frames count`
2. `streams list`
3. `expert list`
4. `filter validate-detailed` before new filters
5. `follow` only valid stream ids
6. `slice pcap` / `evidence bundle` only after narrowing scope

Avoid full frame dumps on unknown or large captures.
