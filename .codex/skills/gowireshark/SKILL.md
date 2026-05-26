---
name: gowireshark
description: Analyze packet captures with the gowireshark CLI. Use when a task involves pcap inspection, protocol statistics, frame lookup, display-filter validation, stream following, traffic maps, expert analysis, evidence bundling, or extracted objects from packet captures.
---

# gowireshark

Use the `gowireshark` CLI for packet-analysis work. Prefer the smallest query that answers the question.

## Recommended Agent Workflow

1. **Explore the capture landscape**: Start with `metadata fields` or `filter suggest` to discover available fields. Use `frames count` to gauge capture size.
2. **Understand traffic structure**: Use `streams list` to see TCP/UDP streams and their IDs. Each `streamId >= 0` is a followable stream.
3. **Deep-dive into streams**: For each interesting stream, use `follow --filter 'tcp.stream eq N'` to get reassembled payloads.
4. **Expert analysis**: Run `expert list` to find anomalies, retransmissions, and protocol violations.
5. **Evidence production**: Use `slice pcap` to extract relevant packets, or `evidence bundle` for comprehensive forensic output.
6. **File extraction**: Use `export-object list/write` when the task needs extracted HTTP objects.

## Output discipline

- Expect JSON on stdout and diagnostics on stderr.
- Summarize findings; do not paste large frame arrays unless the user asked for raw output.
- If a command fails because a filter or path is invalid, correct that first instead of retrying broader commands.

## Common flags available on most commands

`--filter`, `--decode-as`, `--profile`, `--pref`, `--name-resolution`, `--parse-mode`, `--layers`, `--compact`, `--raw-json`

## References

- Read `references/cli-reference.md` when you need exact command forms or flags.