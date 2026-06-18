# MCP Tool Reference

## Core Analysis

```
triage_pcap(file, filter?)       — Frame count, streams, expert findings, stats, conversations
search_frames(file, filter?, page?, size?, fields?, indices?) — Paginated/batch/field frame search
get_frame(file, index, include_hex?, fields?) — Single frame with optional hex and fields
inspect_stream(file, protocol?, filter?) — Follow and reconstruct TCP/UDP stream
```

## Filter Helpers

```
validate_filter(expr, detailed?) — Validate display filter, set detailed=true for field feedback
suggest_filter(prefix, limit?)   — Suggest field names by prefix (e.g. 'tcp.')
```

## Metadata

```
get_field_info(name)            — Get metadata for a field (e.g. 'tcp.stream')
```

> Protocols are exposed as the `epan://docs/protocols` Resource (not a Tool). Use `list_protocols` via Resource access.

## Evidence & Export

```
slice_pcap(file, out, filter?, indices?)  — Slice PCAP by filter or indices
build_evidence(file, filter?)             — Conversations, endpoints, expert infos, protocol hierarchy
export_objects(file, protocol, action?, packet_num?, out?) — List or extract exportable objects (HTTP, SMB, etc.)
verify_zeek_alert(file, filter?, alert?, ...) — Verify Zeek alert against packet evidence
```

## CLI Equivalents (for reference)

The MCP tools wrap the following CLI commands:

```bash
epan frames count --file <file> [--filter <expr>]
epan streams list --file <file> [--filter <expr>]
epan expert list --file <file> [--filter <expr>]
epan stats --file <file> [--filter <expr>]
epan traffic conversations list --file <file> [--filter <expr>]
epan frames page --file <file> --page N --size N [--filter <expr>]
epan frames batch --file <file> --indices 1,5,10
epan frames fields --file <file> --fields ip.src,ip.dst [--filter <expr>]
epan frames get --file <file> --index N
epan frames hex --file <file> --index N
epan follow --file <file> --protocol tcp|udp --filter '<expr>'
epan filter validate --expr '<expr>'
epan filter validate-detailed --expr '<expr>'
epan filter suggest --prefix '<prefix>'
epan metadata field --name <name>
epan metadata protocols
epan slice pcap --file <file> --out <out> [--filter <expr>] [--indices <indices>]
epan evidence bundle --file <file> [--filter <expr>]
epan tap endpoints --file <file> --type ip [--filter <expr>]
epan export-object list --file <file> --protocol <proto>
epan export-object write --file <file> --protocol <proto> --packet-num N --out <out>
epan extract --file <file> --out <dir>
```

## Guidance

- Use `triage_pcap` as the first command for any new PCAP.
- `search_frames` is the default inspection command for paginated views.
- `inspect_stream` expects a Wireshark display filter (e.g. `tcp.stream eq 0`).
- `slice_pcap` creates a new pcap from selected frames.
- `build_evidence` produces comprehensive forensic metadata.
- `export_objects` with action=extract extracts exportable objects to disk.
- Always validate new display filters with `validate_filter` with detailed=true before using them.