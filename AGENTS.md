# epan-cli Agent Rules

Use `epan` as a bounded forensic toolbox. Prefer the smallest command that answers the question and preserve reproducible evidence.

## Default PCAP Workflow

1. Gauge capture size first:
   ```bash
   epan frames count --file <pcap>
   epan stats --file <pcap>
   ```
2. Map traffic structure:
   ```bash
   epan streams list --file <pcap>
   ```
3. Check protocol and dissector anomalies:
   ```bash
   epan expert list --file <pcap>
   ```
4. Follow only mapped streams where `streamId >= 0`:
   ```bash
   epan follow --file <pcap> --protocol tcp --filter 'tcp.stream eq N'
   ```
5. Validate new display filters before using them:
   ```bash
   epan filter validate-detailed --expr '<expr>'
   ```
6. Produce evidence only after narrowing scope:
   ```bash
   epan slice pcap --file <pcap> --filter '<expr>' --out evidence.pcap
   epan evidence bundle --file <pcap> --filter '<expr>'
   ```
7. Extract files when needed:
   ```bash
   epan extract --file <pcap> --out extracted-files/
   epan export-object list --file <pcap> --protocol http
   ```

## Output Discipline

- Do not dump all frames from an unknown or large capture.
- Prefer `frames page`, `frames fields`, `streams list`, `expert list`, `slice pcap`, and `evidence bundle`.
- JSON is emitted on stdout; diagnostics belong on stderr.
- Use real Wireshark field names such as `frame.number`, `ip.src`, `ip.dst`, and `frame.protocols`.

## MCP Tool Names

MCP uses breaking, Agent-oriented names. Prefer `health_check`, `count_frames`, `list_streams`, `list_expert_findings`, `validate_filter`, `verify_zeek_alert`, `create_pcap_slice`, and `create_evidence_bundle`. Do not use removed legacy names.

## Validation

Run before handing off CLI changes:

```bash
go test ./...
```

Do not commit a `replace github.com/randolphcyg/epan => ../epan` directive in `go.mod`. Use a parent `go.work` file for local multi-repo development; release builds use the tagged SDK dependency and build scripts may inject temporary local replaces internally.
