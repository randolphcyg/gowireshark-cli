# gowireshark-cli Agent Rules

Use `gowireshark` as a bounded forensic toolbox. Prefer the smallest command that answers the question and preserve reproducible evidence.

## Default PCAP Workflow

1. Gauge capture size first:
   ```bash
   gowireshark frames count --file <pcap>
   gowireshark stats --file <pcap>
   ```
2. Map traffic structure:
   ```bash
   gowireshark streams list --file <pcap>
   ```
3. Check protocol and dissector anomalies:
   ```bash
   gowireshark expert list --file <pcap>
   ```
4. Follow only mapped streams where `streamId >= 0`:
   ```bash
   gowireshark follow --file <pcap> --protocol tcp --filter 'tcp.stream eq N'
   ```
5. Validate new display filters before using them:
   ```bash
   gowireshark filter validate-detailed --expr '<expr>'
   ```
6. Produce evidence only after narrowing scope:
   ```bash
   gowireshark slice pcap --file <pcap> --filter '<expr>' --out evidence.pcap
   gowireshark evidence bundle --file <pcap> --filter '<expr>'
   ```
7. Extract files when needed:
   ```bash
   gowireshark extract --file <pcap> --out extracted-files/
   gowireshark export-object list --file <pcap> --protocol http
   ```

## Output Discipline

- Do not dump all frames from an unknown or large capture.
- Prefer `frames page`, `frames fields`, `streams list`, `expert list`, `slice pcap`, and `evidence bundle`.
- JSON is emitted on stdout; diagnostics belong on stderr.
- Use real Wireshark field names such as `frame.number`, `ip.src`, `ip.dst`, and `frame.protocols`.

## Validation

Run before handing off CLI changes:

```bash
go test ./...
```

Do not commit a `replace github.com/randolphcyg/gowireshark => ../gowireshark` directive in `go.mod`. Use a parent `go.work` file for local multi-repo development; release builds use the tagged SDK dependency and build scripts may inject temporary local replaces internally.
