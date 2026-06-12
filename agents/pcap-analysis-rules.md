# epan Agent PCAP Analysis Rules

Use `epan` as a bounded forensic lens. Prefer small, reproducible queries over broad packet dumps.

## Default workflow

1. Gauge capture size first:
   ```bash
   epan frames count --file <pcap>
   epan stats --file <pcap>
   ```
2. Map traffic:
   ```bash
   epan streams list --file <pcap>
   epan traffic conversations list --file <pcap>
   ```
3. Check anomalies:
   ```bash
   epan expert list --file <pcap>
   ```
4. Validate filters before use:
   ```bash
   epan filter validate-detailed --expr '<display-filter>'
   ```
5. Follow only mapped streams where `streamId >= 0`:
   ```bash
   epan follow --file <pcap> --protocol tcp --filter 'tcp.stream eq N'
   ```
6. Produce evidence after narrowing scope:
   ```bash
   epan slice pcap --file <pcap> --filter '<display-filter>' --out evidence.pcap
   epan evidence bundle --file <pcap> --filter '<display-filter>'
   ```
7. Extract files when needed:
   ```bash
   epan extract --file <pcap> --out extracted-files/
   epan export-object list --file <pcap> --protocol http
   ```

## Do not

- Do not dump all frame trees from unknown or large captures.
- Do not guess Wireshark display filter syntax; validate it first.
- Do not follow streams without a valid `tcp.stream` or `udp.stream` id.
- Do not write extracted evidence outside the configured output directory.
