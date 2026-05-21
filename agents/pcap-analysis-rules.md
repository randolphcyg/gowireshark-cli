# gowireshark Agent PCAP Analysis Rules

Use `gowireshark` as a bounded forensic lens. Prefer small, reproducible queries over broad packet dumps.

## Default workflow

1. Gauge capture size first:
   ```bash
   gowireshark frames count --file <pcap>
   ```
2. Map traffic:
   ```bash
   gowireshark streams list --file <pcap>
   gowireshark traffic conversations list --file <pcap>
   ```
3. Check anomalies:
   ```bash
   gowireshark expert list --file <pcap>
   ```
4. Validate filters before use:
   ```bash
   gowireshark filter validate-detailed --expr '<display-filter>'
   ```
5. Follow only mapped streams where `streamId >= 0`:
   ```bash
   gowireshark follow --file <pcap> --protocol tcp --filter 'tcp.stream eq N'
   ```
6. Produce evidence after narrowing scope:
   ```bash
   gowireshark slice pcap --file <pcap> --filter '<display-filter>' --out evidence.pcap
   gowireshark evidence bundle --file <pcap> --filter '<display-filter>'
   ```

## Do not

- Do not dump all frame trees from unknown or large captures.
- Do not guess Wireshark display filter syntax; validate it first.
- Do not follow streams without a valid `tcp.stream` or `udp.stream` id.
- Do not write extracted evidence outside the configured output directory.
