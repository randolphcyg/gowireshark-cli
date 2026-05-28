# gowireshark CLI Project Rules

## PCAP Analysis Workflow

When analyzing packet captures, use the CLI as a forensic lens:

1. **Gauge scale first**: `gowireshark frames count --file <pcap>`.
2. **Map traffic**: `gowireshark streams list --file <pcap>`.
3. **Find anomalies**: `gowireshark expert list --file <pcap>`.
4. **Follow selectively**: only follow streams where `streamId >= 0`; use `gowireshark follow --file <pcap> --protocol tcp --filter 'tcp.stream eq N'`.
5. **Validate filters**: run `gowireshark filter validate-detailed --expr '<expr>'` before using a new display filter.
6. **Create evidence**: use `slice pcap` or `evidence bundle` after narrowing the scope.

## Do Not

- Do not dump full frame trees from unknown or large captures.
- Do not run broad `frames page` commands before `frames count`.
- Do not guess Wireshark display filter syntax; validate it first.

## Useful Commands

```bash
gowireshark frames count --file "$PCAP"
gowireshark stats --file "$PCAP"
gowireshark streams list --file "$PCAP"
gowireshark expert list --file "$PCAP"
gowireshark traffic timeline summary --file "$PCAP"
gowireshark filter validate-detailed --expr 'tcp.stream eq 0'
gowireshark slice pcap --file "$PCAP" --filter 'tcp.stream eq 0' --out stream-0.pcap
gowireshark extract --file "$PCAP" --out extracted-files/
```
