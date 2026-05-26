# Basic analysis flow

1. Explore metadata and field availability:
   ```
   gowireshark metadata fields
   gowireshark filter suggest --prefix 'tcp.'
   ```

2. Gauge capture scale:
   ```
   gowireshark frames count --file capture.pcap
   ```

3. Discover streams and traffic structure:
   ```
   gowireshark streams list --file capture.pcap
   ```

4. For each `streamId >= 0`, follow it:
   ```
   gowireshark follow --file capture.pcap --protocol tcp --filter 'tcp.stream eq 0'
   ```

5. Check expert analysis for anomalies:
   ```
   gowireshark expert list --file capture.pcap
   ```

6. Narrow with validated filters before deep analysis:
   ```
   gowireshark filter validate-detailed --expr 'tcp.port == 443'
   gowireshark frames page --file capture.pcap --page 1 --size 20 --filter 'tcp.port == 443'
   ```

7. Produce evidence artifacts when needed:
   ```
   gowireshark slice pcap --file capture.pcap --filter 'tcp.port == 80' --out http.pcap
   gowireshark evidence bundle --file capture.pcap --filter 'tcp.port == 80'
   ```

8. Extract objects when the task needs files:
   ```
   gowireshark export-object list --file capture.pcap --protocol http
   gowireshark export-object write --file capture.pcap --protocol http --packet-num 42 --out extracted.dat
   ```