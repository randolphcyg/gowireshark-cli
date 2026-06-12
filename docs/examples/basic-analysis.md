# Basic analysis flow

1. Explore metadata and field availability:
   ```
   epan metadata fields
   epan filter suggest --prefix 'tcp.'
   ```

2. Gauge capture scale:
   ```
   epan frames count --file capture.pcap
   ```

3. Discover streams and traffic structure:
   ```
   epan streams list --file capture.pcap
   ```

4. For each `streamId >= 0`, follow it:
   ```
   epan follow --file capture.pcap --protocol tcp --filter 'tcp.stream eq 0'
   ```

5. Check expert analysis for anomalies:
   ```
   epan expert list --file capture.pcap
   ```

6. Narrow with validated filters before deep analysis:
   ```
   epan filter validate-detailed --expr 'tcp.port == 443'
   epan frames page --file capture.pcap --page 1 --size 20 --filter 'tcp.port == 443'
   ```

7. Produce evidence artifacts when needed:
   ```
   epan slice pcap --file capture.pcap --filter 'tcp.port == 80' --out http.pcap
   epan evidence bundle --file capture.pcap --filter 'tcp.port == 80'
   ```

8. Extract objects when the task needs files:
   ```
   epan export-object list --file capture.pcap --protocol http
   epan export-object write --file capture.pcap --protocol http --packet-num 42 --out extracted.dat
   ```