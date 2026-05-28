# CLI reference

## System & Discovery

```bash
gowireshark version
gowireshark filter validate --expr 'tcp.port == 80'
gowireshark filter validate-detailed --expr 'tcp.stream'
gowireshark filter suggest --prefix 'tcp.'
gowireshark metadata protocols
gowireshark metadata fields
gowireshark metadata field --name tcp.stream
```

## Frame Inspection

```bash
gowireshark frames count --file capture.pcap --filter 'tcp'
gowireshark frames page --file capture.pcap --page 1 --size 20 --filter 'http'
gowireshark frames get --file capture.pcap --index 5
gowireshark frames batch --file capture.pcap --indices 1,5,10
gowireshark frames hex --file capture.pcap --index 5
gowireshark frames write --file capture.pcap --fields frame.number,ip.src,ip.dst,frame.protocols --out frames.jsonl
gowireshark frames fields --file capture.pcap --fields ip.src,ip.dst,tcp.port
```

## Traffic Analysis

```bash
gowireshark streams list --file capture.pcap --filter 'tcp'
gowireshark traffic conversations list --file capture.pcap --filter 'dns'
gowireshark traffic timeline summary --file capture.pcap
gowireshark traffic files list --file capture.pcap
```

## Stream Reassembly

```bash
gowireshark follow --file capture.pcap --protocol tcp --filter 'tcp.stream eq 3'
gowireshark follow --file capture.pcap --protocol udp --filter 'udp.stream eq 1'
```

## Expert & Evidence

```bash
gowireshark expert list --file capture.pcap --filter 'tcp'
gowireshark slice pcap --file capture.pcap --filter 'tcp.port == 443' --out tls.pcap
gowireshark slice pcap --file capture.pcap --indices 1,5,9 --out selected.pcap
gowireshark evidence bundle --file capture.pcap --filter 'tcp.port == 80'
```

## Tap & SRT

```bash
gowireshark tap conversations --file capture.pcap --type tcp --filter 'tcp'
gowireshark tap endpoints --file capture.pcap --type ip
gowireshark srt list --file capture.pcap --protocol smb
gowireshark srt list --file capture.pcap --protocol dns
```

## Export Objects

```bash
gowireshark export-object list --file capture.pcap --protocol http
gowireshark export-object write --file capture.pcap --protocol http --packet-num 42 --out extracted.dat
```

## Stats & Extraction

```bash
gowireshark stats --file capture.pcap --filter 'tcp'
gowireshark extract --file capture.pcap --out extracted-files/
```

## Common Flags

Most commands support: `--filter`, `--compact`, `--raw-json`

Flags planned for future SDK support: `--decode-as`, `--profile`, `--pref`, `--name-resolution`, `--parse-mode`, `--layers`

## Guidance

- `frames page` is the default inspection command for large pcaps.
- `streams list` reveals followable streams (look for `streamId >= 0` and use the `followFilter` field).
- `follow` expects a Wireshark display filter that narrows the desired stream (e.g. `tcp.stream eq 0`).
- `slice pcap` creates a new pcap from selected frames; verify with `frames count` on the output.
- `evidence bundle` produces comprehensive forensic metadata including conversations, expert infos, and protocol hierarchy.
- `export-object write` extracts HTTP objects to disk; use only when the task needs artifacts, not just metadata.