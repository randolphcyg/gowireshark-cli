# CLI reference

## System & Discovery

```bash
epan version
epan filter validate --expr 'tcp.port == 80'
epan filter validate-detailed --expr 'tcp.stream'
epan filter suggest --prefix 'tcp.'
epan metadata protocols
epan metadata fields
epan metadata field --name tcp.stream
```

## Frame Inspection

```bash
epan frames count --file capture.pcap --filter 'tcp'
epan frames page --file capture.pcap --page 1 --size 20 --filter 'http'
epan frames get --file capture.pcap --index 5
epan frames batch --file capture.pcap --indices 1,5,10
epan frames hex --file capture.pcap --index 5
epan frames write --file capture.pcap --fields frame.number,ip.src,ip.dst,frame.protocols --out frames.jsonl
epan frames fields --file capture.pcap --fields ip.src,ip.dst,tcp.port
```

## Traffic Analysis

```bash
epan streams list --file capture.pcap --filter 'tcp'
epan traffic conversations list --file capture.pcap --filter 'dns'
epan traffic timeline summary --file capture.pcap
epan traffic files list --file capture.pcap
```

## Stream Reassembly

```bash
epan follow --file capture.pcap --protocol tcp --filter 'tcp.stream eq 3'
epan follow --file capture.pcap --protocol udp --filter 'udp.stream eq 1'
```

## Expert & Evidence

```bash
epan expert list --file capture.pcap --filter 'tcp'
epan slice pcap --file capture.pcap --filter 'tcp.port == 443' --out tls.pcap
epan slice pcap --file capture.pcap --indices 1,5,9 --out selected.pcap
epan evidence bundle --file capture.pcap --filter 'tcp.port == 80'
```

## Tap & SRT

```bash
epan tap conversations --file capture.pcap --type tcp --filter 'tcp'
epan tap endpoints --file capture.pcap --type ip
epan srt list --file capture.pcap --protocol smb
epan srt list --file capture.pcap --protocol dns
```

## Export Objects

```bash
epan export-object list --file capture.pcap --protocol http
epan export-object write --file capture.pcap --protocol http --packet-num 42 --out extracted.dat
```

## Stats & Extraction

```bash
epan stats --file capture.pcap --filter 'tcp'
epan extract --file capture.pcap --out extracted-files/
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