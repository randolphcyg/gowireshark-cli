# epan

CLI and MCP server for network packet forensics, powered by libwireshark. All commands emit JSON on stdout and diagnostics on stderr.

## Quick Start

```bash
# Build the current platform
./build.sh

# Verify
./dist/epan-<target>/bin/epan-env version
./dist/epan-<target>/bin/epan-env frames count --file /path/to/capture.pcap
```

## CLI Reference

### System

```bash
epan version
```

### Filter

```bash
epan filter validate --expr 'tcp.port == 80'
epan filter validate-detailed --expr 'tcp.stream'
epan filter suggest --prefix 'tcp.'
```

### Metadata

```bash
epan metadata protocols
epan metadata fields
epan metadata field --name tcp.stream
```

### Frames

```bash
epan frames count --file capture.pcap --filter 'tcp'
epan frames page --file capture.pcap --page 1 --size 20 --filter 'http'
epan frames get --file capture.pcap --index 5
epan frames batch --file capture.pcap --indices 1,5,10
epan frames hex --file capture.pcap --index 5
epan frames fields --file capture.pcap --fields ip.src,ip.dst,tcp.port
epan frames write --file capture.pcap --fields frame.number,ip.src,ip.dst,frame.protocols --out frames.jsonl
```

### Streams & Traffic

```bash
epan streams list --file capture.pcap --filter 'tcp'
epan traffic conversations list --file capture.pcap --filter 'dns'
epan traffic timeline summary --file capture.pcap
epan traffic files list --file capture.pcap
```

### Expert, Follow & Evidence

```bash
epan expert list --file capture.pcap --filter 'tcp'
epan follow --file capture.pcap --protocol tcp --filter 'tcp.stream eq 3'
epan follow --file capture.pcap --protocol udp --filter 'udp.stream eq 1'
epan slice pcap --file capture.pcap --filter 'tcp.port == 443' --out tls.pcap
epan slice pcap --file capture.pcap --indices 1,5,9 --out selected.pcap
epan evidence bundle --file capture.pcap --filter 'tcp.port == 80'
```

### Tap, SRT & Export Objects

```bash
epan tap conversations --file capture.pcap --type tcp --filter 'tcp'
epan tap endpoints --file capture.pcap --type ip
epan srt list --file capture.pcap --protocol smb
epan srt list --file capture.pcap --protocol dns
epan export-object list --file capture.pcap --protocol http
epan export-object write --file capture.pcap --protocol http --packet-num 42 --out extracted.dat
```

### Stats & Extraction

```bash
epan stats --file capture.pcap --filter 'tcp'
epan extract --file capture.pcap --out extracted-files/
```

### Common Flags

```
--filter <expr>          Wireshark display filter
--compact                compact JSON output
--raw-json               include raw protocol fields in output
--ignore-errors          skip frames with parse errors
```

## MCP Server

The MCP server exposes 11 composite tools optimized for LLM agents. Start it via the wrapper:

```bash
./bin/epan-mcp-env
```

### MCP Tools

| Tool | Description |
|------|-------------|
| `triage_pcap` | Frame count, streams, expert findings, stats, conversations |
| `search_frames` | Search frames with filter, pagination, field extraction, or batch indices |
| `get_frame` | Single frame with optional hex dump and field selection |
| `inspect_stream` | Follow and reconstruct TCP/UDP stream |
| `validate_filter` | Validate display filter (set `detailed=true` for field-level feedback) |
| `suggest_filter` | Suggest field names by prefix |
| `get_field_info` | Metadata for a display filter field |
| `slice_pcap` | Slice PCAP by filter or frame indices |
| `build_evidence` | Evidence bundle: conversations, endpoints, expert infos, protocol hierarchy |
| `export_objects` | List or extract exportable objects (HTTP, SMB, etc.) with `action=list\|extract` |
| `verify_zeek_alert` | Verify Zeek alert against packet evidence |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `EPAN_PCAP_DIR` | *(none)* | Base directory for PCAP files; relative paths resolve here |
| `EPAN_OUTPUT_DIR` | system temp dir | Base directory for output files |
| `EPAN_TIMEOUT` | `120s` | Per-command timeout |
| `EPAN_MAX_OUTPUT_BYTES` | `2097152` (2 MB) | Max stdout bytes before truncation |
| `EPAN_BIN` | `epan` | Path to the CLI binary |
| `MCP_CALL_LOG_PATH` | *(none)* | If set, logs all MCP calls as JSONL |

### MCP Configuration

```json
{
  "mcpServers": {
    "epan": {
      "command": "/path/to/epan-<target>/bin/epan-mcp-env",
      "args": [],
      "env": {
        "EPAN_PCAP_DIR": "/path/to/pcaps",
        "EPAN_OUTPUT_DIR": "/tmp/epan-output"
      }
    }
  }
}
```

For Windows, use the `.cmd` wrapper:

```json
{
  "mcpServers": {
    "epan": {
      "command": "C:\\tools\\epan-windows-amd64\\bin\\epan-mcp-env.cmd",
      "args": [],
      "env": {
        "EPAN_PCAP_DIR": "C:\\tools\\epan-windows-amd64\\pcaps",
        "EPAN_OUTPUT_DIR": "C:\\tools\\epan-windows-amd64\\output"
      }
    }
  }
}
```

The `.cmd` wrapper self-contains `PATH`, `WIRESHARK_LIB_DIR`, and `WIRESHARK_DATA_DIR`. Do not duplicate these in `env`.

### MCP Resources

The server exposes these resources for exploration:

| URI | Description |
|-----|-------------|
| `epan://pcaps` | Lists PCAP files in `EPAN_PCAP_DIR` |
| `epan://outputs` | Lists files in `EPAN_OUTPUT_DIR` |
| `epan://pcap/{name}/summary` | Lightweight summary for a named PCAP |
| `epan://docs/protocols` | Supported protocol list |

## Agent Integration

### Trae

**CLI mode** — point Trae at the wrapper:

```bash
/path/to/epan-<target>/bin/epan-env frames count --file /path/to/capture.pcap
```

Copy `.trae/rules/project_rules.md` into each project for tool-use policy.

**MCP mode** — copy `.trae/mcp.json.template` to `.trae/mcp.json` and update paths. Do not commit real local `.trae/mcp.json` files.

### Codex

```bash
cp /path/to/epan-<target>/.codex/AGENTS.md ./AGENTS.md
/path/to/epan-<target>/bin/epan-env frames count --file /path/to/capture.pcap
```

For MCP, use `.codex/config.toml.template` and point it to `bin/epan-mcp-env`.

### Claude Code

```bash
cp /path/to/epan-<target>/CLAUDE.md ./CLAUDE.md
cp /path/to/epan-<target>/.mcp.json.template ./.mcp.json
# edit absolute paths in .mcp.json
```

### Generic MCP Clients

Use `agents/mcp.json.template` or `.mcp.json.template`, replacing absolute paths. Use `agents/pcap-analysis-rules.md` as the common tool-use policy.

## Build

`build.sh` produces self-contained packages with the CLI, MCP server, Wireshark runtime libraries, data files, wrapper scripts, and agent templates.

| Target | Host | Output |
|--------|------|--------|
| `darwin-arm64` | macOS Apple Silicon + SDK dev env | `.tar.gz` |
| `linux-amd64` | Docker (Ubuntu 24.04 base) | `.tar.gz` |
| `linux-arm64` | Docker (Ubuntu 24.04 base) | `.tar.gz` |
| `windows-amd64` | Windows + MSYS2 + SDK dev env | `.zip` |

```bash
./build.sh                                  # current host target
./build.sh --target darwin-arm64
./build.sh --target linux-amd64
./build.sh --target linux-arm64
./build.sh --target windows-amd64
./build.sh --all
./build.sh --version 0.1.0 --target linux-amd64
./build.sh --target darwin-arm64 --no-package
```

### macOS

Requires the epan SDK dev environment. Do not vendor Wireshark source into this repo.

```bash
cd ../epan
./init_mac_dev.sh
source ./dev_env.sh

cd ../epan
./build.sh --version 0.1.0 --target darwin-arm64
```

For local development across repos, use a `go.work` file:

```bash
cd /Users/randolph/go
go work init ./gowireshark ./epan
```

### Linux

Linux packages are built via Docker. The base image is Ubuntu 24.04.

```bash
./build.sh --version 0.1.0 --target linux-amd64
./build.sh --version 0.1.0 --target linux-arm64
```

To use a regional apt mirror:

```bash
./build.sh --version 0.1.0 --target linux-amd64 --apt-mirror http://mirrors.ustc.edu.cn/ubuntu
```

### Windows

Windows packages must be built on Windows (no cross-compilation for CGO).

**Prerequisites:**
- Windows 10/11 64-bit
- MSYS2 installed at `C:\msys64` (from https://www.msys2.org/)
- Go 1.21+

**Step 1 — Install MSYS2 dependencies (first time only):**

```powershell
# Run as Administrator in PowerShell
C:\msys64\usr\bin\bash.exe --login -c "pacman -S --needed --noconfirm mingw-w64-ucrt-x86_64-toolchain mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-ninja mingw-w64-ucrt-x86_64-pkgconf mingw-w64-ucrt-x86_64-glib2 zip"
```

**Step 2 — Initialize SDK dev environment:**

```powershell
cd <epan-sdk-path>
.\init_win_dev.ps1
```

This installs MSYS2 packages, downloads and compiles Wireshark (~100 MB+), generates `cgo_windows.go`, and creates `dev_env.ps1` / `dev_env.sh`. Expect 30–60 minutes depending on network and CPU.

**Step 3 — Build in MSYS2 MinGW x64 terminal:**

```bash
cd <epan-sdk-path>
source ./dev_env.sh
cd <epan-path>
./build.sh --version 0.1.0 --target windows-amd64
```

**Step 4 — Verify:**

```bash
# In MSYS2 bash
cd <epan-path>/dist/epan-windows-amd64
./bin/epan.exe version

# In cmd or PowerShell (simulates agent runtime)
<epan-path>\dist\epan-windows-amd64\bin\epan-env.cmd version
```

Expected output: `{"version": "4.6.6"}`. If you get `exit code -1073741515`, MSYS2 runtime DLLs are missing from `lib/` — rebuild with the latest `build.sh`.

**Troubleshooting:**

| Error | Solution |
|-------|----------|
| `zip not found` | Run `pacman -S zip` in MSYS2, or re-run `init_win_dev.ps1` |
| `WIRESHARK_LIB_DIR not set` | Run `source ./dev_env.sh` in MSYS2 bash |
| `DLL load failed / exit code -1073741515` | Missing transitive DLLs (glib/gio/gmodule). Rebuild with latest `build.sh` |
| `command failed: ` (MCP, no details) | MCP server started but CLI command failed — likely DLL issue. Run `epan-env.cmd version` to verify |
| `Permission denied` | Ensure correct file permissions |

## Package Layout

```text
epan-<target>/
  bin/
    epan[.exe]
    epan-mcp[.exe]
    epan-env[.cmd]
    epan-mcp-env[.cmd]
  lib/
  share/wireshark/
  .trae/
    rules/project_rules.md
    mcp.json.template
  .codex/
    AGENTS.md
    config.toml.template
  .claude/
    settings.json.template
  agents/
    pcap-analysis-rules.md
    mcp.json.template
  .mcp.json.template
  CLAUDE.md
  README.md
  PACKAGE_INFO
```

Always use wrapper scripts (`epan-env` / `epan-mcp-env`) on target machines. They set `DYLD_LIBRARY_PATH` / `LD_LIBRARY_PATH`, `WIRESHARK_LIB_DIR`, `WIRESHARK_DATA_DIR`, `WIRESHARK_CONF_DIR`, `BIN`, `PCAP_DIR`, and `OUTPUT_DIR`. Do not call raw `bin/epan` directly on a relocated machine.

## Validation Checklist

Run before publishing:

```bash
bash -n build.sh
go test ./...
! grep -q '^replace github.com/randolphcyg/gowireshark' go.mod
./dist/epan-<target>/bin/epan-env version
./dist/epan-<target>/bin/epan-env frames count --file /path/to/capture.pcap
```

For Linux archives, run the last two commands on the same OS/architecture as the target host.