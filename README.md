# gowireshark-cli

CLI frontend and MCP server for `gowireshark`. All commands emit JSON on stdout and diagnostics on stderr.

## Build Matrix

`build.sh` builds agent-ready packages. A package contains the CLI, MCP server, Wireshark runtime libraries, Wireshark data files, wrapper scripts, and templates for Trae, Codex, Claude Code, and generic MCP-capable agents.

| Target | Host requirement | Output |
|---|---|---|
| `darwin-arm64` | macOS Apple Silicon + initialized `../gowireshark` SDK dev env | `.tar.gz` |
| `linux-amd64` | Docker; produces Ubuntu/Linux x86_64 package | `.tar.gz` |
| `linux-arm64` | Docker; produces Ubuntu/Linux ARM64 package | `.tar.gz` |
| `windows-amd64` | Windows + MSYS2 + initialized Windows SDK dev env | `.zip` |

Linux packages are built from the repo `Dockerfile` base image. The current base is Ubuntu 24.04, so treat Linux archives as Ubuntu 24.04-compatible runtime packages. If you need Ubuntu 22.04 compatibility, build a dedicated Ubuntu 22.04 package instead of reusing a 24.04 archive on older hosts.

Common commands:

```bash
./build.sh                                  # current host target
./build.sh --target darwin-arm64
./build.sh --target linux-amd64
./build.sh --target linux-arm64
./build.sh --target windows-amd64
./build.sh --all
./build.sh --version 0.1.0 --target linux-amd64
./build.sh --target darwin-arm64 --no-package
./build.sh --target linux-arm64 --apt-mirror http://repo.huaweicloud.com/ubuntu-ports
```

`--all` builds what the current host can produce safely:

- macOS Apple Silicon: `darwin-arm64`, `linux-amd64`, `linux-arm64`; Windows is skipped by design.
- Linux: current Linux architecture.
- Windows/MSYS2: `windows-amd64`.

### macOS Apple Silicon

Native macOS builds reuse the `gowireshark` SDK dev environment. Do not vendor Wireshark source into this repo.

```bash
cd ../gowireshark
./init_mac_dev.sh
source ./dev_env.sh

cd ../gowireshark-cli
./build.sh --version 0.1.0 --target darwin-arm64
```

`gowireshark-cli/go.mod` should keep the released SDK dependency only. The macOS build script injects a temporary local SDK `replace` through an internal modfile and does not mutate `go.mod`.

For local development across both repos, use a workspace outside the repo instead of committing `replace`:

```bash
cd /Users/randolph/go
go work init ./gowireshark ./gowireshark-cli
# if go.work already exists:
go work use ./gowireshark ./gowireshark-cli
```

Validate the package:

```bash
tar -xzf dist/gowireshark-cli-darwin-arm64.tar.gz -C /tmp
/tmp/gowireshark-cli-darwin-arm64/bin/gowireshark-env version
/tmp/gowireshark-cli-darwin-arm64/bin/gowireshark-env frames count --file /path/to/capture.pcap
```

### Ubuntu / Linux

Linux packages are built with Docker and include the runtime libraries needed by agents on target machines.

```bash
./build.sh --version 0.1.0 --target linux-amd64
./build.sh --version 0.1.0 --target linux-arm64
```

Use the target matching the agent host CPU:

| Agent host | Build command |
|---|---|
| Ubuntu/Linux x86_64 / AMD64 | `./build.sh --version 0.1.0 --target linux-amd64` |
| Ubuntu/Linux ARM64 / AArch64 | `./build.sh --version 0.1.0 --target linux-arm64` |

For build-only directory validation without creating a tarball:

```bash
./build.sh --version 0.1.0 --target linux-amd64 --no-package
```

If a regional mirror fails, pass an explicit mirror:

```bash
./build.sh --version 0.1.0 --target linux-amd64 --apt-mirror http://mirrors.ustc.edu.cn/ubuntu
./build.sh --version 0.1.0 --target linux-arm64 --apt-mirror http://mirrors.ustc.edu.cn/ubuntu-ports
```

Use on the target Ubuntu/Linux host:

```bash
tar -xzf gowireshark-cli-linux-amd64.tar.gz
cd gowireshark-cli-linux-amd64
./bin/gowireshark-env version
./bin/gowireshark-env frames count --file /path/to/capture.pcap
./bin/gowireshark-mcp-env
```

### Windows x86_64

Windows packages must be built on Windows. macOS/Linux hosts do not cross-compile Windows CGO packages.

```powershell
cd C:\path\to\gowireshark
.\init_win_dev.ps1
. .\dev_env.ps1

cd C:\path\to\gowireshark-cli
# Run from Git Bash/MSYS2 bash:
./build.sh --version 0.1.0 --target windows-amd64
```

Use on the target Windows host:

```cmd
powershell -Command "Expand-Archive dist\gowireshark-cli-windows-amd64.zip -DestinationPath C:\tools"
C:\tools\gowireshark-cli-windows-amd64\bin\gowireshark-env.cmd version
C:\tools\gowireshark-cli-windows-amd64\bin\gowireshark-mcp-env.cmd
```

Windows packaging copies DLLs from `WIRESHARK_LIB_DIR`; always run the SDK `init_win_dev.ps1` / `dev_env.ps1` first so the package contains the required runtime files.

## Package Layout

```text
gowireshark-cli-<target>/
  bin/
    gowireshark[.exe]
    gowireshark-mcp[.exe]
    gowireshark-env[.cmd]
    gowireshark-mcp-env[.cmd]
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

Always use wrapper scripts on target machines. They set `DYLD_LIBRARY_PATH` or `LD_LIBRARY_PATH`, `WIRESHARK_LIB_DIR`, `WIRESHARK_DATA_DIR`, `WIRESHARK_CONF_DIR`, `GOWIRESHARK_BIN`, `GOWIRESHARK_PCAP_DIR`, and `GOWIRESHARK_OUTPUT_DIR`.

Do not call raw `bin/gowireshark` directly on a relocated machine unless the same dynamic library paths already exist. Use `bin/gowireshark-env` / `bin/gowireshark-env.cmd`.

## Trae / Agent Usage

### CLI mode

Point Trae at the wrapper in the extracted package, or put it on `PATH`:

```bash
/path/to/gowireshark-cli-<target>/bin/gowireshark-env frames count --file /path/to/capture.pcap
/path/to/gowireshark-cli-<target>/bin/gowireshark-env frames page --file /path/to/capture.pcap --page 1 --size 10
```

For stable use, copy `.trae/rules/project_rules.md` into each project where Trae should use the tool.

### MCP mode

Copy `.trae/mcp.json.template` to `.trae/mcp.json` and point it at the extracted MCP wrapper:

```json
{
  "mcpServers": {
    "gowireshark": {
      "command": "/path/to/gowireshark-cli-<target>/bin/gowireshark-mcp-env",
      "args": [],
      "env": {
        "GOWIRESHARK_PCAP_DIR": "/path/to/pcaps",
        "GOWIRESHARK_OUTPUT_DIR": "/tmp/gowireshark-output"
      }
    }
  }
}
```

Do not commit real local `.trae/mcp.json` files.

### Codex

Codex should use project-level instructions and the package wrappers:

```bash
cp /path/to/gowireshark-cli-<target>/.codex/AGENTS.md ./AGENTS.md
/path/to/gowireshark-cli-<target>/bin/gowireshark-env frames count --file /path/to/capture.pcap
```

If your Codex runtime supports MCP config, use `.codex/config.toml.template` as a local template and point it to:

```bash
/path/to/gowireshark-cli-<target>/bin/gowireshark-mcp-env
```

Do not commit personal Codex MCP config unless the paths are intentionally portable for the team.

### Claude Code

Claude Code can use the shipped `CLAUDE.md` and project-scoped MCP template:

```bash
cp /path/to/gowireshark-cli-<target>/CLAUDE.md ./CLAUDE.md
cp /path/to/gowireshark-cli-<target>/.mcp.json.template ./.mcp.json
# edit absolute paths in .mcp.json
```

The `.claude/settings.json.template` file is optional. Copy it only when the target project wants shared Claude Code settings.

### Generic MCP clients

Use `agents/mcp.json.template` or `.mcp.json.template`, replacing absolute paths:

```bash
/path/to/gowireshark-cli-<target>/bin/gowireshark-mcp-env
```

Use `agents/pcap-analysis-rules.md` as the common tool-use policy for any agent.

For Windows, use the `.cmd` wrapper in the same template:

```json
{
  "mcpServers": {
    "gowireshark": {
      "command": "C:\\tools\\gowireshark-cli-windows-amd64\\bin\\gowireshark-mcp-env.cmd",
      "args": [],
      "env": {
        "GOWIRESHARK_PCAP_DIR": "C:\\pcaps",
        "GOWIRESHARK_OUTPUT_DIR": "C:\\tmp\\gowireshark-output"
      }
    }
  }
}
```

## Common Flags

```
--filter <expr>          display filter
--decode-as <rules>      decode-as rules, e.g. tcp.port:8080:http
--profile <name>         Wireshark profile
--pref <name:val,...>    Wireshark preferences
--name-resolution <opts> mac,network,transport,external
--parse-mode <mode>      raw | base | selected
--layers <names>         selected layers, e.g. tcp,ip
--compact                compact JSON output
--raw-json               include raw protocol fields in output
--ignore-errors          skip frames with parse errors
```

## Commands

### System

```bash
gowireshark version
```

When using a packaged release, replace `gowireshark` with the wrapper:

```bash
./bin/gowireshark-env version
```

### Filter

```bash
gowireshark filter validate --expr 'tcp.port == 80'
gowireshark filter validate-detailed --expr 'tcp.stream'
gowireshark filter suggest --prefix 'tcp.'
```

### Metadata

```bash
gowireshark metadata protocols
gowireshark metadata fields
gowireshark metadata field --name tcp.stream
```

### Frames

```bash
gowireshark frames count --file capture.pcap --filter 'tcp'
gowireshark frames page --file capture.pcap --page 1 --size 20 --filter 'http'
gowireshark frames get --file capture.pcap --index 5
gowireshark frames batch --file capture.pcap --indices 1,5,10
gowireshark frames hex --file capture.pcap --index 5
gowireshark frames write --file capture.pcap --fields frame.number,ip.src,ip.dst,frame.protocols --out frames.jsonl
gowireshark frames fields --file capture.pcap --fields ip.src,ip.dst,tcp.port
```

### Streams and Traffic

```bash
gowireshark streams list --file capture.pcap --filter 'tcp'
gowireshark traffic conversations list --file capture.pcap --filter 'dns'
gowireshark traffic timeline summary --file capture.pcap
gowireshark traffic files list --file capture.pcap
```

### Expert, Follow, and Evidence

```bash
gowireshark expert list --file capture.pcap --filter 'tcp'
gowireshark follow --file capture.pcap --protocol tcp --filter 'tcp.stream eq 3'
gowireshark follow --file capture.pcap --protocol udp --filter 'udp.stream eq 1'
gowireshark slice pcap --file capture.pcap --filter 'tcp.port == 443' --out tls.pcap
gowireshark slice pcap --file capture.pcap --indices 1,5,9 --out selected.pcap
gowireshark evidence bundle --file capture.pcap --filter 'tcp.port == 80'
```

### Tap, SRT, and Export Objects

```bash
gowireshark tap conversations --file capture.pcap --type tcp --filter 'tcp'
gowireshark tap endpoints --file capture.pcap --type ip
gowireshark srt list --file capture.pcap --protocol smb
gowireshark srt list --file capture.pcap --protocol dns
gowireshark export-object list --file capture.pcap --protocol http
gowireshark export-object write --file capture.pcap --protocol http --packet-num 42 --out extracted.dat
```

### Stats and Extraction

```bash
gowireshark stats --file capture.pcap --filter 'tcp'
gowireshark extract --file capture.pcap --out extracted-files/
```

## Final Validation Checklist

Run these before publishing an archive:

```bash
bash -n build.sh
go test ./...
docker build --check -f Dockerfile .
! grep -q '^replace github.com/randolphcyg/gowireshark' go.mod
./dist/gowireshark-cli-<target>/bin/gowireshark-env version
./dist/gowireshark-cli-<target>/bin/gowireshark-env frames count --file /path/to/capture.pcap
```

For Linux archives, run the last two commands on the same OS/architecture family as the target agent host.
