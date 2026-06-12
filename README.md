# epan

CLI frontend and MCP server for `epan`. All commands emit JSON on stdout and diagnostics on stderr.

## Build Matrix

`build.sh` builds agent-ready packages. A package contains the CLI, MCP server, Wireshark runtime libraries, Wireshark data files, wrapper scripts, and templates for Trae, Codex, Claude Code, and generic MCP-capable agents.

| Target | Host requirement | Output |
|---|---|---|
| `darwin-arm64` | macOS Apple Silicon + initialized `../` SDK dev env | `.tar.gz` |
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

Native macOS builds reuse the `epan` SDK dev environment. Do not vendor Wireshark source into this repo.

```bash
cd ../epan
./init_mac_dev.sh
source ./dev_env.sh

cd ../epan
./build.sh --version 0.1.0 --target darwin-arm64
```

`epan/go.mod` should keep the released SDK dependency only. The macOS build script injects a temporary local SDK `replace` through an internal modfile and does not mutate `go.mod`.

For local development across both repos, use a workspace outside the repo instead of committing `replace`:

```bash
cd /Users/randolph/go
go work init ./gowireshark ./epan
# if go.work already exists:
go work use ./gowireshark ./epan
```

Validate the package:

```bash
tar -xzf dist/epan-darwin-arm64.tar.gz -C /tmp
/tmp/epan-darwin-arm64/bin/epan-env version
/tmp/epan-darwin-arm64/bin/epan-env frames count --file /path/to/capture.pcap
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
tar -xzf epan-linux-amd64.tar.gz
cd epan-linux-amd64
./bin/epan-env version
./bin/epan-env frames count --file /path/to/capture.pcap
./bin/epan-mcp-env
```

### Windows x86_64

Windows packages must be built on Windows. macOS/Linux hosts do not cross-compile Windows CGO packages.

**前置条件**：
- Windows 10/11 64位操作系统
- MSYS2 安装在默认路径 `C:\msys64`（从 https://www.msys2.org/ 下载）
- Go 1.21+ 安装并配置好环境变量
- Git for Windows 安装（可选，但建议安装）

**完整编译流程**：

**步骤1：安装 MSYS2 依赖（首次配置）**

```powershell
# 以管理员身份打开 PowerShell
cd C:\msys64\usr\bin
.\bash.exe --login -c "pacman -S --needed --noconfirm mingw-w64-ucrt-x86_64-toolchain mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-ninja mingw-w64-ucrt-x86_64-pkgconf mingw-w64-ucrt-x86_64-glib2 zip"
```

**步骤2：初始化 SDK 开发环境**

```powershell
cd <epan-sdk-path>
.\init_win_dev.ps1
```

> **注意**：此脚本会：
> - 安装所有必要的 MSYS2 包（包括 zip）
> - 下载并编译 Wireshark 源码（约 100MB+）
> - 生成 `cgo_windows.go` 文件
> - 生成 `dev_env.ps1`（PowerShell 环境脚本）
> - 生成 `dev_env.sh`（MSYS2 bash 环境脚本）
> - 整个过程可能需要 30-60 分钟，具体取决于网络和 CPU 性能

**步骤3：在 MSYS2 bash 中构建 CLI**

打开 **MSYS2 MinGW x64** 终端：

```bash
# 进入 epan SDK 目录并加载环境变量
cd <epan-sdk-path>
source ./dev_env.sh

# 切换到 CLI 项目目录
cd <epan-path>

# 执行构建（指定版本号和目标平台）
./build.sh --version 0.1.0 --target windows-amd64
```

**步骤4：验证构建结果**

**CLI 模式验证**：

```bash
# 在 MSYS2 bash 中
cd <epan-path>/dist/epan-windows-amd64
./bin/epan.exe version
./bin/epan.exe frames count --file <epan-sdk-path>/pcaps/test.pcap
```

**MCP 模式验证**（脱离 MSYS2，模拟 Trae 实际调用环境）：

```cmd
:: 打开 Windows cmd 或 PowerShell，直接使用 wrapper 脚本
<epan-path>\dist\epan-windows-amd64\bin\epan-env.cmd version
```

> 如果输出 `{"version": "4.6.6"}`，说明 CLI 依赖库完整。
> 如果报 `exit code -1073741515`，说明 lib/ 目录中缺少 MSYS2 运行时 DLL，需重新构建（`build.sh` 会自动复制所需的全部 DLL）。

**关键注意事项**：

1. **环境变量传递问题**：
   - PowerShell 中设置的环境变量不能直接传递到 MSYS2 bash
   - 必须在 MSYS2 bash 中使用 `source ./dev_env.sh` 重新加载
   - `dev_env.sh` 会自动设置 `WIRESHARK_LIB_DIR`、`WIRESHARK_DATA_DIR` 和正确的 `PATH`

2. **zip 工具**：
   - 构建脚本需要 `zip` 命令来创建归档文件
   - `init_win_dev.ps1` 已自动安装 zip，无需手动安装

3. **路径格式**：
   - MSYS2 bash 使用 Unix 风格路径（如 `/drive/path/to/project`）
   - Windows 路径需要转换（如 `D:\path\to\project` → `/d/path/to/project`）

4. **Go 工作区**：
   - 建议在两个仓库之外创建 `go.work` 文件，避免修改 `go.mod`
   - 示例：
     ```bash
     cd <parent-directory>
     go work init ./gowireshark ./epan
     ```

5. **运行时环境**：
   - 编译好的 CLI 需要 `libwireshark.dll` 和相关依赖
   - 使用 `epan-env.cmd` 或 `epan-env` 脚本启动，它们会自动设置环境变量
   - 不要直接运行 `epan.exe`，否则会缺少依赖

**在 Trae/Codex/Claude Code 中使用**：

**方式1：CLI 模式**

配置 Trae 工具路径指向 wrapper 脚本：

```bash
# 在 Trae 中配置工具路径
/path/to/epan-windows-amd64/bin/epan-env frames count --file /path/to/capture.pcap
```

**方式2：MCP 模式**

配置 `.trae/mcp.json`（将 `<dist-path>` 替换为实际路径）：

```json
{
  "mcpServers": {
    "epan": {
      "command": "<dist-path>\\epan-windows-amd64\\bin\\epan-mcp-env.cmd",
      "args": [],
      "env": {
        "PCAP_DIR": "<dist-path>\\epan-windows-amd64\\pcaps",
        "OUTPUT_DIR": "<dist-path>\\epan-windows-amd64\\output"
      }
    }
  }
}
```

> **重要**：Windows 必须使用 `.cmd` 后缀的文件（`epan-mcp-env.cmd`）。
> 该 wrapper 会自动设置 `PATH`（包含 `lib/` 目录和 `C:\Windows\System32`）、
> `WIRESHARK_LIB_DIR`、`WIRESHARK_DATA_DIR` 等环境变量，无需在 `env` 字段中额外设置。
> 如果 MCP 客户端以空环境启动进程（仅传递 `env` 中的变量），wrapper 仍然能正常工作，
> 因为它内置了系统路径兜底。

MCP 模式启动后，通过 Trae 调用 `epan_get_version` 应返回 `{"version": "4.6.6"}`。

> MCP tool name 从 1.0 起采用面向 Agent 的动词命名，旧名已删除。常用入口：
> `epan_health_check`、`epan_count_frames`、`epan_list_streams`、
> `epan_validate_filter`、`epan_verify_zeek_alert`、
> `epan_create_evidence_bundle`。升级后需要重启 MCP 客户端以刷新 schema。
> 可设置 `MCP_CALL_LOG_PATH=/path/to/mcp-calls.jsonl` 记录 JSONL 调用日志。

**方式3：直接在目标主机使用**

```cmd
powershell -Command "Expand-Archive dist\epan-windows-amd64.zip -DestinationPath C:\tools"
C:\tools\epan-windows-amd64\bin\epan-env.cmd version
C:\tools\epan-windows-amd64\bin\epan-mcp-env.cmd
```

**故障排除**：

| 错误信息 | 解决方案 |
|---|---|
| `zip not found` | 重新运行 `init_win_dev.ps1`，或在 MSYS2 中运行 `pacman -S zip` |
| `WIRESHARK_LIB_DIR not set` | 在 MSYS2 bash 中运行 `source ./dev_env.sh` |
| `DLL load failed / exit code -1073741515` | `libwireshark.dll` 的传递依赖（glib/gio/gmodule 等）缺失。确保使用最新 `build.sh` 重新构建（新版本会自动从 MSYS2 `ucrt64/bin` 复制全部所需 DLL） |
| `command failed: ` (MCP 调用无详细信息) | MCP 服务器启动成功但执行 CLI 命令失败，通常原因同上（DLL 缺失）。在 cmd 中运行 `<dist>\bin\epan-env.cmd version` 验证 |
| `Permission denied` | 确保所有文件有正确的执行权限 |

**自动化脚本**（可选）：

创建 `build_win.sh` 脚本：

```bash
#!/usr/bin/env bash
cd <epan-sdk-path>
source ./dev_env.sh
cd <epan-path>
./build.sh --version 0.1.0 --target windows-amd64
echo "Build completed. Output in dist/"
```

> **提示**：Windows packaging copies DLLs from `WIRESHARK_LIB_DIR`; always run the SDK `init_win_dev.ps1` / `source dev_env.sh` first so the package contains the required runtime files.

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

Always use wrapper scripts on target machines. They set `DYLD_LIBRARY_PATH` or `LD_LIBRARY_PATH`, `WIRESHARK_LIB_DIR`, `WIRESHARK_DATA_DIR`, `WIRESHARK_CONF_DIR`, `BIN`, `PCAP_DIR`, and `OUTPUT_DIR`.

Do not call raw `bin/epan` directly on a relocated machine unless the same dynamic library paths already exist. Use `bin/epan-env` / `bin/epan-env.cmd`.

## Trae / Agent Usage

### CLI mode

Point Trae at the wrapper in the extracted package, or put it on `PATH`:

```bash
/path/to/epan-<target>/bin/epan-env frames count --file /path/to/capture.pcap
/path/to/epan-<target>/bin/epan-env frames page --file /path/to/capture.pcap --page 1 --size 10
```

For stable use, copy `.trae/rules/project_rules.md` into each project where Trae should use the tool.

### MCP mode

Copy `.trae/mcp.json.template` to `.trae/mcp.json` and point it at the extracted MCP wrapper:

```json
{
  "mcpServers": {
    "epan": {
      "command": "/path/to/epan-<target>/bin/epan-mcp-env",
      "args": [],
      "env": {
        "PCAP_DIR": "/path/to/pcaps",
        "OUTPUT_DIR": "/tmp/epan-output"
      }
    }
  }
}
```

Do not commit real local `.trae/mcp.json` files.

### Codex

Codex should use project-level instructions and the package wrappers:

```bash
cp /path/to/epan-<target>/.codex/AGENTS.md ./AGENTS.md
/path/to/epan-<target>/bin/epan-env frames count --file /path/to/capture.pcap
```

If your Codex runtime supports MCP config, use `.codex/config.toml.template` as a local template and point it to:

```bash
/path/to/epan-<target>/bin/epan-mcp-env
```

Do not commit personal Codex MCP config unless the paths are intentionally portable for the team.

### Claude Code

Claude Code can use the shipped `CLAUDE.md` and project-scoped MCP template:

```bash
cp /path/to/epan-<target>/CLAUDE.md ./CLAUDE.md
cp /path/to/epan-<target>/.mcp.json.template ./.mcp.json
# edit absolute paths in .mcp.json
```

The `.claude/settings.json.template` file is optional. Copy it only when the target project wants shared Claude Code settings.

### Generic MCP clients

Use `agents/mcp.json.template` or `.mcp.json.template`, replacing absolute paths:

```bash
/path/to/epan-<target>/bin/epan-mcp-env
```

Use `agents/pcap-analysis-rules.md` as the common tool-use policy for any agent.

For Windows, use the `.cmd` wrapper in the same template (note the `.cmd` extension is required):

```json
{
  "mcpServers": {
    "epan": {
      "command": "C:\\tools\\epan-windows-amd64\\bin\\epan-mcp-env.cmd",
      "args": [],
      "env": {
        "PCAP_DIR": "C:\\tools\\epan-windows-amd64\\pcaps",
        "OUTPUT_DIR": "C:\\tools\\epan-windows-amd64\\output"
      }
    }
  }
}
```

> The `.cmd` wrapper self-contains `PATH` (includes `lib/` and `C:\\Windows\\System32`),
> `WIRESHARK_LIB_DIR`, and `WIRESHARK_DATA_DIR`. Do not duplicate these in `env`.

## Common Flags

```
--filter <expr>          display filter
--compact                compact JSON output
--raw-json               include raw protocol fields in output
--ignore-errors          skip frames with parse errors
```

The following flags are planned for future SDK support and are not yet available in the CLI:
`--decode-as`, `--profile`, `--pref`, `--name-resolution`, `--parse-mode`, `--layers`

## Commands

### System

```bash
epan version
```

When using a packaged release, replace `epan` with the wrapper:

```bash
./bin/epan-env version
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
epan frames write --file capture.pcap --fields frame.number,ip.src,ip.dst,frame.protocols --out frames.jsonl
epan frames fields --file capture.pcap --fields ip.src,ip.dst,tcp.port
```

### Streams and Traffic

```bash
epan streams list --file capture.pcap --filter 'tcp'
epan traffic conversations list --file capture.pcap --filter 'dns'
epan traffic timeline summary --file capture.pcap
epan traffic files list --file capture.pcap
```

### Expert, Follow, and Evidence

```bash
epan expert list --file capture.pcap --filter 'tcp'
epan follow --file capture.pcap --protocol tcp --filter 'tcp.stream eq 3'
epan follow --file capture.pcap --protocol udp --filter 'udp.stream eq 1'
epan slice pcap --file capture.pcap --filter 'tcp.port == 443' --out tls.pcap
epan slice pcap --file capture.pcap --indices 1,5,9 --out selected.pcap
epan evidence bundle --file capture.pcap --filter 'tcp.port == 80'
```

### Tap, SRT, and Export Objects

```bash
epan tap conversations --file capture.pcap --type tcp --filter 'tcp'
epan tap endpoints --file capture.pcap --type ip
epan srt list --file capture.pcap --protocol smb
epan srt list --file capture.pcap --protocol dns
epan export-object list --file capture.pcap --protocol http
epan export-object write --file capture.pcap --protocol http --packet-num 42 --out extracted.dat
```

### Stats and Extraction

```bash
epan stats --file capture.pcap --filter 'tcp'
epan extract --file capture.pcap --out extracted-files/
```

## Final Validation Checklist

Run these before publishing an archive:

```bash
bash -n build.sh
go test ./...
docker build --check -f Dockerfile .
! grep -q '^replace github.com/randolphcyg/gowireshark' go.mod
./dist/epan-<target>/bin/epan-env version
./dist/epan-<target>/bin/epan-env frames count --file /path/to/capture.pcap
```

For Linux archives, run the last two commands on the same OS/architecture family as the target agent host.
