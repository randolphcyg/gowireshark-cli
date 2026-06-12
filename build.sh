#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIST_DIR="$SCRIPT_DIR/dist"
SDK_DIR="${GOWIRESHARK_SDK_DIR:-$SCRIPT_DIR/../gowireshark}"
SDK_DIR="$(cd "$SDK_DIR" 2>/dev/null && pwd || echo "$SDK_DIR")"

VERSION="dev"
TARGETS=()
BUILD_ALL=false
NO_PACKAGE=false
APT_MIRROR="${APT_MIRROR:-}"

usage() {
  cat <<USAGE
Usage: $0 [--version VERSION] [--target TARGET] [--all] [--no-package] [--apt-mirror URL]

Targets:
  darwin-arm64      macOS Apple Silicon native package
  linux-amd64       Ubuntu/Linux x86_64 package via Docker
  linux-arm64       Ubuntu/Linux ARM64 package via Docker
  windows-amd64     Windows x86_64 package; requires Windows + MSYS2 dev env

Examples:
  $0
  $0 --target darwin-arm64
  $0 --target linux-amd64
  $0 --target linux-arm64 --no-package
  $0 --target windows-amd64
  $0 --all --version 0.1.0
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --target) TARGETS+=("$2"); shift 2 ;;
    --all) BUILD_ALL=true; shift ;;
    --no-package|--no-save) NO_PACKAGE=true; shift ;;
    --apt-mirror) APT_MIRROR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown flag: $1" >&2; usage >&2; exit 1 ;;
  esac
done

host_os() {
  case "$(uname -s | tr '[:upper:]' '[:lower:]')" in
    darwin*) echo darwin ;;
    linux*) echo linux ;;
    mingw*|msys*|cygwin*) echo windows ;;
    *) echo unknown ;;
  esac
}

host_arch() {
  case "$(uname -m)" in
    arm64|aarch64) echo arm64 ;;
    x86_64|amd64) echo amd64 ;;
    *) uname -m ;;
  esac
}

default_target() {
  echo "$(host_os)-$(host_arch)"
}

all_targets_for_host() {
  case "$(host_os)" in
    darwin) echo "darwin-arm64 linux-amd64 linux-arm64" ;;
    linux) echo "linux-$(host_arch)" ;;
    windows) echo "windows-amd64" ;;
    *) echo "$(default_target)" ;;
  esac
}

if $BUILD_ALL; then
  read -r -a TARGETS <<< "$(all_targets_for_host)"
elif [[ ${#TARGETS[@]} -eq 0 ]]; then
  TARGETS=("$(default_target)")
fi

valid_target() {
  case "$1" in
    darwin-arm64|linux-amd64|linux-arm64|windows-amd64) return 0 ;;
    *) return 1 ;;
  esac
}

for target in "${TARGETS[@]}"; do
  if ! valid_target "$target"; then
    echo "unsupported target: $target" >&2
    usage >&2
    exit 1
  fi
done

mkdir -p "$DIST_DIR"

package_dir() {
  echo "$DIST_DIR/epan-$1"
}

prepare_package() {
  local target="$1"
  local pkg
  pkg="$(package_dir "$target")"
  rm -rf "$pkg" "$DIST_DIR/epan-$target.tar.gz" "$DIST_DIR/epan-$target.zip"
  mkdir -p "$pkg/bin" "$pkg/lib" "$pkg/share"
  for agent_dir in .trae .codex .claude agents; do
    if [[ -d "$SCRIPT_DIR/$agent_dir" ]]; then
      mkdir -p "$pkg/$agent_dir"
      cp -R "$SCRIPT_DIR/$agent_dir/." "$pkg/$agent_dir/"
    fi
  done
  [[ -f "$SCRIPT_DIR/CLAUDE.md" ]] && cp "$SCRIPT_DIR/CLAUDE.md" "$pkg/CLAUDE.md"
  [[ -f "$SCRIPT_DIR/.mcp.json.template" ]] && cp "$SCRIPT_DIR/.mcp.json.template" "$pkg/.mcp.json.template"
  cp "$SCRIPT_DIR/README.md" "$pkg/README.md"
  cat > "$pkg/PACKAGE_INFO" <<INFO
name=epan
target=$target
version=$VERSION
built_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
INFO
  echo "$pkg"
}

ensure_sdk_dir() {
  if [[ ! -f "$SDK_DIR/go.mod" ]]; then
    cat >&2 <<ERR
missing local epan SDK: $SDK_DIR
Set SDK_DIR or place the SDK beside this repo:
  /path/to/gowireshark
  /path/to/epan
ERR
    exit 1
  fi
}

local_sdk_modfile() {
  local target="$1" modfile
  ensure_sdk_dir
  mkdir -p "$DIST_DIR/.mod"
  modfile="$DIST_DIR/.mod/epan-$target.mod"
  cp "$SCRIPT_DIR/go.mod" "$modfile"
  go mod edit -modfile="$modfile" -dropreplace github.com/randolphcyg/gowireshark 2>/dev/null || true
  go mod edit -modfile="$modfile" -replace "github.com/randolphcyg/gowireshark=$SDK_DIR"
  echo "$modfile"
}

source_darwin_env() {
  local env_file="$SDK_DIR/dev_env.sh"
  if [[ ! -f "$env_file" ]]; then
    cat >&2 <<ERR
missing SDK dev env: $env_file
Run first:
  cd $SDK_DIR
  ./init_mac_dev.sh
  source ./dev_env.sh
ERR
    exit 1
  fi
  # shellcheck disable=SC1090
  source "$env_file"
}

write_unix_wrappers() {
  local pkg="$1"
  local lib_var="$2"
  cat > "$pkg/bin/epan-env" <<EOF2
#!/usr/bin/env bash
set -euo pipefail
ROOT="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")/.." && pwd)"
export $lib_var="\$ROOT/lib\${$lib_var:+:\$$lib_var}"
export WIRESHARK_LIB_DIR="\$ROOT/lib"
export WIRESHARK_DATA_DIR="\$ROOT/share/wireshark"
export WIRESHARK_CONF_DIR="\${WIRESHARK_CONF_DIR:-/tmp/epan_conf}"
export EPAN_BIN="\$ROOT/bin/epan"
export EPAN_PCAP_DIR="\${EPAN_PCAP_DIR:-\$ROOT/pcaps}"
export EPAN_OUTPUT_DIR="\${EPAN_OUTPUT_DIR:-\$ROOT/output}"
mkdir -p "\$WIRESHARK_CONF_DIR" "\$EPAN_PCAP_DIR" "\$EPAN_OUTPUT_DIR"
exec "\$ROOT/bin/epan" "\$@"
EOF2
  cat > "$pkg/bin/epan-mcp-env" <<EOF2
#!/usr/bin/env bash
set -euo pipefail
ROOT="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")/.." && pwd)"
export $lib_var="\$ROOT/lib\${$lib_var:+:\$$lib_var}"
export WIRESHARK_LIB_DIR="\$ROOT/lib"
export WIRESHARK_DATA_DIR="\$ROOT/share/wireshark"
export WIRESHARK_CONF_DIR="\${WIRESHARK_CONF_DIR:-/tmp/epan_conf}"
export EPAN_BIN="\$ROOT/bin/epan-env"
export EPAN_PCAP_DIR="\${EPAN_PCAP_DIR:-\$ROOT/pcaps}"
export EPAN_OUTPUT_DIR="\${EPAN_OUTPUT_DIR:-\$ROOT/output}"
mkdir -p "\$WIRESHARK_CONF_DIR" "\$EPAN_PCAP_DIR" "\$EPAN_OUTPUT_DIR"
exec "\$ROOT/bin/epan-mcp" "\$@"
EOF2
  chmod +x "$pkg/bin/epan-env" "$pkg/bin/epan-mcp-env"
}

write_windows_wrappers() {
  local pkg="$1"
  cat > "$pkg/bin/epan-env.cmd" <<'EOF2'
@echo off
set ROOT=%~dp0..
set PATH=C:\Windows\System32;C:\Windows;%ROOT%\lib;%ROOT%\bin;%PATH%
set WIRESHARK_LIB_DIR=%ROOT%\lib
set WIRESHARK_DATA_DIR=%ROOT%\share\wireshark
if "%WIRESHARK_CONF_DIR%"=="" set WIRESHARK_CONF_DIR=%TEMP%\epan_conf
set EPAN_BIN=%ROOT%\bin\epan.exe
if "%EPAN_PCAP_DIR%"=="" set EPAN_PCAP_DIR=%ROOT%\pcaps
if "%EPAN_OUTPUT_DIR%"=="" set EPAN_OUTPUT_DIR=%ROOT%\output
if not exist "%WIRESHARK_CONF_DIR%" mkdir "%WIRESHARK_CONF_DIR%"
if not exist "%EPAN_PCAP_DIR%" mkdir "%EPAN_PCAP_DIR%"
if not exist "%EPAN_OUTPUT_DIR%" mkdir "%EPAN_OUTPUT_DIR%"
"%ROOT%\bin\epan.exe" %*
EOF2
  cat > "$pkg/bin/epan-mcp-env.cmd" <<'EOF2'
@echo off
set ROOT=%~dp0..
set PATH=C:\Windows\System32;C:\Windows;%ROOT%\lib;%ROOT%\bin;%PATH%
set WIRESHARK_LIB_DIR=%ROOT%\lib
set WIRESHARK_DATA_DIR=%ROOT%\share\wireshark
if "%WIRESHARK_CONF_DIR%"=="" set WIRESHARK_CONF_DIR=%TEMP%\epan_conf
set EPAN_BIN=%ROOT%\bin\epan-env.cmd
if "%EPAN_PCAP_DIR%"=="" set EPAN_PCAP_DIR=%ROOT%\pcaps
if "%EPAN_OUTPUT_DIR%"=="" set EPAN_OUTPUT_DIR=%ROOT%\output
if not exist "%WIRESHARK_CONF_DIR%" mkdir "%WIRESHARK_CONF_DIR%"
if not exist "%EPAN_PCAP_DIR%" mkdir "%EPAN_PCAP_DIR%"
if not exist "%EPAN_OUTPUT_DIR%" mkdir "%EPAN_OUTPUT_DIR%"
"%ROOT%\bin\epan-mcp.exe" %*
EOF2
}

copy_if_exists() {
  local src="$1" dst="$2"
  [[ -e "$src" ]] && cp -R "$src" "$dst"
}

resolve_darwin_dep() {
  local dep="$1" lib_dir="$2" base brew_prefix
  base="${dep##*/}"
  case "$dep" in
    /usr/lib/*|/System/*) return 1 ;;
    @rpath/*|@loader_path/*|@executable_path/*)
      for candidate in "$lib_dir/$base" "$SDK_DIR/local_deps/install/lib/$base"; do
        [[ -f "$candidate" ]] && { echo "$candidate"; return 0; }
      done
      ;;
    *)
      [[ -f "$dep" ]] && { echo "$dep"; return 0; }
      ;;
  esac
  if command -v brew >/dev/null 2>&1; then
    brew_prefix="$(brew --prefix)"
    for candidate in "$brew_prefix/lib/$base" "$brew_prefix"/opt/*/lib/"$base"; do
      [[ -f "$candidate" ]] && { echo "$candidate"; return 0; }
    done
  fi
  return 1
}

copy_darwin_deps_recursive() {
  local pkg="$1"
  local lib_dir="$pkg/lib"
  local queue=()
  local seen_file="$pkg/.deps_seen"
  : > "$seen_file"
  while IFS= read -r f; do queue+=("$f"); done < <(find "$pkg/bin" "$lib_dir" -type f \( -perm -111 -o -name '*.dylib' \) 2>/dev/null)

  while [[ ${#queue[@]} -gt 0 ]]; do
    local file="${queue[0]}"
    queue=("${queue[@]:1}")
    [[ -f "$file" ]] || continue
    if grep -Fxq "$file" "$seen_file"; then continue; fi
    echo "$file" >> "$seen_file"

    while IFS= read -r dep; do
      local resolved base
      resolved="$(resolve_darwin_dep "$dep" "$lib_dir" || true)"
      [[ -n "$resolved" ]] || continue
      base="${resolved##*/}"
      if [[ ! -e "$lib_dir/$base" ]]; then
        cp -L "$resolved" "$lib_dir/$base"
        chmod u+w "$lib_dir/$base" || true
        queue+=("$lib_dir/$base")
      fi
    done < <(otool -L "$file" 2>/dev/null | awk 'NR>1 {print $1}')
  done
  rm -f "$seen_file"

  if command -v install_name_tool >/dev/null 2>&1; then
    while IFS= read -r file; do
      chmod u+w "$file" || true
      if [[ "$file" == "$pkg/bin/"* ]]; then
        install_name_tool -add_rpath "@executable_path/../lib" "$file" 2>/dev/null || true
      else
        install_name_tool -id "@rpath/${file##*/}" "$file" 2>/dev/null || true
        install_name_tool -add_rpath "@loader_path" "$file" 2>/dev/null || true
      fi
      while IFS= read -r dep; do
        case "$dep" in
          /usr/lib/*|/System/*) continue ;;
          *) install_name_tool -change "$dep" "@rpath/${dep##*/}" "$file" 2>/dev/null || true ;;
        esac
      done < <(otool -L "$file" 2>/dev/null | awk 'NR>1 {print $1}')
    done < <(find "$pkg/bin" "$lib_dir" -type f \( -perm -111 -o -name '*.dylib' \) 2>/dev/null)
  fi
  if command -v codesign >/dev/null 2>&1; then
    while IFS= read -r file; do
      codesign --force --sign - "$file" >/dev/null 2>&1 || true
    done < <(find "$pkg/bin" "$lib_dir" -type f \( -perm -111 -o -name '*.dylib' \) 2>/dev/null)
  fi
}

archive_package() {
  local target="$1"
  local pkg
  pkg="$(package_dir "$target")"
  if $NO_PACKAGE; then
    echo "  -> package dir: $pkg"
    return
  fi
  case "$target" in
    windows-*)
      local zip_cmd
      if command -v zip >/dev/null 2>&1; then
        zip_cmd="zip"
      elif [[ -x /usr/bin/zip ]]; then
        zip_cmd="/usr/bin/zip"
      elif [[ -x /bin/zip ]]; then
        zip_cmd="/bin/zip"
      elif [[ -x /c/msys64/usr/bin/zip ]]; then
        zip_cmd="/c/msys64/usr/bin/zip"
      elif [[ -x /c/msys32/usr/bin/zip ]]; then
        zip_cmd="/c/msys32/usr/bin/zip"
      fi
      if [[ -n "$zip_cmd" ]]; then
        (cd "$DIST_DIR" && "$zip_cmd" -qr "epan-$target.zip" "epan-$target")
        echo "  -> $DIST_DIR/epan-$target.zip"
      else
        echo "zip not found; leaving package dir only: $pkg" >&2
      fi
      ;;
    *)
      tar -C "$DIST_DIR" -czf "$DIST_DIR/epan-$target.tar.gz" "epan-$target"
      echo "  -> $DIST_DIR/epan-$target.tar.gz"
      ;;
  esac
}

build_darwin_arm64() {
  if [[ "$(host_os)" != "darwin" || "$(host_arch)" != "arm64" ]]; then
    echo "darwin-arm64 requires macOS Apple Silicon host" >&2
    exit 1
  fi
  source_darwin_env
  local target="darwin-arm64" pkg modfile
  modfile="$(local_sdk_modfile "$target")"
  pkg="$(prepare_package "$target")"
  cp -R "$SDK_DIR/local_deps/install/share/wireshark" "$pkg/share/"
  cp -L "$SDK_DIR/local_deps/install/lib"/*.dylib "$pkg/lib/"
  GOWORK=off CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -modfile="$modfile" -mod=mod -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o "$pkg/bin/epan" ./cmd/epan
  GOWORK=off CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -modfile="$modfile" -mod=mod -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o "$pkg/bin/epan-mcp" ./cmd/epan-mcp
  copy_darwin_deps_recursive "$pkg"
  write_unix_wrappers "$pkg" "DYLD_LIBRARY_PATH"
  archive_package "$target"
}

build_linux() {
  local target="$1" platform arch tmp pkg
  arch="${target#linux-}"
  platform="linux/$arch"
  tmp="$DIST_DIR/.docker-$target"
  pkg="$(prepare_package "$target")"
  rm -rf "$tmp"
  mkdir -p "$tmp"
  local build_args=(--platform "$platform" --target package-export --build-arg "VERSION=$VERSION")
  [[ -z "$APT_MIRROR" ]] || build_args+=(--build-arg "APT_MIRROR=$APT_MIRROR")
  docker build "${build_args[@]}" --output "type=local,dest=$tmp" -f "$SCRIPT_DIR/Dockerfile" "$SCRIPT_DIR"
  cp -R "$tmp/bin/." "$pkg/bin/"
  cp -R "$tmp/lib/." "$pkg/lib/"
  cp -R "$tmp/share/." "$pkg/share/"
  rm -rf "$tmp"
  chmod +x "$pkg/bin/epan" "$pkg/bin/epan-mcp"
  write_unix_wrappers "$pkg" "LD_LIBRARY_PATH"
  archive_package "$target"
}

build_windows_amd64() {
  case "$(host_os)" in
    windows) ;;
    *) echo "windows-amd64 requires Windows + MSYS2 + init_win_dev.ps1" >&2; exit 1 ;;
  esac
  local target="windows-amd64" pkg
  pkg="$(prepare_package "$target")"
  if [[ -z "${WIRESHARK_LIB_DIR:-}" || -z "${WIRESHARK_DATA_DIR:-}" ]]; then
    echo "windows-amd64 requires dev_env.ps1 environment. Run init_win_dev.ps1 first." >&2
    exit 1
  fi
  CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o "$pkg/bin/epan.exe" ./cmd/epan
  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o "$pkg/bin/epan-mcp.exe" ./cmd/epan-mcp
  cp -R "$WIRESHARK_DATA_DIR" "$pkg/share/wireshark"
  cp -R "$WIRESHARK_LIB_DIR"/* "$pkg/lib/"
  
  # Copy MSYS2 runtime DLLs for standalone operation
  # libwireshark.dll has deep transitive deps (glib, gio, gmodule, etc.),
  # so copy all DLLs from ucrt64/bin to ensure the build is truly standalone
  local msys2_root="${MSYS2_ROOT:-/c/msys64}"
  local msys2_bin="$msys2_root/ucrt64/bin"
  if [[ -d "$msys2_bin" ]]; then
    echo "Copying MSYS2 runtime DLLs..."
    cp -n "$msys2_bin"/*.dll "$pkg/lib/"
  fi
  
  write_windows_wrappers "$pkg"
  archive_package "$target"
}

build_target() {
  local target="$1"
  echo "=== Building $target ==="
  case "$target" in
    darwin-arm64) build_darwin_arm64 ;;
    linux-amd64|linux-arm64) build_linux "$target" ;;
    windows-amd64) build_windows_amd64 ;;
  esac
}

echo "=== epan release build ==="
echo "Version: $VERSION"
echo "Targets: ${TARGETS[*]}"
echo "Package archives: $([[ $NO_PACKAGE == true ]] && echo disabled || echo enabled)"

for target in "${TARGETS[@]}"; do
  build_target "$target"
done

echo "=== Done ==="
find "$DIST_DIR" -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.zip' \) -print | sort || true
