ARG WIRESHARK_VER=4.6.6
ARG GO_VER=1.26.3
ARG VERSION=dev
ARG APT_MIRROR=

FROM ubuntu:24.04 AS wireshark-builder
ARG WIRESHARK_VER
ARG APT_MIRROR
ENV DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    pkgs="build-essential cmake ninja-build wget flex bison doxygen libpcap-dev libglib2.0-dev libssl-dev libc-ares-dev libgcrypt20-dev libspeexdsp-dev libgmp-dev libunbound-dev libxml2-dev libsasl2-dev libzstd-dev libcurl4-openssl-dev ca-certificates"; \
    apt_opts="-o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30"; \
    arch="$(dpkg --print-architecture)"; \
    if [ "$arch" = "arm64" ]; then mirrors="http://repo.huaweicloud.com/ubuntu-ports http://mirrors.ustc.edu.cn/ubuntu-ports http://mirrors.aliyun.com/ubuntu-ports http://ports.ubuntu.com/ubuntu-ports"; else mirrors="http://repo.huaweicloud.com/ubuntu http://mirrors.ustc.edu.cn/ubuntu http://mirrors.aliyun.com/ubuntu http://archive.ubuntu.com/ubuntu"; fi; \
    [ -z "$APT_MIRROR" ] || mirrors="$APT_MIRROR $mirrors"; \
    ok=0; \
    for mirror in $mirrors; do \
      echo "Trying apt mirror: $mirror"; \
      sed -i -E "s@URIs: .*@URIs: ${mirror}@g" /etc/apt/sources.list.d/ubuntu.sources; \
      apt-get clean; rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/partial/*; \
      if apt-get $apt_opts update && apt-get $apt_opts install -y --no-install-recommends $pkgs; then ok=1; break; fi; \
      dpkg --configure -a || true; \
    done; \
    test "$ok" = "1"; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN wget https://www.wireshark.org/download/src/all-versions/wireshark-${WIRESHARK_VER}.tar.xz -L && \
    tar -xf wireshark-${WIRESHARK_VER}.tar.xz && \
    mv wireshark-${WIRESHARK_VER} wireshark

WORKDIR /opt/wireshark/build
RUN cmake -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_wireshark=OFF \
    -DENABLE_LUA=OFF \
    -DDISABLE_PROTOBUF=ON \
    -DENABLE_DEBUG_INFO=OFF \
    -DENABLE_MAN_PAGES=OFF \
    -DDISABLE_GNUTLS=ON \
    -DENABLE_DOCS=OFF \
    -DG_DISABLE_ASSERT=1 \
    -DCMAKE_C_FLAGS="-DG_DISABLE_ASSERT" \
    -DENABLE_APPLICATION_BUNDLE=OFF \
    -DCMAKE_INSTALL_PREFIX=/opt/wireshark/build .. && \
    ninja -j$(nproc) && \
    ninja install

RUN mkdir -p /app/libs /app/include/wireshark && \
    cp -d /opt/wireshark/build/run/lib*.so* /app/libs/ && \
    cp /opt/wireshark/*.h /app/include/wireshark/ && \
    cp /opt/wireshark/build/*.h /app/include/wireshark/ && \
    cp -r /opt/wireshark/include/* /app/include/wireshark/ && \
    cp -r /opt/wireshark/epan /app/include/wireshark/ && \
    cp -r /opt/wireshark/wiretap /app/include/wireshark/ && \
    cp -r /opt/wireshark/wsutil /app/include/wireshark/

FROM ubuntu:24.04 AS go-builder
ARG GO_VER
ARG VERSION
ARG APT_MIRROR
ENV DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    pkgs="wget ca-certificates gcc libc6-dev pkg-config file binutils libglib2.0-dev libpcap-dev libssl-dev libzstd-dev libsasl2-dev libxml2-dev libc-ares-dev libcurl4-openssl-dev"; \
    apt_opts="-o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30"; \
    arch="$(dpkg --print-architecture)"; \
    if [ "$arch" = "arm64" ]; then mirrors="http://repo.huaweicloud.com/ubuntu-ports http://mirrors.ustc.edu.cn/ubuntu-ports http://mirrors.aliyun.com/ubuntu-ports http://ports.ubuntu.com/ubuntu-ports"; else mirrors="http://repo.huaweicloud.com/ubuntu http://mirrors.ustc.edu.cn/ubuntu http://mirrors.aliyun.com/ubuntu http://archive.ubuntu.com/ubuntu"; fi; \
    [ -z "$APT_MIRROR" ] || mirrors="$APT_MIRROR $mirrors"; \
    ok=0; \
    for mirror in $mirrors; do \
      echo "Trying apt mirror: $mirror"; \
      sed -i -E "s@URIs: .*@URIs: ${mirror}@g" /etc/apt/sources.list.d/ubuntu.sources; \
      apt-get clean; rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/partial/*; \
      if apt-get $apt_opts update && apt-get $apt_opts install -y --no-install-recommends $pkgs; then ok=1; break; fi; \
      dpkg --configure -a || true; \
    done; \
    test "$ok" = "1"; \
    rm -rf /var/lib/apt/lists/*

RUN ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') && \
    GO_TARBALL="go${GO_VER}.linux-${ARCH}.tar.gz" && \
    wget "https://go.dev/dl/${GO_TARBALL}" && \
    tar -C /usr/local -xzf "${GO_TARBALL}" && \
    rm "${GO_TARBALL}"

ENV PATH="/usr/local/go/bin:${PATH}" \
    CGO_ENABLED=1 \
    GOPROXY=https://goproxy.cn,direct \
    CGO_CFLAGS="-I/app/include -I/app/include/wireshark -I/app/include/wireshark/epan -I/app/include/wireshark/wiretap -I/app/include/wireshark/wsutil" \
    CGO_LDFLAGS="-L/app/libs -Wl,-rpath,/app/libs -lwiretap -lwsutil -lwireshark -lpcap -lglib-2.0 -lm" \
    LD_LIBRARY_PATH="/app/libs" \
    WIRESHARK_DATA_DIR="/app/share/wireshark" \
    WIRESHARK_LIB_DIR="/app/libs" \
    WIRESHARK_CONF_DIR="/tmp/epan_conf"

COPY --from=wireshark-builder /app/libs/ /app/libs/
COPY --from=wireshark-builder /app/include/ /app/include/
COPY --from=wireshark-builder /opt/wireshark/build/share/ /app/share/

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod edit -dropreplace github.com/randolphcyg/ && go mod download
COPY . .
RUN go mod edit -dropreplace github.com/randolphcyg/ && go mod download github.com/randolphcyg/gowireshark

RUN mkdir -p /out/bin /out/lib /out/share && \
    go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o /out/bin/epan ./cmd/epan && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o /out/bin/epan-mcp ./cmd/epan-mcp && \
    cp -d /app/libs/lib*.so* /out/lib/ && \
    cp -R /app/share/wireshark /out/share/ && \
    for f in /out/bin/epan /out/lib/*.so*; do \
      ldd "$f" 2>/dev/null | awk '/=> \/.*\.so/ {print $(NF-1)} /^\/.*\.so/ {print $1}' || true; \
    done | sort -u | while read -r lib; do \
      case "$lib" in \
        ""|*ld-linux*|*/libc.so.*|*/libm.so.*|*/libpthread.so.*|*/libdl.so.*|*/librt.so.*) continue ;; \
      esac; \
      cp -L "$lib" /out/lib/ 2>/dev/null || true; \
    done && \
    chmod +x /out/bin/epan /out/bin/epan-mcp

FROM ubuntu:24.04 AS runtime
ENV LD_LIBRARY_PATH=/usr/local/lib \
    WIRESHARK_DATA_DIR=/usr/local/share/wireshark \
    WIRESHARK_LIB_DIR=/usr/local/lib \
    WIRESHARK_CONF_DIR=/tmp/epan_conf \
    EPAN_PCAP_DIR=/app/pcaps \
    EPAN_OUTPUT_DIR=/app/output
COPY --from=go-builder /out/bin/epan /usr/local/bin/epan
COPY --from=go-builder /out/bin/epan-mcp /usr/local/bin/epan-mcp
COPY --from=go-builder /out/lib/ /usr/local/lib/
COPY --from=go-builder /out/share/wireshark /usr/local/share/wireshark
RUN mkdir -p /tmp/epan_conf /app/pcaps /app/output && ldconfig || true
ENTRYPOINT ["epan"]
CMD ["version"]

FROM ubuntu:24.04 AS mcp-http-runtime
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
ENV LD_LIBRARY_PATH=/usr/local/lib \
    WIRESHARK_DATA_DIR=/usr/local/share/wireshark \
    WIRESHARK_LIB_DIR=/usr/local/lib \
    WIRESHARK_CONF_DIR=/tmp/epan_conf \
    EPAN_PCAP_DIR=/pcaps \
    EPAN_OUTPUT_DIR=/outputs/epan
COPY --from=go-builder /out/bin/epan /usr/local/bin/epan
COPY --from=go-builder /out/bin/epan-mcp /usr/local/bin/epan-mcp
COPY --from=go-builder /out/lib/ /usr/local/lib/
COPY --from=go-builder /out/share/wireshark /usr/local/share/wireshark
RUN mkdir -p /tmp/epan_conf /pcaps /outputs/epan && ldconfig || true
ENTRYPOINT ["epan-mcp"]
CMD ["--transport", "http", "--listen", ":8002", "--endpoint", "/mcp"]
EXPOSE 8002

FROM scratch AS package-export
COPY --from=go-builder /out/bin/ /bin/
COPY --from=go-builder /out/lib/ /lib/
COPY --from=go-builder /out/share/ /share/
