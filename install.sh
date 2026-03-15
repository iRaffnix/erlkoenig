#!/bin/sh
# Erlkoenig Installer
# ====================
#
# Usage:
#   sudo sh install.sh --version v0.2.0          # download from GitHub
#   sudo sh install.sh --local /path/to/artifacts # install from local dir
#
# This script installs:
#   /opt/erlkoenig/rt/erlkoenig_rt          C runtime (static binary)
#   /opt/erlkoenig/                         OTP release (BEAM + ERTS)
#   /opt/erlkoenig/bin/erlkoenig-dsl        DSL compiler (optional)
#   /opt/erlkoenig/rt/demo/                 Demo binaries (optional)
#
# It does NOT pipe curl into sh. Download, review, then run.

set -eu

REPO="iRaffnix/erlkoenig"
VERSION=""
LOCAL_DIR=""
INSTALL_DIR="/opt/erlkoenig"
RT_DIR="/opt/erlkoenig/rt"

# ── Argument parsing ──────────────────────────────────────

usage() {
    echo "Usage: sudo sh install.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --version VERSION   Download release from GitHub (e.g., v0.2.0)"
    echo "  --local DIR         Install from local directory (CI artifacts)"
    echo "  --help              Show this help"
    echo ""
    echo "Examples:"
    echo "  sudo sh install.sh --version v0.2.0"
    echo "  sudo sh install.sh --local /tmp/artifacts"
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --local)   LOCAL_DIR="$2"; shift 2 ;;
        --help)    usage ;;
        *)         echo "Error: unknown option: $1" >&2; exit 1 ;;
    esac
done

if [ -z "$VERSION" ] && [ -z "$LOCAL_DIR" ]; then
    echo "Error: specify --version or --local" >&2
    echo "Run: sh install.sh --help" >&2
    exit 1
fi

# ── Checks ────────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must run as root (sudo)" >&2
    exit 1
fi

if [ -z "$LOCAL_DIR" ] && ! command -v curl >/dev/null 2>&1; then
    echo "Error: curl is required for remote install" >&2
    exit 1
fi

# ── Conflict detection ────────────────────────────────────

if [ -f /etc/systemd/system/erlkoenig_nft.service ] || systemctl is-active --quiet erlkoenig_nft 2>/dev/null; then
    echo "" >&2
    echo "  [E] erlkoenig_nft.service is installed as a standalone service." >&2
    echo "" >&2
    echo "  erlkoenig bundles erlkoenig_nft as an OTP application." >&2
    echo "  Running both will cause nftables conflicts." >&2
    echo "" >&2
    echo "  To resolve, disable the standalone service first:" >&2
    echo "    sudo systemctl stop erlkoenig_nft" >&2
    echo "    sudo systemctl disable erlkoenig_nft" >&2
    echo "    sudo rm /etc/systemd/system/erlkoenig_nft.service" >&2
    echo "" >&2
    echo "  Your firewall config is preserved at:" >&2
    echo "    /opt/erlkoenig_nft/etc/firewall.term" >&2
    exit 1
fi

# ── Create user + directories ─────────────────────────────

if ! id erlkoenig >/dev/null 2>&1; then
    useradd -r -m -d "$INSTALL_DIR" -s /bin/bash erlkoenig
    echo "Created user: erlkoenig"
fi

mkdir -p "$INSTALL_DIR" "$RT_DIR" "$RT_DIR/demo" /etc/erlkoenig
chown erlkoenig:erlkoenig "$INSTALL_DIR" /etc/erlkoenig

# ── Download or copy artifacts ────────────────────────────

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

if [ -n "$LOCAL_DIR" ]; then
    # ── Local mode: copy from directory ──
    echo "Installing from local directory: $LOCAL_DIR"

    # Find the release tarball
    TARBALL=$(find "$LOCAL_DIR" -name 'erlkoenig-*.tar.gz' -not -name 'static-demo*' | head -1)
    if [ -z "$TARBALL" ]; then
        echo "Error: no erlkoenig-*.tar.gz found in $LOCAL_DIR" >&2
        exit 1
    fi

    # Find C runtime
    RT_BIN=$(find "$LOCAL_DIR" -name 'erlkoenig_rt' -o -name 'erlkoenig_rt-linux-amd64' | head -1)
    if [ -z "$RT_BIN" ]; then
        echo "Error: no erlkoenig_rt found in $LOCAL_DIR" >&2
        exit 1
    fi

    cp "$TARBALL" "$WORKDIR/erlkoenig-release.tar.gz"
    cp "$RT_BIN" "$WORKDIR/erlkoenig_rt"

    # Optional: DSL escript
    DSL_BIN=$(find "$LOCAL_DIR" -name 'erlkoenig-dsl' -o -name 'erlkoenig-dsl-linux-amd64' | head -1)
    if [ -n "$DSL_BIN" ]; then
        cp "$DSL_BIN" "$WORKDIR/erlkoenig-dsl"
    fi

    # Optional: demo binaries
    DEMO_TAR=$(find "$LOCAL_DIR" -name 'static-demo-binaries-*.tar.gz' | head -1)
    if [ -n "$DEMO_TAR" ]; then
        cp "$DEMO_TAR" "$WORKDIR/static-demo-binaries.tar.gz"
    fi

    # Detect version from tarball content
    VERSION=$(tar xzf "$WORKDIR/erlkoenig-release.tar.gz" -O releases/start_erl.data 2>/dev/null | awk '{print "v"$2}' || true)
    if [ -z "$VERSION" ]; then
        VERSION="unknown"
    fi
else
    # ── Remote mode: download from GitHub ──
    echo "Downloading erlkoenig $VERSION from GitHub..."
    BASE_URL="https://github.com/$REPO/releases/download/$VERSION"

    curl -fsSL -o "$WORKDIR/erlkoenig_rt" "$BASE_URL/erlkoenig_rt-linux-amd64"
    curl -fsSL -o "$WORKDIR/erlkoenig-release.tar.gz" \
        "$BASE_URL/erlkoenig-${VERSION#v}.tar.gz"

    # Optional downloads (don't fail if missing)
    curl -fsSL -o "$WORKDIR/erlkoenig-dsl" "$BASE_URL/erlkoenig-dsl-linux-amd64" 2>/dev/null || true
    curl -fsSL -o "$WORKDIR/static-demo-binaries.tar.gz" \
        "$BASE_URL/static-demo-binaries-linux-amd64.tar.gz" 2>/dev/null || true
fi

# ── Install C runtime ─────────────────────────────────────

echo "Installing C runtime..."
install -m 755 "$WORKDIR/erlkoenig_rt" "$RT_DIR/erlkoenig_rt"
chown root:root "$RT_DIR/erlkoenig_rt"
setcap \
    cap_sys_admin,cap_net_admin,cap_sys_chroot,cap_sys_ptrace,\
cap_setpcap,cap_setuid,cap_setgid,cap_dac_override,\
cap_bpf,cap_sys_resource+ep \
    "$RT_DIR/erlkoenig_rt"

echo "  $RT_DIR/erlkoenig_rt ($(wc -c < "$RT_DIR/erlkoenig_rt") bytes)"

# ── Install OTP release ───────────────────────────────────

echo "Installing OTP release..."
tar xzf "$WORKDIR/erlkoenig-release.tar.gz" -C "$INSTALL_DIR"
chown -R erlkoenig:erlkoenig "$INSTALL_DIR"
echo "  $INSTALL_DIR/"

# ── Install DSL escript (optional) ─────────────────────────

if [ -f "$WORKDIR/erlkoenig-dsl" ]; then
    echo "Installing DSL compiler..."
    install -m 755 -o erlkoenig -g erlkoenig \
        "$WORKDIR/erlkoenig-dsl" "$INSTALL_DIR/bin/erlkoenig-dsl"

    # Fix shebang to use bundled ERTS
    ERTS_BIN=$(ls -d "$INSTALL_DIR"/erts-*/bin 2>/dev/null | head -1)
    if [ -n "$ERTS_BIN" ]; then
        sed -i "1s|.*|#!${ERTS_BIN}/escript|" "$INSTALL_DIR/bin/erlkoenig-dsl"
    fi
    echo "  $INSTALL_DIR/bin/erlkoenig-dsl"
fi

# ── Install demo binaries (optional) ──────────────────────

if [ -f "$WORKDIR/static-demo-binaries.tar.gz" ]; then
    echo "Installing demo binaries..."
    tar xzf "$WORKDIR/static-demo-binaries.tar.gz" -C "$WORKDIR"
    if [ -d "$WORKDIR/static-demo-binaries" ]; then
        cp "$WORKDIR"/static-demo-binaries/test-erlkoenig-* "$RT_DIR/demo/" 2>/dev/null || true
        cp "$WORKDIR"/static-demo-binaries/echo-server "$RT_DIR/" 2>/dev/null || true
        cp "$WORKDIR"/static-demo-binaries/reverse-proxy "$RT_DIR/" 2>/dev/null || true
        cp "$WORKDIR"/static-demo-binaries/api-server "$RT_DIR/" 2>/dev/null || true
        chown -R root:root "$RT_DIR/demo"
        chmod 700 "$RT_DIR/demo"/*
        chmod 755 "$RT_DIR/echo-server" "$RT_DIR/reverse-proxy" "$RT_DIR/api-server" 2>/dev/null || true
    fi
    echo "  $RT_DIR/demo/"
fi

# ── Make erlkoenig_run executable ─────────────────────────

if [ -f "$INSTALL_DIR/bin/erlkoenig_run" ]; then
    chmod +x "$INSTALL_DIR/bin/erlkoenig_run"
fi

# ── Systemd service ───────────────────────────────────────

if [ -d /etc/systemd/system ]; then
    cat > /etc/systemd/system/erlkoenig.service <<UNIT
[Unit]
Description=Erlkoenig Container Runtime
After=network.target
Wants=network.target

[Service]
Type=simple
User=erlkoenig
Group=erlkoenig
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/bin/erlkoenig_run
KillSignal=SIGTERM
TimeoutStopSec=15
Environment=HOME=${INSTALL_DIR}
RuntimeDirectory=erlkoenig
RuntimeDirectoryMode=0755

AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
Delegate=yes
DelegateSubgroup=init
LimitNOFILE=65536
LimitMEMLOCK=infinity

Restart=on-failure
RestartSec=5

StandardOutput=journal
StandardError=journal
SyslogIdentifier=erlkoenig

NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes
ProtectClock=yes
RestrictSUIDSGID=yes
ProtectKernelTunables=yes

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    echo "Systemd unit: erlkoenig.service"
fi

# ── Done ──────────────────────────────────────────────────

echo ""
echo "Erlkoenig $VERSION installed successfully."
echo ""
echo "  Runtime: $RT_DIR/erlkoenig_rt"
echo "  Release: $INSTALL_DIR/"
echo "  Config:  /etc/erlkoenig/"
echo ""
echo "Start:    sudo systemctl start erlkoenig"
echo "Status:   sudo systemctl status erlkoenig"
echo "Stop:     sudo systemctl stop erlkoenig"
echo "Logs:     journalctl -u erlkoenig -f"
