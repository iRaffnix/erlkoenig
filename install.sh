#!/bin/sh
# Erlkoenig installer / updater
# ===============================
#
# Usage:
#   sudo sh install.sh --version v0.3.0          # download from GitHub
#   sudo sh install.sh --local /path/to/artifacts # install from local dir
#
# Installs to /opt/erlkoenig (customizable with --prefix).
# Does NOT pipe curl into sh. Download, review, then run.

set -eu

REPO="iRaffnix/erlkoenig"
PREFIX="/opt/erlkoenig"
RT_DIR=""   # set after PREFIX is final
SERVICE_USER="erlkoenig"
VERSION=""
LOCAL_DIR=""
FORCE=false

# ── Helpers ──────────────────────────────────────────────

info()  { echo "  [*] $*"; }
warn()  { echo "  [!] $*" >&2; }
err()   { echo "  [E] $*" >&2; }
ok()    { echo "  [+] $*"; }

# ── Argument parsing ─────────────────────────────────────

usage() {
    echo "Usage: sudo sh install.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --version VERSION   Download release from GitHub (e.g., v0.2.0)"
    echo "  --local DIR         Install from local directory (CI artifacts)"
    echo "  --prefix DIR        Installation directory (default: /opt/erlkoenig)"
    echo "  --force             Force reinstall even if same version"
    echo "  --help              Show this help"
    echo ""
    echo "Examples:"
    echo "  sudo sh install.sh --version v0.3.0"
    echo "  sudo sh install.sh --local /tmp/artifacts"
    echo "  gh run download <run-id> -D /tmp/artifacts"
    echo "  sudo sh install.sh --local /tmp/artifacts"
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --local)   LOCAL_DIR="$2"; shift 2 ;;
        --prefix)  PREFIX="$2"; shift 2 ;;
        --force)   FORCE=true; shift ;;
        --help|-h) usage ;;
        *)         err "Unknown option: $1"; exit 1 ;;
    esac
done

RT_DIR="$PREFIX/rt"

# ── Checks ───────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    err "Installer must be run as root (use sudo)"
    exit 1
fi

if [ -z "$VERSION" ] && [ -z "$LOCAL_DIR" ]; then
    err "--version or --local is required"
    echo "  Run: sh install.sh --help" >&2
    exit 1
fi

if [ -z "$LOCAL_DIR" ] && ! command -v curl >/dev/null 2>&1; then
    err "curl is required for remote install (or use --local)"
    exit 1
fi

if [ -n "$LOCAL_DIR" ] && [ ! -d "$LOCAL_DIR" ]; then
    err "Local directory not found: $LOCAL_DIR"
    exit 1
fi

# ── Detect architecture ─────────────────────────────────

detect_target() {
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)  arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *) err "Unsupported architecture: $arch"; exit 1 ;;
    esac

    # Detect musl vs glibc
    libc="linux"
    if command -v ldd >/dev/null 2>&1; then
        if ldd --version 2>&1 | grep -qi musl; then
            libc="musl"
        fi
    elif [ -f /etc/alpine-release ]; then
        libc="musl"
    fi

    echo "${arch}-${libc}"
}

# ── Read installed version ───────────────────────────────

installed_version() {
    if [ -f "$PREFIX/releases/start_erl.data" ]; then
        awk '{print "v" $2}' "$PREFIX/releases/start_erl.data" 2>/dev/null || true
    fi
}

# ── Daemon management ────────────────────────────────────

daemon_is_running() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl is-active --quiet erlkoenig 2>/dev/null && return 0
    fi
    # Check for running beam process
    pgrep -f "beam.*erlkoenig" >/dev/null 2>&1 && return 0
    return 1
}

stop_daemon() {
    info "Stopping erlkoenig daemon ..."

    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet erlkoenig 2>/dev/null; then
        systemctl stop erlkoenig 2>/dev/null || true
    fi

    # Wait for clean shutdown (up to 15s — matches systemd TimeoutStopSec)
    i=0
    while [ $i -lt 15 ]; do
        if ! daemon_is_running; then
            ok "Daemon stopped"
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done

    # Hard kill as last resort
    pkill -9 -f "beam.*erlkoenig" 2>/dev/null || true
    sleep 1
    ok "Daemon stopped (forced)"
}

start_daemon() {
    info "Starting erlkoenig daemon ..."
    if command -v systemctl >/dev/null 2>&1 && [ -L /etc/systemd/system/erlkoenig.service ]; then
        systemctl start erlkoenig
    fi
    sleep 2
    if daemon_is_running; then
        ok "Daemon started"
    else
        warn "Daemon may not have started — check: journalctl -u erlkoenig -n 20"
    fi
}

# ── Conflict detection ───────────────────────────────────

if [ -f /etc/systemd/system/erlkoenig_nft.service ] || systemctl is-active --quiet erlkoenig_nft 2>/dev/null; then
    echo "" >&2
    err "erlkoenig_nft.service is installed as a standalone service."
    echo "" >&2
    echo "  erlkoenig bundles erlkoenig_nft as an OTP application." >&2
    echo "  Running both will cause nftables conflicts." >&2
    echo "" >&2
    echo "  To resolve, disable the standalone service first:" >&2
    echo "    sudo systemctl stop erlkoenig_nft" >&2
    echo "    sudo systemctl disable erlkoenig_nft" >&2
    echo "    sudo rm /etc/systemd/system/erlkoenig_nft.service" >&2
    echo "" >&2
    exit 1
fi

# ── Version check ────────────────────────────────────────

TARGET=$(detect_target)
CURRENT=$(installed_version)
IS_UPDATE=false

if [ -d "$PREFIX/bin" ]; then
    IS_UPDATE=true
    if [ -n "$CURRENT" ] && [ -n "$VERSION" ]; then
        cur_norm=$(echo "$CURRENT" | sed 's/^v//')
        new_norm=$(echo "$VERSION" | sed 's/^v//')
        if [ "$cur_norm" = "$new_norm" ] && [ "$FORCE" = false ]; then
            ok "Already at version ${VERSION} — nothing to do (use --force to reinstall)"
            exit 0
        fi
    fi
fi

if [ "$IS_UPDATE" = true ]; then
    echo "Updating erlkoenig: ${CURRENT:-unknown} -> ${VERSION:-local} (${TARGET})"
else
    echo "Installing erlkoenig ${VERSION:-local} (${TARGET})"
fi
echo "  prefix: ${PREFIX}"
echo ""

# ── Stop daemon if running ───────────────────────────────

DAEMON_WAS_RUNNING=false

if [ "$IS_UPDATE" = true ] && daemon_is_running; then
    DAEMON_WAS_RUNNING=true
    stop_daemon
fi

# ── Acquire artifacts ────────────────────────────────────

TMPDIR=$(mktemp -d)

cleanup() {
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

if [ -n "$LOCAL_DIR" ]; then
    info "Installing from local artifacts: $LOCAL_DIR"

    # Find the release tarball
    TARBALL=$(find "$LOCAL_DIR" -name 'erlkoenig-*.tar.gz' -not -name 'static-demo*' -print -quit 2>/dev/null || true)
    if [ -z "$TARBALL" ]; then
        err "No erlkoenig-*.tar.gz found in $LOCAL_DIR"
        exit 1
    fi

    # Find C runtime
    RT_BIN=$(find "$LOCAL_DIR" -name 'erlkoenig_rt' -o -name 'erlkoenig_rt-linux-amd64' | head -1)
    if [ -z "$RT_BIN" ]; then
        err "No erlkoenig_rt found in $LOCAL_DIR"
        exit 1
    fi

    cp "$TARBALL" "$TMPDIR/erlkoenig-release.tar.gz"
    cp "$RT_BIN" "$TMPDIR/erlkoenig_rt"

    # Optional: demo binaries
    DEMO_TAR=$(find "$LOCAL_DIR" -name 'static-demo-binaries-*.tar.gz' | head -1)
    if [ -n "$DEMO_TAR" ]; then
        cp "$DEMO_TAR" "$TMPDIR/static-demo-binaries.tar.gz"
    fi

    # Detect version from tarball content
    if [ -z "$VERSION" ]; then
        VERSION=$(tar xzf "$TMPDIR/erlkoenig-release.tar.gz" -O releases/start_erl.data 2>/dev/null | awk '{print "v"$2}' || true)
        if [ -z "$VERSION" ]; then
            VERSION="unknown"
        fi
    fi

    ok "Found: $(basename "$TARBALL")"
else
    ARCHIVE="erlkoenig-${VERSION#v}-${TARGET}.tar.gz"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE}"

    info "Downloading ${ARCHIVE} ..."
    if ! curl -fsSL "$URL" -o "$TMPDIR/erlkoenig-release.tar.gz"; then
        err "Download failed. Check that ${VERSION} has a ${TARGET} build."
        err "Available at: https://github.com/${REPO}/releases/tag/${VERSION}"
        if [ "$DAEMON_WAS_RUNNING" = true ]; then
            warn "Restarting daemon with previous version ..."
            start_daemon
        fi
        exit 1
    fi

    # C runtime (architecture-independent — static musl binary)
    if ! curl -fsSL "https://github.com/${REPO}/releases/download/${VERSION}/erlkoenig_rt-linux-amd64" \
            -o "$TMPDIR/erlkoenig_rt"; then
        err "Failed to download erlkoenig_rt"
        if [ "$DAEMON_WAS_RUNNING" = true ]; then
            warn "Restarting daemon with previous version ..."
            start_daemon
        fi
        exit 1
    fi

    # Optional: demo binaries
    curl -fsSL "https://github.com/${REPO}/releases/download/${VERSION}/static-demo-binaries-linux-amd64.tar.gz" \
        -o "$TMPDIR/static-demo-binaries.tar.gz" 2>/dev/null || true
fi

# Verify release archive
if ! tar tzf "$TMPDIR/erlkoenig-release.tar.gz" >/dev/null 2>&1; then
    err "Release archive is corrupt"
    if [ "$DAEMON_WAS_RUNNING" = true ]; then
        warn "Restarting daemon with previous version ..."
        start_daemon
    fi
    exit 1
fi

ok "Artifacts verified"

# ── Service user ─────────────────────────────────────────

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    if getent group "$SERVICE_USER" >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin -g "$SERVICE_USER" "$SERVICE_USER"
    else
        useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    fi
    ok "Service user '$SERVICE_USER' created"
fi

# ── Clean extraction (updates) ───────────────────────────
# Old files (stale boot scripts, BEAM modules from different OTP version)
# can cause crashes. Wipe and re-extract cleanly.

if [ "$IS_UPDATE" = true ]; then
    info "Removing old release files ..."
    rm -rf "${PREFIX:?}/bin" "${PREFIX:?}/erts-"* "${PREFIX:?}/lib" "${PREFIX:?}/releases" "${PREFIX:?}/dist"
fi

# ── Create directories ───────────────────────────────────

mkdir -p "$PREFIX" "$RT_DIR" "$RT_DIR/demo" /etc/erlkoenig /var/lib/erlkoenig/volumes /var/log/erlkoenig /run/erlkoenig/containers

# ── Extract OTP release ──────────────────────────────────

info "Extracting release to ${PREFIX} ..."
if ! tar xzf "$TMPDIR/erlkoenig-release.tar.gz" -C "$PREFIX"; then
    err "Extraction failed"
    if [ "$DAEMON_WAS_RUNNING" = true ]; then
        warn "Restarting daemon with previous version ..."
        start_daemon
    fi
    exit 1
fi

ok "OTP release extracted"

# ── Remove stale versioned scripts ──────────────────────
# The release tarball may contain scripts from old versions
# (e.g. erlkoenig-0.4.0 alongside erlkoenig-0.5.0). Keep only
# the current version.

REL_VSN=$(awk '{print $2}' "$PREFIX/releases/start_erl.data" 2>/dev/null || true)
if [ -n "$REL_VSN" ]; then
    for f in "$PREFIX"/bin/erlkoenig-*; do
        base=$(basename "$f")
        case "$base" in
            erlkoenig-"$REL_VSN") ;; # keep current
            erlkoenig-dsl*)        ;; # keep if present
            erlkoenig-*)
                info "Removing stale script: $base"
                rm -f "$f"
                ;;
        esac
    done
fi

# ── Install C runtime ────────────────────────────────────

info "Installing C runtime ..."
install -m 755 "$TMPDIR/erlkoenig_rt" "$RT_DIR/erlkoenig_rt"
chown root:root "$RT_DIR/erlkoenig_rt"

ok "C runtime: $RT_DIR/erlkoenig_rt ($(wc -c < "$RT_DIR/erlkoenig_rt") bytes)"

# ── Install demo binaries (optional) ─────────────────────

DEMOS_INSTALLED=false

# From tarball (CI release artifacts)
if [ -f "$TMPDIR/static-demo-binaries.tar.gz" ] && [ -s "$TMPDIR/static-demo-binaries.tar.gz" ]; then
    tar xzf "$TMPDIR/static-demo-binaries.tar.gz" -C "$TMPDIR" 2>/dev/null || true
    if [ -d "$TMPDIR/static-demo-binaries" ]; then
        cp "$TMPDIR"/static-demo-binaries/test-erlkoenig-* "$RT_DIR/demo/" 2>/dev/null || true
        cp "$TMPDIR"/static-demo-binaries/echo-server "$RT_DIR/" 2>/dev/null || true
        cp "$TMPDIR"/static-demo-binaries/reverse-proxy "$RT_DIR/" 2>/dev/null || true
        cp "$TMPDIR"/static-demo-binaries/api-server "$RT_DIR/" 2>/dev/null || true
        DEMOS_INSTALLED=true
    fi
fi

# From loose files in --local dir (local build artifacts)
if [ "$DEMOS_INSTALLED" = false ] && [ -n "$LOCAL_DIR" ]; then
    LOOSE_DEMOS=$(find "$LOCAL_DIR" -maxdepth 1 -name 'test-erlkoenig-*' -type f 2>/dev/null | head -1)
    if [ -n "$LOOSE_DEMOS" ]; then
        cp "$LOCAL_DIR"/test-erlkoenig-* "$RT_DIR/demo/" 2>/dev/null || true
        chmod 755 "$RT_DIR/demo/"* 2>/dev/null || true
        DEMOS_INSTALLED=true
    fi
fi

if [ "$DEMOS_INSTALLED" = true ]; then
    ok "Demo binaries installed"
fi

# ── File permissions ─────────────────────────────────────

chown -R root:"$SERVICE_USER" "$PREFIX"
chmod 750 "$PREFIX"
[ -f "$PREFIX/bin/erlkoenig_run" ] && chmod 755 "$PREFIX/bin/erlkoenig_run"
[ -f "$PREFIX/dist/erlkoenig.service" ] && chmod 644 "$PREFIX/dist/erlkoenig.service"

# RT dir owned by root (C runtime runs with file capabilities)
chown -R root:root "$RT_DIR"
chmod 755 "$RT_DIR" "$RT_DIR/erlkoenig_rt"
[ -d "$RT_DIR/demo" ] && chmod 700 "$RT_DIR/demo"/* 2>/dev/null || true

# Volume base dir owned by service user
chown "$SERVICE_USER":"$SERVICE_USER" /var/lib/erlkoenig/volumes

# Log directory owned by service user
chown "$SERVICE_USER":"$SERVICE_USER" /var/log/erlkoenig

ok "Permissions set"

# ── File capabilities on C runtime ─────────────────────
# MUST happen AFTER all chown operations — chown strips file capabilities.

if command -v setcap >/dev/null 2>&1; then
    setcap \
        'cap_sys_admin,cap_net_admin,cap_sys_chroot,cap_sys_ptrace,cap_setpcap,cap_setuid,cap_setgid,cap_dac_override,cap_bpf,cap_sys_resource=ep' \
        "$RT_DIR/erlkoenig_rt"
    ok "Capabilities set on erlkoenig_rt"
else
    warn "setcap not found — install libcap2-bin and run:"
    warn "  setcap 'cap_sys_admin,...=ep' $RT_DIR/erlkoenig_rt"
fi

# ── Systemd unit (symlink from dist/) ────────────────────

if [ -d /etc/systemd/system ] && [ -f "$PREFIX/dist/erlkoenig.service" ]; then
    ln -sf "$PREFIX/dist/erlkoenig.service" /etc/systemd/system/erlkoenig.service
    systemctl daemon-reload
    ok "Systemd unit: erlkoenig.service (symlinked)"
fi

# ── Generate cookie if missing ──────────────────────────

COOKIE_FILE="$PREFIX/cookie"
if [ ! -f "$COOKIE_FILE" ]; then
    head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32 > "$COOKIE_FILE"
    chmod 440 "$COOKIE_FILE"
    chown root:"$SERVICE_USER" "$COOKIE_FILE"
    ok "Cookie generated: $COOKIE_FILE"
fi

# ── Fix hostname resolution for epmd ────────────────────
# Debian cloud images set hostname to 127.0.1.1 in /etc/hosts.
# epmd binds to 127.0.0.1 — the mismatch prevents CLI from
# connecting to the running node. Fix if needed.

HOSTNAME=$(hostname)
if grep -q "127\.0\.1\.1.*$HOSTNAME" /etc/hosts 2>/dev/null; then
    sed -i "s/127\.0\.1\.1\(.*$HOSTNAME\)/127.0.0.1\1/" /etc/hosts
    ok "Fixed /etc/hosts: $HOSTNAME → 127.0.0.1 (was 127.0.1.1)"
fi

# ── Restart daemon if it was running ─────────────────────

if [ "$DAEMON_WAS_RUNNING" = true ]; then
    start_daemon
fi

# ── Done ─────────────────────────────────────────────────

echo ""
if [ "$IS_UPDATE" = true ]; then
    echo "Update complete! ${CURRENT:-unknown} -> ${VERSION:-local}"
else
    echo "Installation complete!"
fi
echo ""
echo "  Start:     sudo systemctl start erlkoenig"
echo "  Status:    sudo systemctl status erlkoenig"
echo "  Stop:      sudo systemctl stop erlkoenig"
echo "  Enable:    sudo systemctl enable erlkoenig"
echo "  Logs:      journalctl -u erlkoenig -f"
echo ""
echo "  Runtime:   $RT_DIR/erlkoenig_rt"
echo "  Release:   $PREFIX/"
echo "  Config:    /etc/erlkoenig/"
echo "  Volumes:   /var/lib/erlkoenig/volumes/"
echo "  Socket:    /run/erlkoenig/ctl.sock"
echo ""
