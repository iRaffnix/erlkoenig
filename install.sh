#!/bin/sh
# Erlkoenig installer / updater
# ===============================
#
# Usage:
#   sudo sh install.sh --version v0.9.0          # download from GitHub
#   sudo sh install.sh --local /path/to/artifacts # install from local dir
#
# Installs to /opt/erlkoenig (customizable with --prefix).
# Does NOT pipe curl into sh. Download, review, then run.

set -eu

REPO="iRaffnix/erlkoenig"
RT_REPO="iRaffnix/erlkoenig_rt"
PREFIX="/opt/erlkoenig"
RT_DIR=""   # set after PREFIX is final
SERVICE_USER="erlkoenig"
VERSION=""
RT_VERSION=""
LOCAL_DIR=""
ERLKOENIG_TAR=""
RT_TAR=""
RT_BIN=""
FORCE=false
FIX_HOSTS=false

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
    echo "  --rt-version VERSION Download erlkoenig_rt release tag (default: --version)"
    echo "  --local DIR         Install from local directory (CI artifacts)"
    echo "  --erlkoenig-tar PATH Use exact erlkoenig release tarball"
    echo "  --rt-tar PATH       Use exact erlkoenig_rt release tarball"
    echo "  --rt-bin PATH       Use exact erlkoenig_rt binary"
    echo "  --prefix DIR        Installation directory (default: /opt/erlkoenig)"
    echo "  --force             Force reinstall even if same version"
    echo "  --fix-hosts         Rewrite 127.0.1.1 hostname entries to 127.0.0.1"
    echo "  --help              Show this help"
    echo ""
    echo "Examples:"
    echo "  sudo sh install.sh --version v0.9.0"
    echo "  sudo sh install.sh --local /tmp/artifacts"
    echo "  gh run download <run-id> -D /tmp/artifacts"
    echo "  sudo sh install.sh --local /tmp/artifacts"
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version)       VERSION="$2"; shift 2 ;;
        --rt-version)    RT_VERSION="$2"; shift 2 ;;
        --local)         LOCAL_DIR="$2"; shift 2 ;;
        --erlkoenig-tar) ERLKOENIG_TAR="$2"; shift 2 ;;
        --rt-tar)        RT_TAR="$2"; shift 2 ;;
        --rt-bin)        RT_BIN="$2"; shift 2 ;;
        --prefix)        PREFIX="$2"; shift 2 ;;
        --force)         FORCE=true; shift ;;
        --fix-hosts)     FIX_HOSTS=true; shift ;;
        --help|-h)       usage ;;
        *)               err "Unknown option: $1"; exit 1 ;;
    esac
done

RT_DIR="$PREFIX/rt"

# ── Checks ───────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    err "Installer must be run as root (use sudo)"
    exit 1
fi

if [ -z "$VERSION" ] && [ -z "$LOCAL_DIR" ] && [ -z "$ERLKOENIG_TAR" ]; then
    err "--version, --local, or --erlkoenig-tar is required"
    echo "  Run: sh install.sh --help" >&2
    exit 1
fi

if [ -z "$LOCAL_DIR" ] && [ -z "$ERLKOENIG_TAR" ] && ! command -v curl >/dev/null 2>&1; then
    err "curl is required for remote install (or use --local/--erlkoenig-tar)"
    exit 1
fi

if [ -n "$LOCAL_DIR" ] && [ ! -d "$LOCAL_DIR" ]; then
    err "Local directory not found: $LOCAL_DIR"
    exit 1
fi

if [ -n "$ERLKOENIG_TAR" ] && [ ! -f "$ERLKOENIG_TAR" ]; then
    err "erlkoenig tarball not found: $ERLKOENIG_TAR"
    exit 1
fi

if [ -n "$RT_TAR" ] && [ ! -f "$RT_TAR" ]; then
    err "erlkoenig_rt tarball not found: $RT_TAR"
    exit 1
fi

if [ -n "$RT_BIN" ] && [ ! -f "$RT_BIN" ]; then
    err "erlkoenig_rt binary not found: $RT_BIN"
    exit 1
fi

if [ -n "$RT_VERSION" ] && [ -z "$VERSION" ] && [ -z "$RT_TAR" ] && [ -z "$RT_BIN" ] && [ -z "$LOCAL_DIR" ]; then
    err "--rt-version requires --version unless an RT artifact is supplied locally"
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

detect_rt_target() {
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)  echo "linux-amd64" ;;
        aarch64|arm64) echo "linux-arm64" ;;
        *) err "Unsupported runtime architecture: $arch"; exit 1 ;;
    esac
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

# ── Temporary workspace ──────────────────────────────────

TMPDIR=$(mktemp -d)

cleanup() {
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

# ── Stop daemon if running ───────────────────────────────

DAEMON_WAS_RUNNING=false
PRESERVED_SYS_CONFIG=""

if [ "$IS_UPDATE" = true ] && daemon_is_running; then
    DAEMON_WAS_RUNNING=true
    stop_daemon
fi

if [ "$IS_UPDATE" = true ]; then
    if [ -f /etc/erlkoenig/sys.config ]; then
        PRESERVED_SYS_CONFIG="/etc/erlkoenig/sys.config"
        info "Using external sys.config: /etc/erlkoenig/sys.config"
    elif [ -f "$PREFIX/releases/start_erl.data" ]; then
        OLD_REL_VSN=$(awk '{print $2}' "$PREFIX/releases/start_erl.data" 2>/dev/null || true)
        if [ -n "$OLD_REL_VSN" ] && [ -f "$PREFIX/releases/$OLD_REL_VSN/sys.config" ]; then
            PRESERVED_SYS_CONFIG="$TMPDIR/sys.config.preserved"
            cp "$PREFIX/releases/$OLD_REL_VSN/sys.config" "$PRESERVED_SYS_CONFIG"
            info "Preserving existing release sys.config"
        fi
    fi
fi

# ── Acquire artifacts ────────────────────────────────────

copy_rt_from_tar() {
    tarball="$1"
    extract_dir="$TMPDIR/rt"

    rm -rf "$extract_dir"
    mkdir -p "$extract_dir"
    if ! tar xzf "$tarball" -C "$extract_dir"; then
        err "erlkoenig_rt tarball is corrupt: $tarball"
        exit 1
    fi

    rt_from_tar=$(find "$extract_dir" -type f -name 'erlkoenig_rt' -print -quit 2>/dev/null || true)
    if [ -z "$rt_from_tar" ]; then
        err "No erlkoenig_rt binary found inside $(basename "$tarball")"
        exit 1
    fi

    cp "$rt_from_tar" "$TMPDIR/erlkoenig_rt"
}

if [ -n "$LOCAL_DIR" ] || [ -n "$ERLKOENIG_TAR" ]; then
    if [ -n "$LOCAL_DIR" ]; then
        info "Installing from local artifacts: $LOCAL_DIR"
    else
        info "Installing from explicit local artifacts"
    fi

    # Find the release tarball
    if [ -n "$ERLKOENIG_TAR" ]; then
        TARBALL="$ERLKOENIG_TAR"
    else
        TARBALL=$(find "$LOCAL_DIR" -type f -name 'erlkoenig-*.tar.gz' -not -name 'static-demo*' -print -quit 2>/dev/null || true)
    fi
    if [ -z "$TARBALL" ]; then
        err "No erlkoenig-*.tar.gz found in $LOCAL_DIR"
        exit 1
    fi

    # Find C runtime
    if [ -n "$RT_BIN" ]; then
        cp "$RT_BIN" "$TMPDIR/erlkoenig_rt"
    elif [ -n "$RT_TAR" ]; then
        copy_rt_from_tar "$RT_TAR"
    elif [ -n "$LOCAL_DIR" ]; then
        FOUND_RT_BIN=$(find "$LOCAL_DIR" -type f \( -name 'erlkoenig_rt' -o -name 'erlkoenig_rt-linux-*' \) -print -quit 2>/dev/null || true)
        if [ -n "$FOUND_RT_BIN" ]; then
            cp "$FOUND_RT_BIN" "$TMPDIR/erlkoenig_rt"
        else
            FOUND_RT_TAR=$(find "$LOCAL_DIR" -type f -name 'erlkoenig_rt-*.tar.gz' -print -quit 2>/dev/null || true)
            if [ -n "$FOUND_RT_TAR" ]; then
                copy_rt_from_tar "$FOUND_RT_TAR"
            else
                err "No erlkoenig_rt binary or erlkoenig_rt-*.tar.gz found in $LOCAL_DIR"
                exit 1
            fi
        fi
    else
        err "--erlkoenig-tar requires --rt-bin, --rt-tar, or --local for the runtime artifact"
        exit 1
    fi

    cp "$TARBALL" "$TMPDIR/erlkoenig-release.tar.gz"

    # Optional: demo binaries
    if [ -n "$LOCAL_DIR" ]; then
        DEMO_TAR=$(find "$LOCAL_DIR" -type f -name 'static-demo-binaries-*.tar.gz' -print -quit 2>/dev/null || true)
        if [ -n "$DEMO_TAR" ]; then
            cp "$DEMO_TAR" "$TMPDIR/static-demo-binaries.tar.gz"
        fi
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

    if [ -n "$RT_BIN" ]; then
        info "Using local C runtime: $RT_BIN"
        cp "$RT_BIN" "$TMPDIR/erlkoenig_rt"
    elif [ -n "$RT_TAR" ]; then
        info "Using local C runtime archive: $RT_TAR"
        copy_rt_from_tar "$RT_TAR"
    else
        RT_VERSION_EFFECTIVE="${RT_VERSION:-$VERSION}"
        RT_TARGET=$(detect_rt_target)
        RT_ARCHIVE="erlkoenig_rt-${RT_VERSION_EFFECTIVE}-${RT_TARGET}.tar.gz"
        RT_URL="https://github.com/${RT_REPO}/releases/download/${RT_VERSION_EFFECTIVE}/${RT_ARCHIVE}"

        info "Downloading ${RT_ARCHIVE} ..."
        if curl -fsSL "$RT_URL" -o "$TMPDIR/erlkoenig_rt.tar.gz"; then
            copy_rt_from_tar "$TMPDIR/erlkoenig_rt.tar.gz"
        elif ! curl -fsSL "https://github.com/${RT_REPO}/releases/download/${RT_VERSION_EFFECTIVE}/erlkoenig_rt-${RT_TARGET}" \
                -o "$TMPDIR/erlkoenig_rt"; then
            err "Failed to download erlkoenig_rt"
            err "Available at: https://github.com/${RT_REPO}/releases/tag/${RT_VERSION_EFFECTIVE}"
            if [ "$DAEMON_WAS_RUNNING" = true ]; then
                warn "Restarting daemon with previous version ..."
                start_daemon
            fi
            exit 1
        fi
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

if [ ! -f /etc/erlkoenig/firewall.term ]; then
    cat > /etc/erlkoenig/firewall.term <<'EOF'
% Minimal Erlkoenig host firewall configuration.
%
% This file is intentionally conservative: it lets the daemon boot with
% an explicit firewall contract and keeps input/forward/output policy at
% accept. Operators should replace it with site policy before relying on
% the host firewall for protection.
#{
    table => <<"erlkoenig_host">>,
    ban_set => #{ipv4 => <<"blocklist">>, ipv6 => <<"blocklist6">>},
    sets => [
        {<<"blocklist">>, ipv4_addr, #{flags => [timeout]}},
        {<<"blocklist6">>, ipv6_addr, #{flags => [timeout]}}
    ],
    counters => [<<"input">>, <<"forward">>, <<"output">>, <<"dropped">>, <<"banned">>],
    chains => [
        #{
            name => <<"prerouting_ban">>,
            hook => prerouting,
            type => filter,
            priority => -300,
            policy => accept,
            rules => [
                {set_lookup_drop, <<"blocklist">>, <<"banned">>},
                {set_lookup_drop, <<"blocklist6">>, <<"banned">>}
            ]
        },
        #{name => <<"input">>, hook => input, type => filter, priority => 0, policy => accept, rules => []},
        #{name => <<"forward">>, hook => forward, type => filter, priority => 0, policy => accept, rules => []},
        #{name => <<"output">>, hook => output, type => filter, priority => 0, policy => accept, rules => []}
    ]
}.
EOF
    chmod 640 /etc/erlkoenig/firewall.term
    chown root:"$SERVICE_USER" /etc/erlkoenig/firewall.term 2>/dev/null || chown root:root /etc/erlkoenig/firewall.term
    ok "Default firewall config: /etc/erlkoenig/firewall.term"
else
    info "Keeping existing firewall config: /etc/erlkoenig/firewall.term"
fi

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

if [ -n "$PRESERVED_SYS_CONFIG" ] && [ -f "$PRESERVED_SYS_CONFIG" ]; then
    REL_VSN_FOR_CONFIG=$(awk '{print $2}' "$PREFIX/releases/start_erl.data" 2>/dev/null || true)
    if [ -n "$REL_VSN_FOR_CONFIG" ] && [ -d "$PREFIX/releases/$REL_VSN_FOR_CONFIG" ]; then
        cp "$PRESERVED_SYS_CONFIG" "$PREFIX/releases/$REL_VSN_FOR_CONFIG/sys.config"
        chmod 640 "$PREFIX/releases/$REL_VSN_FOR_CONFIG/sys.config"
        ok "Preserved sys.config: $PREFIX/releases/$REL_VSN_FOR_CONFIG/sys.config"
        if [ "$PRESERVED_SYS_CONFIG" != "/etc/erlkoenig/sys.config" ] && [ ! -f /etc/erlkoenig/sys.config ]; then
            cp "$PRESERVED_SYS_CONFIG" /etc/erlkoenig/sys.config
            chmod 640 /etc/erlkoenig/sys.config
            chown root:"$SERVICE_USER" /etc/erlkoenig/sys.config 2>/dev/null || chown root:root /etc/erlkoenig/sys.config
            ok "External sys.config: /etc/erlkoenig/sys.config"
        fi
    fi
fi

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

mkdir -p /etc/erlkoenig
COOKIE_FILE="/etc/erlkoenig/cookie"
LEGACY_COOKIE_FILE="$PREFIX/cookie"

if [ ! -f "$COOKIE_FILE" ]; then
    if [ -f "$LEGACY_COOKIE_FILE" ] && [ ! -L "$LEGACY_COOKIE_FILE" ]; then
        cp "$LEGACY_COOKIE_FILE" "$COOKIE_FILE"
        ok "Cookie migrated: $LEGACY_COOKIE_FILE -> $COOKIE_FILE"
    else
        head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32 > "$COOKIE_FILE"
        ok "Cookie generated: $COOKIE_FILE"
    fi
fi
chmod 440 "$COOKIE_FILE"
chown root:"$SERVICE_USER" "$COOKIE_FILE"

if [ -e "$LEGACY_COOKIE_FILE" ] || [ -L "$LEGACY_COOKIE_FILE" ]; then
    if [ ! -L "$LEGACY_COOKIE_FILE" ] || [ "$(readlink "$LEGACY_COOKIE_FILE" 2>/dev/null || true)" != "$COOKIE_FILE" ]; then
        rm -f "$LEGACY_COOKIE_FILE"
    fi
fi
ln -s "$COOKIE_FILE" "$LEGACY_COOKIE_FILE" 2>/dev/null || true
ok "Cookie source: $COOKIE_FILE ($LEGACY_COOKIE_FILE symlink)"

if [ -f /root/.erlang.cookie ]; then
    warn "/root/.erlang.cookie exists but is ignored; erlkoenig uses $COOKIE_FILE"
fi

# ── Fix hostname resolution for epmd ────────────────────
# Debian cloud images set hostname to 127.0.1.1 in /etc/hosts.
# epmd binds to 127.0.0.1 — the mismatch prevents CLI from
# connecting to the running node. Fix if needed.

HOSTNAME=$(hostname)
if grep -q "127\.0\.1\.1.*$HOSTNAME" /etc/hosts 2>/dev/null; then
    if [ "$FIX_HOSTS" = true ]; then
        sed -i "s/127\.0\.1\.1\(.*$HOSTNAME\)/127.0.0.1\1/" /etc/hosts
        ok "Fixed /etc/hosts: $HOSTNAME -> 127.0.0.1 (was 127.0.1.1)"
    else
        warn "/etc/hosts maps $HOSTNAME to 127.0.1.1; Erlang distribution may be unreachable"
        warn "Re-run with --fix-hosts to rewrite that entry to 127.0.0.1"
    fi
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
