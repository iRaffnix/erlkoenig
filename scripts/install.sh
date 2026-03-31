#!/bin/sh
# install.sh — Install/uninstall erlkoenig OTP release.
#
# Installs:
#   /opt/erlkoenig/              OTP release (ERTS + compiled modules)
#   /opt/erlkoenig/cookie        Erlang distribution cookie
#   /opt/erlkoenig/etc/          Config directory (firewall.term, etc.)
#   /etc/systemd/system/         systemd unit (symlink)
#   /usr/lib/erlkoenig/          C runtime binaries (if present)
#
# Usage:
#   sudo ./scripts/install.sh [--prefix /opt/erlkoenig] [--uninstall]

set -eu

PREFIX="/opt/erlkoenig"
ACTION="install"
SERVICE_USER="erlkoenig"
SRCDIR="$(cd "$(dirname "$0")/.." && pwd)"

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)    PREFIX="$2"; shift 2 ;;
        --uninstall) ACTION="uninstall"; shift ;;
        --help)      usage; exit 0 ;;
        *)           echo "Unknown: $1"; exit 1 ;;
    esac
done

[ "$(id -u)" = "0" ] || { echo "Error: must run as root"; exit 1; }

TARBALL=$(ls "$SRCDIR"/_build/prod/rel/erlkoenig/erlkoenig-*.tar.gz 2>/dev/null | head -1)

usage() {
    echo "Usage: sudo $0 [--prefix DIR] [--uninstall]"
}

do_install() {
    echo "Installing erlkoenig to $PREFIX ..."

    # Verify tarball exists
    if [ -z "$TARBALL" ] || [ ! -f "$TARBALL" ]; then
        echo "ERROR: Release tarball not found."
        echo "       Run 'rebar3 as prod tar' first."
        exit 1
    fi

    # Service group (shared with erlkoenig_rt, erlkoenig_ebpfd)
    if ! getent group "$SERVICE_USER" >/dev/null 2>&1; then
        groupadd --system "$SERVICE_USER"
        echo "  Created group: $SERVICE_USER"
    fi

    # Check if this is an update
    IS_UPDATE=false
    if [ -d "$PREFIX/releases" ]; then
        IS_UPDATE=true
        echo "  Detected existing installation — updating"

        # Stop daemon if running
        if systemctl is-active --quiet erlkoenig 2>/dev/null; then
            systemctl stop erlkoenig
            echo "  Stopped running daemon"
        fi

        # Preserve cookie across updates
        if [ -f "$PREFIX/cookie" ]; then
            cp "$PREFIX/cookie" /tmp/erlkoenig_cookie_preserve
        fi

        # Clean old ERTS/lib (prevents version conflicts)
        rm -rf "${PREFIX:?}/bin" "${PREFIX:?}/erts-"* "${PREFIX:?}/lib" \
               "${PREFIX:?}/releases" "${PREFIX:?}/dist"
        echo "  Cleaned old release files"
    fi

    # Extract tarball
    mkdir -p "$PREFIX"
    tar xzf "$TARBALL" -C "$PREFIX"
    echo "  Extracted release to $PREFIX"

    # Restore preserved cookie
    if [ -f /tmp/erlkoenig_cookie_preserve ]; then
        cp /tmp/erlkoenig_cookie_preserve "$PREFIX/cookie"
        rm -f /tmp/erlkoenig_cookie_preserve
        echo "  Restored existing cookie"
    fi

    # Generate cookie if first install
    if [ ! -f "$PREFIX/cookie" ]; then
        head -c 32 /dev/urandom | base64 | tr -d '/+=\n' | head -c 32 > "$PREFIX/cookie"
        echo "  Generated new cookie"
    fi

    # File ownership
    chown -R root:"$SERVICE_USER" "$PREFIX"
    chmod 750 "$PREFIX"
    chown root:"$SERVICE_USER" "$PREFIX/cookie"
    chmod 440 "$PREFIX/cookie"

    # vm.args — relx generates this at startup from vm.args.src
    REL_VSN_DIR=$(ls -d "$PREFIX"/releases/*/start.boot 2>/dev/null | head -1 | xargs dirname 2>/dev/null)
    if [ -n "$REL_VSN_DIR" ]; then
        # vm.args.src is root-owned, read-only
        [ -f "$REL_VSN_DIR/vm.args.src" ] && \
            chown root:"$SERVICE_USER" "$REL_VSN_DIR/vm.args.src" && \
            chmod 440 "$REL_VSN_DIR/vm.args.src"

        # vm.args is generated at startup — service user must be able to write
        touch "$REL_VSN_DIR/vm.args"
        chown "$SERVICE_USER":"$SERVICE_USER" "$REL_VSN_DIR/vm.args" 2>/dev/null || \
            chown root:"$SERVICE_USER" "$REL_VSN_DIR/vm.args"
        chmod 640 "$REL_VSN_DIR/vm.args"

        # sys.config is root-owned, read-only
        [ -f "$REL_VSN_DIR/sys.config" ] && \
            chown root:"$SERVICE_USER" "$REL_VSN_DIR/sys.config" && \
            chmod 440 "$REL_VSN_DIR/sys.config"

        echo "  Configured release directory permissions"
    fi

    # Config directory
    mkdir -p "$PREFIX/etc"
    chown root:"$SERVICE_USER" "$PREFIX/etc"
    chmod 750 "$PREFIX/etc"
    if [ ! -e /etc/erlkoenig ]; then
        ln -s "$PREFIX/etc" /etc/erlkoenig
        echo "  Symlinked /etc/erlkoenig -> $PREFIX/etc"
    fi

    # Install wrapper: rename relx script → _release, install wrapper as erlkoenig
    if [ -f "$PREFIX/bin/erlkoenig" ]; then
        mv "$PREFIX/bin/erlkoenig" "$PREFIX/bin/_release"
        chmod 755 "$PREFIX/bin/_release"
    fi
    cp "$SRCDIR/bin/erlkoenig_wrapper.sh" "$PREFIX/bin/erlkoenig"
    chmod 755 "$PREFIX/bin/erlkoenig"
    echo "  Installed cookie wrapper (bin/erlkoenig → bin/_release)"

    # Systemd
    if [ -d /etc/systemd/system ]; then
        # Create service unit for the OTP release
        cat > /etc/systemd/system/erlkoenig.service << UNIT
[Unit]
Description=Erlkoenig Container Runtime
After=network.target

[Service]
Type=simple
User=root
Group=$SERVICE_USER

Environment=ERL_EPMD_ADDRESS=127.0.0.1
Environment=ERL_EPMD_PORT=4369

ExecStart=$PREFIX/bin/erlkoenig foreground

KillSignal=SIGTERM
TimeoutStopSec=30

Restart=on-failure
RestartSec=5

RuntimeDirectory=erlkoenig
RuntimeDirectoryMode=0770

LimitNOFILE=65536
LimitMEMLOCK=infinity

AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE CAP_KILL

ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
UNIT
        systemctl daemon-reload
        echo "  Systemd unit created"
    fi

    # Hostname check (Erlang distribution needs resolvable hostname)
    if ! getent hosts "$(hostname -s)" >/dev/null 2>&1; then
        echo ""
        echo "  WARNING: hostname '$(hostname -s)' not resolvable."
        echo "  Add to /etc/hosts: 127.0.0.1 $(hostname -s)"
        echo ""
    fi

    echo ""
    echo "Done. Start with:"
    echo "  sudo systemctl start erlkoenig"
    echo ""
    echo "Or manually:"
    echo "  export RELX_COOKIE=\"\$(cat $PREFIX/cookie)\""
    echo "  $PREFIX/bin/erlkoenig foreground"
}

do_uninstall() {
    echo "Uninstalling erlkoenig from $PREFIX ..."

    if systemctl is-active --quiet erlkoenig 2>/dev/null; then
        systemctl stop erlkoenig
        echo "  Stopped daemon"
    fi
    systemctl disable erlkoenig 2>/dev/null || true

    rm -f /etc/systemd/system/erlkoenig.service
    [ -L /etc/erlkoenig ] && rm -f /etc/erlkoenig
    systemctl daemon-reload 2>/dev/null || true

    rm -rf "$PREFIX"
    echo "  Removed $PREFIX"
    echo "Done. Group '$SERVICE_USER' preserved."
}

case "$ACTION" in
    install)   do_install ;;
    uninstall) do_uninstall ;;
esac
