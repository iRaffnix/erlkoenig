#!/bin/sh
# Manual installer smoke test.
#
# Intended for a fresh Linux VM/LXC such as erlkoenig-2 before and after
# install.sh changes. This is not wired into CI because it needs root,
# systemd/cgroup support, and a real local artifact bundle.

set -eu

ARTIFACTS=""
PREFIX="${PREFIX:-/opt/erlkoenig}"
INSTALL_SH="${INSTALL_SH:-./install.sh}"
SERVICE="${SERVICE:-erlkoenig}"

usage() {
    cat <<EOF
Usage: sudo sh tests/install/test-install-smoke.sh --artifacts DIR [OPTIONS]

Options:
  --artifacts DIR     Directory containing erlkoenig + erlkoenig_rt artifacts
  --prefix DIR        Install prefix (default: /opt/erlkoenig)
  --install-sh PATH   Installer path (default: ./install.sh)
  --service NAME      systemd service name (default: erlkoenig)
  --help              Show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --artifacts)  ARTIFACTS="$2"; shift 2 ;;
        --prefix)     PREFIX="$2"; shift 2 ;;
        --install-sh) INSTALL_SH="$2"; shift 2 ;;
        --service)    SERVICE="$2"; shift 2 ;;
        --help|-h)    usage; exit 0 ;;
        *)            echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

[ "$(id -u)" = "0" ] || { echo "error: run as root" >&2; exit 1; }
[ -n "$ARTIFACTS" ] || { echo "error: --artifacts DIR is required" >&2; exit 2; }
[ -d "$ARTIFACTS" ] || { echo "error: artifacts dir not found: $ARTIFACTS" >&2; exit 1; }
[ -f "$INSTALL_SH" ] || { echo "error: installer not found: $INSTALL_SH" >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "error: systemctl is required for this smoke test" >&2; exit 1; }

echo "==> install from local artifacts"
sh "$INSTALL_SH" --local "$ARTIFACTS" --prefix "$PREFIX" --force

echo "==> start service"
systemctl daemon-reload
systemctl restart "$SERVICE"

echo "==> wait for service"
i=0
while [ "$i" -lt 30 ]; do
    if systemctl is-active --quiet "$SERVICE"; then
        break
    fi
    i=$((i + 1))
    sleep 1
done
systemctl is-active --quiet "$SERVICE"
systemctl --no-pager --full status "$SERVICE"

EK="$PREFIX/bin/ek"
[ -x "$EK" ] || { echo "error: ek CLI not executable at $EK" >&2; exit 1; }

echo "==> ek node ping (with retry; Erlang distribution needs a few seconds after systemd starts the process)"
i=0
while [ "$i" -lt 30 ]; do
    if "$EK" node ping >/dev/null 2>&1; then
        break
    fi
    i=$((i + 1))
    sleep 1
done
"$EK" node ping

echo "==> ek ps"
"$EK" ps

echo "install smoke: OK"
