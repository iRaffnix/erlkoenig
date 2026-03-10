#!/bin/sh
# Erlkoenig-RT Install Script
# Usage: sudo ./install.sh [PREFIX]
#
# Installs erlkoenig_rt + demo binaries and sets Linux capabilities.
# Default prefix: /usr/local
#
# After install, see GETTING_STARTED.md for next steps.

set -e

PREFIX="${1:-/usr/local}"
INSTALL_DIR="${PREFIX}/lib/erlkoenig"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must run as root (need setcap)" >&2
    exit 1
fi

if [ ! -f "${SCRIPT_DIR}/erlkoenig_rt" ]; then
    echo "Error: erlkoenig_rt not found in ${SCRIPT_DIR}" >&2
    echo "" >&2
    echo "Expected layout:" >&2
    echo "  ${SCRIPT_DIR}/erlkoenig_rt" >&2
    echo "  ${SCRIPT_DIR}/demo/test-erlkoenig-*  (optional)" >&2
    echo "" >&2
    echo "Build first: make rt" >&2
    exit 1
fi

echo "Installing erlkoenig_rt to ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"
cp "${SCRIPT_DIR}/erlkoenig_rt" "${INSTALL_DIR}/erlkoenig_rt"
chmod 755 "${INSTALL_DIR}/erlkoenig_rt"

if [ -f "${SCRIPT_DIR}/VERSION" ]; then
    cp "${SCRIPT_DIR}/VERSION" "${INSTALL_DIR}/VERSION"
fi

echo "Setting capabilities..."
setcap cap_sys_admin,cap_net_admin,cap_sys_chroot,cap_sys_ptrace,cap_setpcap,cap_setuid,cap_setgid,cap_dac_override+ep \
    "${INSTALL_DIR}/erlkoenig_rt"

# Demo binaries (fuer Getting Started / Tests)
if [ -d "${SCRIPT_DIR}/demo" ]; then
    echo "Installing demo binaries..."
    mkdir -p "${INSTALL_DIR}/demo"
    cp "${SCRIPT_DIR}"/demo/test-erlkoenig-* "${INSTALL_DIR}/demo/" 2>/dev/null || true
    chmod 755 "${INSTALL_DIR}/demo/"* 2>/dev/null || true
fi

echo ""
echo "Done."
echo "  erlkoenig_rt:  ${INSTALL_DIR}/erlkoenig_rt"
if [ -d "${INSTALL_DIR}/demo" ]; then
    DEMO_COUNT=$(ls "${INSTALL_DIR}/demo/" 2>/dev/null | wc -l)
    echo "  demo binaries: ${INSTALL_DIR}/demo/ (${DEMO_COUNT} files)"
fi
echo ""
echo "Next: see GETTING_STARTED.md"
