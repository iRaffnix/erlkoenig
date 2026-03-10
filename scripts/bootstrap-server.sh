#
# Copyright 2026 Erlkoenig Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#!/bin/bash
# bootstrap-server.sh — Frischen Server fuer Erlkoenig vorbereiten
#
# Laeuft als root auf dem Zielserver. Macht:
#   1. Pakete installieren (setcap-Tool)
#   2. User erlkoenig anlegen
#   3. SSH-Key deployen (fuer root + erlkoenig)
#   4. Verzeichnisse anlegen
#   5. Kernel-Parameter setzen
#   6. SELinux konfigurieren (Rocky/RHEL)
#
# Unterstuetzt: Debian/Ubuntu, Rocky/RHEL/CentOS/Fedora
#
# Usage:
#   ssh root@SERVER 'bash -s' < scripts/bootstrap-server.sh

set -euo pipefail

PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICY8PU7zt07TGXztiqtBIsAm6x0YKnsHRR/O86mQuzTt erlkoenig@debian-8gb-nbg1-1"

echo ""
echo "=== Erlkoenig Server Bootstrap ==="
echo ""

# ── Distribution erkennen ────────────────────────────────

if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO_FAMILY="unknown"
    case "$ID" in
        debian|ubuntu|linuxmint) DISTRO_FAMILY="debian" ;;
        rocky|rhel|centos|fedora|alma) DISTRO_FAMILY="rhel" ;;
        alpine) DISTRO_FAMILY="alpine" ;;
        arch|manjaro) DISTRO_FAMILY="arch" ;;
    esac
    echo "  Distribution: $PRETTY_NAME ($DISTRO_FAMILY)"
else
    DISTRO_FAMILY="unknown"
    echo "  WARN: /etc/os-release nicht gefunden"
fi

# ── 1. Pakete ───────────────────────────────────────────

echo ""
echo "--- Pakete ---"

case "$DISTRO_FAMILY" in
    debian)
        apt-get update -qq
        apt-get install -y -qq libcap2-bin > /dev/null
        echo "  OK   libcap2-bin installiert (setcap)"
        ;;
    rhel)
        dnf install -y -q libcap > /dev/null 2>&1
        echo "  OK   libcap installiert (setcap)"
        ;;
    alpine)
        apk add --quiet libcap-utils
        echo "  OK   libcap-utils installiert (setcap)"
        ;;
    *)
        if command -v setcap >/dev/null 2>&1; then
            echo "  OK   setcap bereits verfuegbar"
        else
            echo "  WARN setcap nicht gefunden — manuell installieren"
        fi
        ;;
esac

# ── 2. User erlkoenig ──────────────────────────────────

echo ""
echo "--- User ---"

if id erlkoenig &>/dev/null; then
    echo "  OK   User erlkoenig existiert bereits"
else
    useradd --system --create-home --shell /bin/bash erlkoenig
    echo "  OK   User erlkoenig angelegt"
fi

# ── 3. SSH-Keys ────────────────────────────────────────

echo ""
echo "--- SSH Keys ---"

# Root
mkdir -p /root/.ssh
chmod 700 /root/.ssh
if ! grep -qF "$PUBKEY" /root/.ssh/authorized_keys 2>/dev/null; then
    echo "$PUBKEY" >> /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    echo "  OK   SSH key fuer root hinzugefuegt"
else
    echo "  OK   SSH key fuer root bereits vorhanden"
fi

# erlkoenig
EK_HOME=$(eval echo ~erlkoenig)
mkdir -p "$EK_HOME/.ssh"
chmod 700 "$EK_HOME/.ssh"
if ! grep -qF "$PUBKEY" "$EK_HOME/.ssh/authorized_keys" 2>/dev/null; then
    echo "$PUBKEY" >> "$EK_HOME/.ssh/authorized_keys"
    chmod 600 "$EK_HOME/.ssh/authorized_keys"
    echo "  OK   SSH key fuer erlkoenig hinzugefuegt"
else
    echo "  OK   SSH key fuer erlkoenig bereits vorhanden"
fi
chown -R erlkoenig:erlkoenig "$EK_HOME/.ssh"

# ── 4. Verzeichnisse ──────────────────────────────────

echo ""
echo "--- Verzeichnisse ---"

mkdir -p /opt/erlkoenig
chown erlkoenig:erlkoenig /opt/erlkoenig
echo "  OK   /opt/erlkoenig (owner: erlkoenig)"

mkdir -p /etc/erlkoenig
chown erlkoenig:erlkoenig /etc/erlkoenig
chmod 700 /etc/erlkoenig
echo "  OK   /etc/erlkoenig (owner: erlkoenig, 700)"

mkdir -p /usr/lib/erlkoenig
echo "  OK   /usr/lib/erlkoenig (owner: root)"

mkdir -p /etc/bash_completion.d
echo "  OK   /etc/bash_completion.d"

# ── 5. Kernel-Parameter ───────────────────────────────

echo ""
echo "--- Kernel ---"

# Unprivileged user namespaces
USERNS=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo "1")
if [ "$USERNS" = "1" ]; then
    echo "  OK   kernel.unprivileged_userns_clone=1"
else
    sysctl -w kernel.unprivileged_userns_clone=1
    echo "kernel.unprivileged_userns_clone=1" >> /etc/sysctl.d/99-erlkoenig.conf
    echo "  OK   kernel.unprivileged_userns_clone=1 (gesetzt)"
fi

# IP forwarding (fuer Container-Networking)
FWD=$(sysctl -n net.ipv4.ip_forward)
if [ "$FWD" = "1" ]; then
    echo "  OK   net.ipv4.ip_forward=1"
else
    sysctl -w net.ipv4.ip_forward=1
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.d/99-erlkoenig.conf
    echo "  OK   net.ipv4.ip_forward=1 (gesetzt)"
fi

# Hostname muss auf 127.0.0.1 zeigen (nicht 127.0.1.1).
# Debian-Default ist 127.0.1.1, Rocky ist 127.0.0.1.
# Erlang Distribution bindet auf 127.0.0.1 — Mismatch bricht erl_call.
HOSTNAME=$(hostname)
if getent hosts "$HOSTNAME" | grep -q '^127\.0\.0\.1'; then
    echo "  OK   $HOSTNAME resolves to 127.0.0.1"
elif getent hosts "$HOSTNAME" | grep -q '^127\.0\.1\.1'; then
    sed -i "s/127\.0\.1\.1\(\s\)/127.0.0.1\1/" /etc/hosts
    echo "  OK   fixed $HOSTNAME: 127.0.1.1 -> 127.0.0.1 in /etc/hosts"
else
    echo "  OK   $HOSTNAME resolves to $(getent hosts "$HOSTNAME" | awk '{print $1}')"
fi

# ── 6. SELinux (Rocky/RHEL) ──────────────────────────

echo ""
echo "--- SELinux ---"

if command -v getenforce >/dev/null 2>&1; then
    SELINUX_MODE=$(getenforce)
    echo "  INFO SELinux mode: $SELINUX_MODE"

    # Labels fuer erlkoenig-Binaries setzen
    if command -v semanage >/dev/null 2>&1; then
        semanage fcontext -a -t bin_t "/usr/lib/erlkoenig(/.*)?" 2>/dev/null || true
        restorecon -Rv /usr/lib/erlkoenig 2>/dev/null || true
        echo "  OK   SELinux labels fuer /usr/lib/erlkoenig gesetzt (bin_t)"

        semanage fcontext -a -t usr_t "/opt/erlkoenig(/.*)?" 2>/dev/null || true
        restorecon -Rv /opt/erlkoenig 2>/dev/null || true
        echo "  OK   SELinux labels fuer /opt/erlkoenig gesetzt (usr_t)"
    else
        echo "  WARN semanage nicht verfuegbar — SELinux-Labels manuell setzen"
        echo "       dnf install policycoreutils-python-utils"
    fi

    if [ "$SELINUX_MODE" = "Enforcing" ]; then
        echo "  WARN SELinux ist Enforcing — erlkoenig braucht evtl. eine Policy."
        echo "       Falls Probleme: setenforce 0 (temporaer) oder"
        echo "       audit2allow -a -M erlkoenig && semodule -i erlkoenig.pp"
    fi
else
    echo "  OK   SELinux nicht aktiv"
fi

# ── 7. Firewall (Rocky/RHEL) ─────────────────────────

echo ""
echo "--- Firewall ---"

if command -v firewall-cmd >/dev/null 2>&1; then
    if systemctl is-active --quiet firewalld; then
        echo "  WARN firewalld ist aktiv"
        echo "       erlkoenig_nft schreibt direkte nftables-Regeln."
        echo "       Option 1: systemctl disable --now firewalld"
        echo "       Option 2: firewalld Regeln fuer erlkoenig Bridge konfigurieren"
    else
        echo "  OK   firewalld nicht aktiv"
    fi
else
    echo "  OK   firewalld nicht installiert"
fi

# ── Ergebnis ──────────────────────────────────────────

echo ""
echo "==========================================="
echo "  Server bereit fuer: make deploy"
echo "    HOST_ROOT=root@$(hostname)"
echo "    HOST_ERL=erlkoenig@$(hostname)"
echo "==========================================="
echo ""
