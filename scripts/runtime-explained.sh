#!/bin/bash
#
# erlkoenig Runtime — erklärt in Bash
#
# Dies ist KEINE Produktions-Runtime. Es ist eine pädagogische Version
# die zeigt, was die 68 KB C-Runtime (erlkoenig_rt) unter der Haube macht.
#
# Fehlende Features gegenüber der echten Runtime:
#   - Kein Seccomp (braucht BPF-Programm, geht nicht in Bash)
#   - Kein Capability-Drop (braucht capset() Syscall)
#   - Kein Binary-via-FD (TOCTOU-Schutz)
#   - Kein Error-Pipe (saubere Fehlerweiterleitung)
#   - Langsamer (~500ms statt 67ms)
#
# Usage: sudo bash runtime-explained.sh <binary> <ip> [args...]
#
# Beispiel:
#   sudo bash runtime-explained.sh /tmp/echo-server 10.0.0.5 8080
#
set -euo pipefail

BINARY="$1"
IP="$2"
shift 2
ARGS="$@"

GATEWAY="10.0.0.1"
NETMASK="24"
BRIDGE="erlkoenig_br0"
ID=$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 12)
ROOTFS="/tmp/erlkoenig-$ID"
VETH_HOST="vh_$ID"
VETH_CONT="vp_$ID"

echo "erlkoenig runtime (bash) — pädagogische Version"
echo ""
echo "  Binary:  $BINARY"
echo "  IP:      $IP/$NETMASK"
echo "  ID:      $ID"
echo ""

# ══════════════════════════════════════════════════════════════
# Schritt 1: Rootfs vorbereiten (tmpfs)
# ══════════════════════════════════════════════════════════════
#
# Jeder Container bekommt sein eigenes Dateisystem im RAM.
# Kein Docker-Image, kein Layer, kein Registry.
# Nur ein leeres tmpfs mit dem Binary drin.

echo "[1/7] Rootfs vorbereiten ..."

mkdir -p "$ROOTFS"
mount -t tmpfs -o size=64M tmpfs "$ROOTFS"

# Minimale Verzeichnisstruktur
mkdir -p "$ROOTFS/proc"
mkdir -p "$ROOTFS/tmp"
mkdir -p "$ROOTFS/dev"

# Binary reinkopieren
cp "$BINARY" "$ROOTFS/binary"
chmod 755 "$ROOTFS/binary"

echo "       tmpfs: $ROOTFS (64 MB)"

# ══════════════════════════════════════════════════════════════
# Schritt 2: Namespaces erstellen (unshare)
# ══════════════════════════════════════════════════════════════
#
# Die echte Runtime nutzt clone() mit 5 Namespace-Flags.
# In Bash nutzen wir 'unshare' — das Gleiche, nur als Command.
#
# PID  — Container sieht nur eigene Prozesse
# NET  — Eigenes Netzwerk (eigene IP, eigene Ports)
# MNT  — Eigenes Dateisystem (schreibgeschützt)
# UTS  — Eigener Hostname
# IPC  — Eigene Interprozesskommunikation

echo "[2/7] Namespaces erstellen (PID, NET, MNT, UTS, IPC) ..."

# Wir starten den Container-Prozess in neuen Namespaces.
# unshare --fork: startet einen neuen Prozess
# --pid:   neuer PID-Namespace (Container ist PID 1)
# --net:   neues Netzwerk (leer, keine Interfaces)
# --mount: neue Mount-Tabelle (eigene Sicht auf Dateisystem)
# --uts:   eigener Hostname
# --ipc:   eigene Shared-Memory-Segmente

unshare --fork --pid --net --mount --uts --ipc \
  bash -c "
    # ══════════════════════════════════════════════════════════
    # Schritt 3: pivot_root (Dateisystem wechseln)
    # ══════════════════════════════════════════════════════════
    #
    # Das Container-Rootfs wird zum neuen Root-Verzeichnis.
    # Nach pivot_root sieht der Container das Host-Dateisystem
    # nicht mehr. Er sieht nur sein tmpfs.

    # Mount-Propagation stoppen (damit unsere Mounts nicht nach außen leaken)
    mount --make-rprivate /

    # tmpfs als neues Root einbinden
    mount --bind $ROOTFS $ROOTFS
    cd $ROOTFS
    mkdir -p .old_root
    pivot_root . .old_root

    # Altes Root aushängen — das Host-Dateisystem ist jetzt unsichtbar
    umount -l /.old_root
    rmdir /.old_root

    # /proc mounten (für PID 1 im neuen Namespace)
    mount -t proc proc /proc

    # ══════════════════════════════════════════════════════════
    # Schritt 4: /proc maskieren
    # ══════════════════════════════════════════════════════════
    #
    # Sensible Kernel-Informationen verstecken.
    # OCI-konform: kmod, timer_list, sched_debug etc.
    # Ohne das könnte der Container Kernel-Parameter lesen.

    mount --bind /dev/null /proc/kcore 2>/dev/null || true
    mount --bind /dev/null /proc/timer_list 2>/dev/null || true
    mount --bind /dev/null /proc/sched_debug 2>/dev/null || true

    # ══════════════════════════════════════════════════════════
    # Schritt 5: Rootfs schreibgeschützt machen
    # ══════════════════════════════════════════════════════════
    #
    # Nach dem Setup wird das Root-Dateisystem read-only remountet.
    # Der Container kann keine Dateien verändern.
    # Nur /tmp bleibt beschreibbar (für temporäre Daten).

    mount -t tmpfs tmpfs /tmp
    mount -o remount,ro /

    # Hostname setzen
    hostname erlkoenig-$ID

    echo '       PID 1 im Container, Rootfs schreibgeschützt'

    # ══════════════════════════════════════════════════════════
    # Schritt 6: Binary starten (exec)
    # ══════════════════════════════════════════════════════════
    #
    # exec ersetzt den aktuellen Prozess durch das Binary.
    # Kein Shell-Prozess bleibt übrig — nur das Binary läuft.
    #
    # In der echten Runtime passiert hier vorher noch:
    #   - Seccomp-Filter anwenden (60 von 300 Syscalls erlaubt)
    #   - Alle 41 Capabilities entfernen
    #   - DNS-IP injizieren
    # Das geht in Bash nicht.

    exec /binary $ARGS
  " &

CHILD_PID=$!
sleep 0.5

# ══════════════════════════════════════════════════════════════
# Schritt 6: Netzwerk einrichten (veth + bridge)
# ══════════════════════════════════════════════════════════════
#
# Die echte Runtime macht das über pure Netlink-Sockets.
# Hier nutzen wir 'ip' Commands — gleiche Wirkung, langsamer.
#
# veth-Paar: zwei virtuelle Netzwerk-Interfaces die wie ein Kabel
# verbunden sind. Ein Ende im Host, ein Ende im Container.

echo "[6/7] Netzwerk einrichten ..."

# Bridge erstellen (falls nicht vorhanden)
if ! ip link show "$BRIDGE" &>/dev/null; then
    ip link add "$BRIDGE" type bridge
    ip addr add "$GATEWAY/$NETMASK" dev "$BRIDGE"
    ip link set "$BRIDGE" up
    echo "       Bridge: $BRIDGE ($GATEWAY)"
fi

# veth-Paar erstellen
ip link add "$VETH_HOST" type veth peer name "$VETH_CONT"

# Host-Ende an Bridge anschließen
ip link set "$VETH_HOST" master "$BRIDGE"
ip link set "$VETH_HOST" up

# Container-Ende in den Netzwerk-Namespace des Containers verschieben
ip link set "$VETH_CONT" netns "$CHILD_PID"

# Im Container: Interface konfigurieren
nsenter -t "$CHILD_PID" -n ip link set lo up
nsenter -t "$CHILD_PID" -n ip link set "$VETH_CONT" up
nsenter -t "$CHILD_PID" -n ip addr add "$IP/$NETMASK" dev "$VETH_CONT"
nsenter -t "$CHILD_PID" -n ip route add default via "$GATEWAY"

echo "       veth: $VETH_HOST <-> $VETH_CONT"
echo "       IP:   $IP/$NETMASK via $GATEWAY"

# ══════════════════════════════════════════════════════════════
# Schritt 7: Fertig
# ══════════════════════════════════════════════════════════════

echo "[7/7] Container läuft"
echo ""
echo "  PID:       $CHILD_PID"
echo "  IP:        $IP"
echo "  Hostname:  erlkoenig-$ID"
echo "  Rootfs:    schreibgeschützt (tmpfs)"
echo "  Namespaces: PID, NET, MNT, UTS, IPC"
echo ""
echo "  Was FEHLT (nur in der echten C-Runtime):"
echo "    - Seccomp: 60 von 300 Syscalls erlaubt"
echo "    - Capabilities: alle 41 entfernt"
echo "    - Binary-Signatur: Ed25519 + X.509"
echo "    - Firewall: per-Container nftables"
echo "    - Audit-Log: jede Aktion geloggt"
echo ""
echo "  Testen:  curl http://$IP:${ARGS%% *} (falls ein Server läuft)"
echo "  Stoppen: kill $CHILD_PID"
echo ""

# Aufräumen wenn der Container stirbt
cleanup() {
    echo ""
    echo "Container gestoppt. Aufräumen ..."
    ip link del "$VETH_HOST" 2>/dev/null || true
    umount -l "$ROOTFS" 2>/dev/null || true
    rmdir "$ROOTFS" 2>/dev/null || true
    echo "Fertig."
}
trap cleanup EXIT

# Warten bis der Container-Prozess endet
wait "$CHILD_PID" 2>/dev/null || true
