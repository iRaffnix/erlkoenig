#!/bin/bash
# vm-backup.sh — Backup erlkoenig VM state before OS reinstall.
#
# Usage: ./scripts/vm-backup.sh [ssh-host]
#   Default host: erlkoenig-2__root
#
# Saves to: /tmp/erlkoenig-vm-backup/

set -eu

HOST="${1:-erlkoenig-2__root}"
BACKUP_DIR="/tmp/erlkoenig-vm-backup"

mkdir -p "$BACKUP_DIR"

echo "Backing up $HOST → $BACKUP_DIR"

# 1. SSH authorized_keys
echo "[1/5] SSH keys..."
scp "$HOST":/root/.ssh/authorized_keys "$BACKUP_DIR/authorized_keys"

# 2. PKI certificates + keys
echo "[2/5] PKI certificates..."
scp -r "$HOST":/etc/erlkoenig/ca/ "$BACKUP_DIR/ca/"

# 3. systemd unit
echo "[3/5] systemd unit..."
scp "$HOST":/etc/systemd/system/erlkoenig.service "$BACKUP_DIR/erlkoenig.service"

# 4. sys.config (contains AMQP credentials, limits, etc.)
echo "[4/5] sys.config..."
REL_DIR=$(ssh "$HOST" 'ls -d /opt/erlkoenig/releases/*/start.boot 2>/dev/null | head -1 | xargs dirname' 2>/dev/null) && \
  scp "$HOST":"$REL_DIR/sys.config" "$BACKUP_DIR/sys.config" || echo "  skipped (no release)"

# 5. hostname + network info
echo "[5/5] Host info..."
ssh "$HOST" 'hostname && ip -4 addr show eth0 2>/dev/null | grep inet' > "$BACKUP_DIR/host-info.txt"

echo ""
echo "Backup complete:"
ls -la "$BACKUP_DIR"/
echo ""
echo "After Debian Trixie install, run:"
echo "  ./scripts/vm-restore.sh $HOST"
