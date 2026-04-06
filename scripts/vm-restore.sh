#!/bin/bash
# vm-restore.sh — Restore erlkoenig VM after Debian Trixie install.
#
# Usage: ./scripts/vm-restore.sh [ssh-host]
#   Default host: erlkoenig-2__root
#
# Expects backup at: /tmp/erlkoenig-vm-backup/

set -eu

HOST="${1:-erlkoenig-2__root}"
BACKUP_DIR="/tmp/erlkoenig-vm-backup"

if [ ! -d "$BACKUP_DIR" ]; then
    echo "ERROR: $BACKUP_DIR not found. Run vm-backup.sh first."
    exit 1
fi

echo "Restoring $HOST from $BACKUP_DIR"

# 1. SSH access (must be done first — might need manual key injection via console)
echo "[1/8] SSH authorized_keys..."
ssh "$HOST" 'mkdir -p /root/.ssh && chmod 700 /root/.ssh'
scp "$BACKUP_DIR/authorized_keys" "$HOST":/root/.ssh/authorized_keys
ssh "$HOST" 'chmod 600 /root/.ssh/authorized_keys'

# 2. Essential packages
echo "[2/8] Installing packages..."
ssh "$HOST" 'apt-get update && apt-get install -y \
    composefs \
    git \
    cmake \
    gcc \
    musl-tools \
    python3-pika \
    openssl \
    curl \
    jq \
    setcap'

# 3. Erlang/OTP 28 + Elixir
echo "[3/8] Erlang + Elixir..."
ssh "$HOST" '
    # Check if already installed
    if ! command -v erl >/dev/null 2>&1; then
        echo "Install Erlang/OTP 28 manually (kerl or package)"
        echo "  See: scripts/build-otp28.sh in erlkoenigin"
    else
        erl -noshell -eval "io:format(\"OTP ~s~n\", [erlang:system_info(otp_release)]), halt()."
    fi
'

# 4. Directories
echo "[4/8] Creating directories..."
ssh "$HOST" '
    mkdir -p /opt/erlkoenig/rt/demo
    mkdir -p /opt/erlkoenig/bin
    mkdir -p /run/erlkoenig/containers
    mkdir -p /etc/erlkoenig/ca
    mkdir -p /var/lib/erlkoenig/objects
    mkdir -p /var/lib/erlkoenig/images
'

# 5. PKI certificates
echo "[5/8] PKI certificates..."
scp -r "$BACKUP_DIR/ca/"* "$HOST":/etc/erlkoenig/ca/

# 6. systemd unit
echo "[6/8] systemd unit..."
scp "$BACKUP_DIR/erlkoenig.service" "$HOST":/etc/systemd/system/erlkoenig.service
ssh "$HOST" 'systemctl daemon-reload && systemctl enable erlkoenig'

# 7. Build + deploy erlkoenig release
echo "[7/8] Deploy erlkoenig release..."
RELEASE=$(ls dist/erlkoenig-*.tar.gz 2>/dev/null | head -1)
DSL=$(ls dist/erlkoenig-dsl 2>/dev/null)
if [ -n "$RELEASE" ]; then
    scp "$RELEASE" "$HOST":/tmp/
    ssh "$HOST" "tar xzf /tmp/$(basename $RELEASE) -C /opt/erlkoenig"
    echo "  Release deployed"
else
    echo "  No release tarball found. Run: make release"
fi
if [ -n "$DSL" ]; then
    scp "$DSL" "$HOST":/opt/erlkoenig/bin/erlkoenig-dsl
    ssh "$HOST" 'chmod 755 /opt/erlkoenig/bin/erlkoenig-dsl'
fi

# 8. Build + install erlkoenig_rt
echo "[8/8] Build + install C runtime..."
cd ../erlkoenig_rt 2>/dev/null && {
    tar czf /tmp/erlkoenig_rt_src.tar.gz --exclude=build --exclude=.git .
    scp /tmp/erlkoenig_rt_src.tar.gz "$HOST":/tmp/
    ssh "$HOST" '
        mkdir -p /tmp/rt_build && cd /tmp/rt_build
        tar xzf /tmp/erlkoenig_rt_src.tar.gz
        make && ./scripts/install.sh
        cp build/erlkoenig_rt /opt/erlkoenig/rt/erlkoenig_rt
    '
    cd - >/dev/null
} || echo "  erlkoenig_rt not found locally, skip"

echo ""
echo "=== Restore complete ==="
echo ""
echo "Next steps:"
echo "  1. Verify: ssh $HOST 'composefs-info --version'"
echo "  2. Configure sys.config (AMQP, socket_dir, etc.)"
echo "  3. Start: ssh $HOST 'systemctl start erlkoenig'"
echo "  4. Test: ssh $HOST '/opt/erlkoenig/bin/erlkoenig ping'"
