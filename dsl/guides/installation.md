# Installation

## Requirements

- **Linux** kernel 6.6+ (composefs, fs-verity, cgroups v2, nftables)
- **Erlang/OTP 28+** (bundled in release tarball)
- **Debian Trixie** or **Ubuntu 25.04+** recommended

## Quick Install

```bash
# Build from source
make release

# Install on target machine
scp dist/erlkoenig-0.5.0.tar.gz root@target:/tmp/
scp install.sh root@target:/tmp/

# On target (as root):
bash /tmp/install.sh --local /tmp/  
```

The installer handles everything:
- Creates `erlkoenig` service user + group
- Extracts OTP release to `/opt/erlkoenig/`
- Installs C runtime with file capabilities
- Sets up systemd unit
- Generates Erlang cookie
- Fixes `/etc/hosts` for epmd (Debian cloud images)
- Creates runtime directories

## What Gets Installed

```
/opt/erlkoenig/
├── bin/
│   ├── erlkoenig              Wrapper script (cookie + delegation)
│   ├── erlkoenig-0.5.0        relx release script
│   └── erlkoenig-dsl          Elixir DSL compiler (escript)
├── rt/
│   ├── erlkoenig_rt            168KB static C runtime (musl)
│   └── demo/
│       └── test-erlkoenig-echo_server
├── releases/0.5.0/
│   ├── sys.config              Runtime configuration
│   ├── vm.args.src             VM arguments (cookie substituted at start)
│   └── *.boot                  Boot scripts
├── erts-16.3/                  Bundled Erlang runtime
├── lib/                        OTP application beams
├── dist/
│   └── erlkoenig.service       systemd unit (symlinked)
└── cookie                      Erlang distribution cookie (auto-generated)

/run/erlkoenig/
└── containers/                 Unix sockets (one per container)

/etc/erlkoenig/                 PKI certificates (optional)
/var/lib/erlkoenig/volumes/     Container volumes
/var/log/erlkoenig/             Audit logs
```

## C Runtime (erlkoenig_rt)

The C runtime is a static musl binary that spawns Linux namespaces.
It is included in the release artifacts. If you need to build it separately:

```bash
# On the target machine:
apt install cmake gcc musl-tools make linux-libc-dev libcap-dev
cd erlkoenig_rt
make
./scripts/install.sh
```

Or use the pre-built binary from the erlkoenig release — `install.sh`
copies it to `/opt/erlkoenig/rt/erlkoenig_rt` and sets capabilities.

## Configuration

Edit `/opt/erlkoenig/releases/0.5.0/sys.config` after installation.

### AMQP (RabbitMQ)

Enable AMQP event publishing:

```erlang
{amqp, #{
    enabled => true,
    host => "10.20.30.2",     %% RabbitMQ host (use private IP)
    port => 5672,
    user => <<"erlkoenig">>,
    password => <<"erlkoenig">>
}}
```

Without AMQP, events are still available internally via `erlkoenig_events`
but not published externally.

### Binary Signatures (PKI)

Enable signature verification:

```erlang
{signature, #{
    mode => on,                                     %% on | warn | off
    trust_roots => ["/etc/erlkoenig/ca/root.pem"],
    min_chain_depth => 2
}}
```

### Resource Limits

Adjust cgroup protection:

```erlang
{resource_protection, #{
    beam_memory_max => 536_870_912,     %% 512 MB for BEAM
    containers_memory_max => auto,       %% auto = MemTotal - host_reserve - beam
    containers_max => 200,               %% max concurrent containers
    require_memory_limit => false,       %% true = reject containers without limits
    require_pids_limit => false
}}
```

## Start / Stop

```bash
systemctl start erlkoenig
systemctl stop erlkoenig
systemctl enable erlkoenig    # start on boot
journalctl -u erlkoenig -f   # follow logs
```

## Verify Installation

```bash
# Service running?
/opt/erlkoenig/bin/erlkoenig ping
# → pong

# Compile a DSL file
erlkoenig-dsl compile examples/simple_echo.exs -o /tmp/test.term

# Deploy containers
/opt/erlkoenig/bin/erlkoenig eval 'erlkoenig_config:load(<<"/tmp/test.term">>).'

# Check running containers
/opt/erlkoenig/bin/erlkoenig eval 'length(pg:get_members(erlkoenig_pg, erlkoenig_cts)).'
```

## Updating

```bash
# Build new release
make release

# Install over existing (stops daemon, preserves cookie + config)
bash install.sh --local dist/ --force
```

The installer preserves:
- `/opt/erlkoenig/cookie` (not overwritten if exists)
- `/etc/erlkoenig/` (PKI certificates)
- `/var/lib/erlkoenig/` (volumes, data)

The installer overwrites:
- `/opt/erlkoenig/releases/*/sys.config` (from release tarball)

After `--force` update, re-apply any custom sys.config changes
(AMQP host, signature mode, etc.).

## Composefs (Debian Trixie)

For container image support with content-addressed deduplication:

```bash
# Add sid repo (composefs not yet in trixie main)
echo "deb http://deb.debian.org/debian/ sid main" > /etc/apt/sources.list.d/sid.list
cat > /etc/apt/preferences.d/sid-pin << EOF
Package: *
Pin: release n=sid
Pin-Priority: 100

Package: composefs libcomposefs1 libcomposefs-dev
Pin: release n=sid
Pin-Priority: 500
EOF

apt update && apt install composefs
```

## Troubleshooting

### "Node is not running"

Check `/etc/hosts` — the hostname must resolve to `127.0.0.1`, not `127.0.1.1`:

```bash
grep $(hostname) /etc/hosts
# Should show: 127.0.0.1 <hostname>
# Fix if needed:
sed -i "s/127.0.1.1\(.*$(hostname)\)/127.0.0.1\1/" /etc/hosts
systemctl restart erlkoenig
```

### "No Erlang cookie found"

```bash
head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32 > /opt/erlkoenig/cookie
chmod 440 /opt/erlkoenig/cookie
chown root:erlkoenig /opt/erlkoenig/cookie
```

### Container spawns but dies immediately

Check if the demo binary exists:

```bash
ls -la /opt/erlkoenig/rt/demo/test-erlkoenig-echo_server
# If missing, build from erlkoenig_rt:
cd erlkoenig_rt && make
cp build/testbin/test-erlkoenig-echo_server /opt/erlkoenig/rt/demo/
chmod 755 /opt/erlkoenig/rt/demo/test-erlkoenig-echo_server
```

### nft tables fail with enoent

Check kernel modules:

```bash
modprobe nf_tables nfnetlink
nft list tables
```

### sys.config overwritten after update

`install.sh --force` replaces sys.config from the release tarball.
Re-apply AMQP, signature, and limit changes after update.
