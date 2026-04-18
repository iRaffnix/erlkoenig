# Chapter 2 — Installation

This chapter gets erlkoenig onto a fresh host. The target platforms are
Debian Trixie (13) and Ubuntu 24.04. Other distributions with kernel
5.10+ and OTP 28 work too but aren't continuously tested.

## Prerequisites

| Component     | Version          | Note                                               |
|---------------|------------------|----------------------------------------------------|
| Linux kernel  | ≥ 5.10           | IPVLAN L3S hooks (fix `d5256083f62e` from 4.19.20), cgroup v2 |
| Erlang/OTP    | ≥ 28             | `minimum_otp_vsn` in `rebar.config` — bundled in the release |
| nftables      | kernel default   | No `nft` CLI needed — erlkoenig speaks Netlink directly |
| `xfsprogs`    | `xfs_quota` + `mkfs.xfs` | For persistent volumes (→ Chapter 15)        |
| `libcap2-bin` | `setcap`         | Applies capabilities to the C runtime              |
| `curl`        | any              | For the installer download                         |

Optional: **composefs** (Debian sid or built from source) for kernel-
verified container images; **RabbitMQ 4.1+** somewhere on the network
for AMQP events (→ Chapter 9).

Root access is required throughout install: `erlkoenig_rt` carries file
capabilities (`cap_sys_admin`, `cap_net_admin`, `cap_sys_chroot`, …),
systemd runs the unit as root, and integration tests mount filesystems.

## Installing from a release

The packaged release ships as a tarball plus an installer script.
Download, review, run:

```bash
curl -fsSL -o install.sh \
    https://github.com/iRaffnix/erlkoenig/releases/latest/download/install.sh
less install.sh                    # review first — never pipe curl into sh
sudo sh install.sh --version v0.6.0
```

The installer:

- Extracts the OTP release to `/opt/erlkoenig/`
- Installs the static C runtime at `/opt/erlkoenig/rt/erlkoenig_rt`
- Optionally installs demo binaries at `/opt/erlkoenig/rt/demo/`
- Creates the `erlkoenig` service user
- Generates an Erlang cookie, syncs it to both `/opt/erlkoenig/cookie`
  (for the daemon) and `/etc/erlkoenig/cookie` (for the `ek` CLI)
- Applies the required file capabilities to `erlkoenig_rt`
- Links the systemd unit to `/etc/systemd/system/erlkoenig.service`
- Fixes `/etc/hosts` if the cloud image set the hostname to 127.0.1.1
  (epmd binds to 127.0.0.1 — the mismatch breaks `ek` CLI)

The BEAM itself runs as the unprivileged `erlkoenig` service user and
drives the C binary over a Unix-domain socket.

## Layout after install

```
/opt/erlkoenig/
├── bin/
│   ├── ek                          # operator CLI wrapper
│   ├── erlkoenig                   # daemon control script
│   └── erts-.../                   # bundled runtime system
├── lib/                            # OTP applications
├── rt/
│   ├── erlkoenig_rt                # static C spawner (~168 KB)
│   └── demo/                       # test-erlkoenig-echo_server etc.
├── examples/                       # DSL examples (copy to ~ and edit)
├── share/
│   └── ek.escript                  # the CLI script itself
└── cookie                          # daemon's Erlang cookie

/etc/erlkoenig/
├── cookie                          # operator-side copy for ek CLI
├── sys.config                      # runtime config overrides
└── ca/                             # trust roots for PKI (→ Chapter 10)

/var/lib/erlkoenig/
├── node.dets                       # container recovery state
└── volumes/                        # persistent volumes root (→ Chapter 15)

/etc/systemd/system/
└── erlkoenig.service -> /opt/erlkoenig/dist/erlkoenig.service
```

## Enabling the systemd service

```bash
sudo systemctl enable --now erlkoenig
journalctl -u erlkoenig -f          # follow startup
```

A healthy startup logs (among other things):

    [ct_guard] Started: flood=50/10s, scan=20/60s, slow=5/3600s,
               honeypot=0 ports, ban=3600s
    erlkoenig_rt: bound unix socket on /run/erlkoenig/ctl.sock

`honeypot=0 ports` is the safe default — honeypots are strictly opt-in
via `guard do honeypot [...]` in a stack file (→ Chapter 7).

## Verify the install

```bash
# 1. CLI can reach the node
ek node ping
# → pong

# 2. App is at the expected version
ek node version
# → 0.6.0

# 3. No containers yet
ek ps
# (empty table)

# 4. The C runtime is capability-equipped
getcap /opt/erlkoenig/rt/erlkoenig_rt
# → cap_sys_admin,cap_net_admin,cap_sys_chroot,cap_sys_ptrace,
#   cap_setpcap,cap_setuid,cap_setgid,cap_dac_override,cap_bpf,
#   cap_sys_resource=ep
```

If `ek node ping` says `can't reach erlkoenig at 'erlkoenig@...'`:

- Check the cookie matches: `md5sum /opt/erlkoenig/cookie /etc/erlkoenig/cookie`
- Check the daemon is running: `systemctl status erlkoenig`
- Check the hostname resolves: `getent hosts $(hostname)`

## Building from source

For local development, build in-tree:

```bash
git clone https://github.com/iRaffnix/erlkoenig.git
cd erlkoenig
make                # full build: Erlang + C + tests + release tarball
make check          # all non-root tests (eunit + dialyzer + DSL)
make release        # release tarball only
make rt             # C runtime only (static musl)
```

`make release` produces `dist/erlkoenig-<VERSION>.tar.gz` that the
installer can ingest:

```bash
sudo sh install.sh --local ./dist
```

This path is what CI uses — nothing beyond the local artifacts is
downloaded.

## Post-install: AMQP (optional, recommended)

Without RabbitMQ, containers still run, but **observability and the
threat-detection mesh stop working** — events fire into a null sink.
Wire up AMQP in `/etc/erlkoenig/sys.config`:

```erlang
{erlkoenig, [
    ...,
    {amqp, #{
        enabled  => true,
        host     => "broker.internal",
        port     => 5672,
        user     => <<"erlkoenig">>,
        password => <<"...">>,
        vhost    => <<"/">>
    }}
]}.
```

Restart the daemon. The node publishes to the `erlkoenig.events` topic
exchange (→ Chapter 9).

## Post-install: PKI (optional)

PKI is off by default (`{signature, #{mode => off, ...}}`). To enforce
signed binaries, place trust roots under `/etc/erlkoenig/ca/` and flip
`mode => on`. Chapter 10 walks through the full signing pipeline.

## Post-install: volume backing

Before starting any container with a `volume "..."` clause, the host
filesystem for persistent volumes must be set up. The short form for a
dev host:

```bash
sudo truncate -s 10G /var/lib/erlkoenig-volumes.img
sudo mkfs.xfs -m reflink=1 -L ek-volumes /var/lib/erlkoenig-volumes.img
sudo mount -o loop,nosuid,nodev,prjquota \
    /var/lib/erlkoenig-volumes.img /var/lib/erlkoenig/volumes
echo '/var/lib/erlkoenig-volumes.img /var/lib/erlkoenig/volumes xfs \
    loop,nosuid,nodev,prjquota,nofail 0 2' | sudo tee -a /etc/fstab
```

Verify:

```bash
mount | grep erlkoenig/volumes
# → /dev/loop0 on /var/lib/erlkoenig/volumes type xfs (rw,nosuid,nodev,prjquota)
xfs_quota -x -c "state -p" /var/lib/erlkoenig/volumes
# → Accounting: ON, Enforcement: ON
```

Without `prjquota` on the mount options, volume quotas silently no-op.
The full walkthrough — sizing, resize, migration to a real partition —
is in → Chapter 15.

## Hands-on: zero-to-first-container in three minutes

From a fresh Debian Trixie box:

```bash
# 1. Download + review + install
curl -fsSL -o install.sh \
    https://github.com/iRaffnix/erlkoenig/releases/latest/download/install.sh
less install.sh
sudo sh install.sh --version v0.6.0

# 2. Start the daemon
sudo systemctl enable --now erlkoenig

# 3. Verify
ek node ping                           # → pong
ek node version                        # → 0.6.0

# 4. Set up the volume backing (if you want persistent volumes)
sudo truncate -s 10G /var/lib/erlkoenig-volumes.img
sudo mkfs.xfs -m reflink=1 -L ek-volumes /var/lib/erlkoenig-volumes.img
sudo mount -o loop,nosuid,nodev,prjquota \
    /var/lib/erlkoenig-volumes.img /var/lib/erlkoenig/volumes

# 5. Run the tutorial
cp /opt/erlkoenig/examples/tutorial.exs ~/tutorial.exs
ek up ~/tutorial.exs
ek ps
```

Chapter 3 walks through the tutorial in detail.

## Troubleshooting

**`ek node ping` prints `can't reach erlkoenig at ...`.**
- Cookie mismatch between operator-side (`/etc/erlkoenig/cookie`) and
  daemon-side (`/opt/erlkoenig/cookie`). The installer syncs them —
  if you've hand-edited one, `sudo cp /opt/erlkoenig/cookie
  /etc/erlkoenig/cookie && sudo systemctl restart erlkoenig`.
- Hostname resolution: `getent hosts $(hostname)` must return
  `127.0.0.1` (not `127.0.1.1`). The installer fixes `/etc/hosts` but
  if your image sets it elsewhere, patch manually.

**`setcap` warning during install.** Install `libcap2-bin`
(Debian/Ubuntu) or `libcap` (Alpine/RHEL), then re-run the installer
with `--force`.

**Container fails with "CAP_SYS_ADMIN required".** The C binary lost
its capabilities — usually after a manual `cp` that didn't preserve
xattrs. Re-run `setcap` by hand or re-run the installer with `--force`.

**`mount -a` says "can't find LABEL".** Loop-backed filesystems aren't
indexed by `blkid`, so the `LABEL=` form doesn't resolve. Use the full
path in fstab instead. See Chapter 15 for the full procedure.

**SSH timeouts immediately after starting the daemon.** This was a
pre-v0.6.0 bug (default honeypot list included port 22). If you're on
a current release and see this, it means an explicit `guard do honeypot
[..., 22, ...]` in your stack file — remove port 22 from the list. See
`doc/findings/2026-04-17-honeypot-default-port-22-lockout.md`.

## Where to go next

The host is installed. → Chapter 3 brings up the first running stack
in about ten minutes.
