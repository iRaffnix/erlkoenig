# Chapter 2 — Installation

This chapter gets erlkoenig onto a fresh host. The target platforms are
Debian Trixie (13) and Ubuntu 24.04. Other distributions with kernel 6.6+
and OTP 28 work too but aren't continuously tested.

## Prerequisites

| Component     | Version               | Note                                              |
|---------------|-----------------------|---------------------------------------------------|
| Linux kernel  | ≥ 6.6                 | IPVLAN L3S, fs-verity, fscrypt, cgroup v2         |
| Erlang/OTP    | ≥ 28                  | `minimum_otp_vsn` in `rebar.config`               |
| nftables      | kernel default        | No CLI needed — erlkoenig speaks Netlink directly |
| XFS userspace | `xfs_quota`, `xfsprogs` | For persistent volumes (→ Chapter 15)           |
| `curl`        | any                   | For the installer download                        |

Optional for the full feature set: **composefs** (from Debian sid or built
from source) for kernel-verified container images; **RabbitMQ 4.1**
somewhere on the network for AMQP events (→ Chapter 9).

Root access is required: `erlkoenig_rt` carries capabilities (cap_sys_admin,
cap_net_admin, cap_sys_chroot, …), systemd runs the unit as root, and
integration tests mount filesystems.

## Installing from a release

The packaged release ships as a tarball plus an installer script. Download,
review, run:

```bash
curl -fsSL -o install.sh \
    https://github.com/iRaffnix/erlkoenig/releases/latest/download/install.sh
less install.sh                    # review first
sudo sh install.sh --version v0.7.0
```

The installer lays down:

- `/opt/erlkoenig/` — the OTP release plus a bundled ERTS
- `/opt/erlkoenig/rt/erlkoenig_rt` — the static C binary
- `/opt/erlkoenig/rt/demo/` — test binaries (sleeper, echo_server, …)
- `/etc/erlkoenig/` — sys.config, cookie, PKI trust roots
- `/var/lib/erlkoenig/` — recovery DETS, the future volume base
- `/etc/systemd/system/erlkoenig.service` — the systemd unit

Capabilities are applied to the C binary via `setcap`; the BEAM itself
runs as an unprivileged user and drives the binary over a Unix-domain
socket.

## Building from source

For local development, build in-tree:

```bash
cd /home/dev/code/erlkoenig
make                # full build: Erlang + C + tests + release tarball
make check          # all non-root tests (eunit + dialyzer + DSL)
make release        # release tarball only
make rt             # C runtime only (static musl)
```

`make release` produces a tarball under `_build/prod/rel/` that the same
`install.sh` can ingest (`--local` instead of `--version`).

## Enabling the systemd service

```bash
sudo systemctl enable --now erlkoenig
journalctl -u erlkoenig -f
```

A healthy node is one where the cookie is readable, the C binary is found
(`rt_path` in `sys.config`, default `auto` scans `/opt/erlkoenig/rt/`), and
the app boots without errors in the log. Quick check:

```bash
sudo erlkoenig ping              # PONG from the local node
sudo erlkoenig eval 'erlkoenig:list().'
```

## Post-install: AMQP and PKI

**AMQP** is optional but strongly recommended — without RabbitMQ containers
still run, but observability and the threat mesh stop working. In
`/etc/erlkoenig/sys.config` flip the `amqp` block to `enabled => true` and
fill in host/port/user. After a restart the node publishes events onto the
`erlkoenig.events` exchange (→ Chapter 9).

**PKI** is off by default (`{signature, #{mode => off, ...}}`). To enforce
signed binaries, place trust roots under `/etc/erlkoenig/ca/` and set
`mode => on`. Details in → Chapter 10.

## Post-install: volume backing

Before the first container with a `volume "..."` clause starts, the host
filesystem for persistent volumes must be set up — otherwise writes land on
the root filesystem and, in the worst case, take the host down. The full
procedure (XFS on loop file, `prjquota` flag, reflink verification) lives
in → Chapter 15.

Short form for a dev host:

```bash
sudo truncate -s 10G /var/lib/erlkoenig-volumes.img
sudo mkfs.xfs -m reflink=1 -L ek-volumes /var/lib/erlkoenig-volumes.img
sudo mkdir -p /var/lib/erlkoenig/volumes
sudo mount -o loop,nosuid,nodev,prjquota \
    /var/lib/erlkoenig-volumes.img /var/lib/erlkoenig/volumes
echo '/var/lib/erlkoenig-volumes.img /var/lib/erlkoenig/volumes xfs \
    loop,nosuid,nodev,prjquota,nofail 0 2' | sudo tee -a /etc/fstab
```

Verification:

```bash
mount | grep erlkoenig-volumes
# expect: type xfs (rw,nosuid,nodev,...,prjquota)
```

## Troubleshooting

**`erlkoenig ping` doesn't respond.** The cookie in `/etc/erlkoenig/cookie`
doesn't match the running BEAM. `systemctl restart erlkoenig` and retry.

**Container fails with "CAP_SYS_ADMIN required".** The C binary lost its
capabilities — often after a manual `cp`. Re-run `setcap` (the installer
writes an idempotent line into `dist/`).

**`mount -a` says "can't find LABEL".** Loop-backed filesystems aren't
indexed by `blkid`, so the `LABEL=` form doesn't resolve. Use the full path
in fstab instead. See Chapter 15 for the full setup.

With the host installed, the foundation is in place. → Chapter 3 brings up
the first running container in about ten minutes.
