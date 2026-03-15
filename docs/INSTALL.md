# Install from Release

No build tools required. The installer handles everything:
user creation, C runtime with capabilities, OTP release, systemd service.

## Requirements

- Linux x86_64, kernel >= 5.2
- Root access (for capabilities and systemd)
- `curl` (for remote install) or local CI artifacts

Tested on **Debian Trixie (13)**.

## Install

Download the installer, review it, then run:

```bash
curl -fsSL -o install.sh \
    https://github.com/iRaffnix/erlkoenig/releases/latest/download/install.sh
less install.sh        # review first
sudo sh install.sh --version v0.2.0
```

For a specific version:

```bash
curl -fsSL -o install.sh \
    https://github.com/iRaffnix/erlkoenig/releases/download/v0.2.0/install.sh
less install.sh
sudo sh install.sh --version v0.2.0
```

### Install from local CI artifacts

Don't wait for a release. Download CI artifacts and install locally:

```bash
gh run list --branch dev-yourname
gh run download <run-id> -D /tmp/artifacts
sudo sh install.sh --local /tmp/artifacts
```

## What the installer does

1. Creates `erlkoenig` system user (if not exists)
2. Creates directories: `/opt/erlkoenig/`, `/opt/erlkoenig/rt/`, `/etc/erlkoenig/`
3. Installs C runtime to `/opt/erlkoenig/rt/erlkoenig_rt` with `setcap`
4. Extracts OTP release to `/opt/erlkoenig/`
5. Installs DSL escript (if present in artifacts)
6. Installs demo binaries to `/opt/erlkoenig/rt/demo/` (if present)
7. Installs and configures systemd service

## Verify

```bash
sudo systemctl status erlkoenig
sudo journalctl -u erlkoenig -n 5
getcap /opt/erlkoenig/rt/erlkoenig_rt
```

## File layout

```
/opt/erlkoenig/
├── bin/erlkoenig          Start/stop script
├── bin/erlkoenig-dsl      DSL compiler (optional)
├── erts-15.2/             Bundled Erlang runtime
├── lib/                   OTP applications
├── releases/              Release config
├── doc/                   Documentation
└── examples/              DSL example configs

/opt/erlkoenig/rt/
├── erlkoenig_rt           C runtime (static binary, setcap)
├── echo-server            Go demo (optional)
├── reverse-proxy          Go demo (optional)
├── api-server             Go demo (optional)
└── demo/                  C test binaries (optional, root-only)

/etc/erlkoenig/
├── ca/                    Trust root certificates (for binary signing)
└── vm.args                Erlang VM config
```

## Usage

```bash
# Start the service
sudo systemctl start erlkoenig

# Deploy a stack
erlkoenig deploy stack.exs

# Manage containers
erlkoenig ps
erlkoenig status
erlkoenig audit
```

## Uninstall

```bash
sudo systemctl stop erlkoenig
sudo systemctl disable erlkoenig
sudo rm /etc/systemd/system/erlkoenig.service
sudo systemctl daemon-reload
sudo rm -rf /opt/erlkoenig /etc/erlkoenig
sudo userdel -r erlkoenig
```

## Troubleshooting

**"Operation not permitted" on container start:**
Check that `erlkoenig_rt` has capabilities: `getcap /opt/erlkoenig/rt/erlkoenig_rt`.
If empty, re-run: `sudo setcap cap_sys_admin,... /opt/erlkoenig/rt/erlkoenig_rt`

**"Cannot bind to port 53":**
The BEAM needs `CAP_NET_BIND_SERVICE`. Check the systemd unit has
`AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE`.

**Release doesn't start:**
Check the journal: `journalctl -u erlkoenig -e`. Common issue:
the bundled ERTS architecture doesn't match (the release is x86_64 only).

**Conflict with erlkoenig_nft.service:**
If you previously had the standalone `erlkoenig_nft` package, stop and
disable it first. The firewall is now integrated into the main service.
