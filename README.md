# Erlkoenig

A container runtime for **static binaries** that starts in 67ms, uses 68 KB
on disk, and needs zero infrastructure.

Nothing runs unless cryptographically authorized. Every binary signed.
Every action audited. Every port a trap.

```text
  Browser :80 ──► Reverse Proxy ──► API Server ──► SQLite DB
                  10.0.0.10         10.0.0.20      10.0.0.30
```

Three containers. Three isolated namespaces. Firewall, DNS, health checks.
Total startup: 200ms. Total RAM: 20 MB. No Docker. No Kubernetes. No YAML.

## Benchmarks

Measured on a Hetzner CX22 (2 vCPU, 4 GB RAM, Debian Trixie):

| Metric | Erlkoenig | Docker | Kubernetes |
|--------|-----------|--------|------------|
| Container startup | **67 ms** | 300-500 ms | 1-3 s |
| 50 containers | **3.3 s** | ~20 s | minutes |
| 3-tier stack | **215 ms** | ~2 s | ~10 s |
| Control plane RAM | **30 MB** | ~200 MB | ~500 MB |
| Runtime binary | **68 KB** | ~50 MB | — |

## Security

Erlkoenig combines a **68 KB C runtime** with an **Erlang/OTP control plane**.

- **Ed25519 binary signing** — every binary verified at `exec()`, not just at deployment.
  Certificate chain from Root CA to signing cert. Unsigned binaries are rejected.
- **Honeypot firewall** — every port except the one you open is a trap.
  One packet at the wrong port = instant 24h ban. Detected in milliseconds
  via kernel conntrack, not polling.
- **5 Linux namespaces** (PID, NET, MNT, UTS, IPC) per container.
  Full isolation — no shared namespaces like Kubernetes pods.
- **Seccomp-BPF** syscall filtering — ~60 of 300+ syscalls allowed.
  Violations kill the process immediately (`SECCOMP_RET_KILL_PROCESS`).
- **Capabilities: all 41 dropped** — even root inside the container has no power.
- **Per-container nftables firewall** — rules added atomically via Netlink.
  The firewall engine ([`erlkoenig_nft`](https://github.com/iRaffnix/erlkoenig_nft))
  is pure Erlang, talking directly to the kernel. No C code, no shelling out.
- **Read-only rootfs** with `/proc` masking (OCI-compliant).
- **Audit log** — every security event in JSON Lines. Binary verified,
  binary rejected, container started, container stopped.
- **Crash recovery in microseconds** — Erlang/OTP supervision, not 30s healthchecks.
- **Zero external dependencies** — no libcap, no libseccomp, no libnetlink.

## Deploy

Define your stack in a single file. Deploy with one command.

```elixir
defmodule MyStack do
  use Erlkoenig.DSL

  container :web do
    binary "/opt/erlkoenig/rt/demo/web"
    signature :required
    ip {10, 0, 0, 10}
    args ["8080", "http://10.0.0.20:8081"]
    ports [{8080, 8080}]
    seccomp :network
    caps []
    limits memory: "64M", pids: 20

    firewall do
      counters [:http, :trap]
      accept :established
      accept :loopback
      connlimit_drop 100
      accept_tcp 8080, counter: :http
      accept :icmp
      log_and_drop "TRAP: ", counter: :trap
    end

    guard do
      detect :conn_flood, threshold: 50, window: 10
      detect :port_scan, threshold: 1, window: 60
      ban_duration 86400
    end
  end
end
```

```bash
erlkoenig deploy stack.exs
```

```
Compiling stack.exs ...
  3 container(s) found

Deploying archive (10.0.0.30) ...
  Started: archive
Deploying signer (10.0.0.20) ...
  Started: signer
Deploying web (10.0.0.10) ...
  Started: web

3/3 containers running.
```

## CLI

All management via Unix socket. No TCP, no epmd, no network exposure.

```bash
erlkoenig deploy stack.exs       # deploy all containers
erlkoenig ps                     # list running containers
erlkoenig stop <id>              # stop a container
erlkoenig inspect <id>           # container details
erlkoenig status                 # daemon info
erlkoenig audit                  # security event log

erlkoenig sign <binary> --cert <cert> --key <key>
erlkoenig verify <binary> --trust-root <ca.pem>
erlkoenig pki create-root-ca --cn <name> --out <cert> --key-out <key>
```

## Try it: Secure Document Signing

A complete tutorial with three Go binaries, PKI setup, binary signing,
and a document signing service. See [**stories/secure-doc-sign/**](stories/secure-doc-sign/).

```bash
cd stories/secure-doc-sign
sh build.sh                          # build 3 static Go binaries
erlkoenig sign web --cert ...        # sign each binary
erlkoenig deploy stack.exs           # deploy 3 containers
curl http://10.0.0.10:8080/sign \
  -d '{"document":"Kaufvertrag","signer":"Dr. Schmidt"}'
```

## Architecture

For a deep dive into the supervision tree, container lifecycle state machine,
port protocol wire format, zone networking, and crash semantics, see
[**docs/ARCHITECTURE.md**](docs/ARCHITECTURE.md).

## Quick Start

### Requirements
- Linux >= 5.2 (cgroups v2, nf_tables batch API, eBPF cgroup device filter)
- Erlang/OTP >= 27

### Install from Release

Download, review, run:

```bash
curl -fsSL -o install.sh \
  https://github.com/iRaffnix/erlkoenig/releases/latest/download/install.sh
less install.sh
sudo sh install.sh --version v0.2.0
```

See [**docs/INSTALL.md**](docs/INSTALL.md) for options and details.

### Build from Source

```bash
make rt          # C runtime (static musl binary, 68 KB)
make erl         # Erlang control plane
make check       # all tests without root (eunit + dialyzer + DSL)
make release     # OTP release tarball
```

See [**docs/BUILD.md**](docs/BUILD.md), [**docs/STATIC_BINARIES.md**](docs/STATIC_BINARIES.md), and [**docs/CONTRIBUTING.md**](docs/CONTRIBUTING.md).

## License

[Apache-2.0](LICENSE)
