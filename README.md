# Erlkoenig

> **Warning:** This project is in early development. APIs will change,
> features may break, and security has not been audited. Do not use in
> production.

A container runtime for **static binaries** that starts in 67ms, uses 68 KB
on disk, and needs zero infrastructure.

```text
  Browser :80 ──► Reverse Proxy ──► API Server ──► SQLite DB
                  10.0.0.10         10.0.0.20      10.0.0.30
```

Three containers. Three isolated networks. Firewall, DNS, health checks.
Total startup: 200ms. Total RAM: 20 MB. No Docker. No Kubernetes. No YAML.

With RAM, SSD, and energy prices rising, hardware efficiency is no longer
optional — it's a competitive advantage. Erlkoenig runs a full container
stack in the resources that other runtimes spend on their control plane alone.
By running **static binaries** with no shared library dependencies, we eliminate
the Docker registry, layer caching overhead, and massive attack surfaces.

## Benchmarks

Measured on a Hetzner CX22 (2 vCPU, 4 GB RAM, Debian Trixie):

| Metric | Erlkoenig | Docker | Kubernetes |
|--------|-----------|--------|------------|
| Container startup | **67 ms** | 300-500 ms | 1-3 s |
| 50 containers | **3.3 s** | ~20 s | minutes |
| 3-tier stack | **215 ms** | ~2 s | ~10 s |
| Control plane RAM | **30 MB** | ~200 MB | ~500 MB |
| Runtime binary | **68 KB** | ~50 MB | — |

## Features

Erlkoenig combines a **68 KB C runtime** with an **Erlang/OTP control plane**.

- **5 Linux namespaces** (PID, NET, MNT, UTS, IPC) per container.
- **Cgroups v2** memory, CPU, PID limits + eBPF device filtering.
- **Seccomp-BPF** syscall filtering (4 profiles).
- **Integrated Firewall:** Every container automatically gets its own `nf_tables` chain. Rules are added atomically when a container starts. The firewall engine ([`erlkoenig_nft`](apps/erlkoenig_nft/)) is pure Erlang, talking directly to the kernel via Netlink. No C code, no shelling out. See [**docs/FIREWALL.md**](docs/FIREWALL.md).
- **Container DNS** for automatic name resolution.
- **Read-only rootfs** with `/proc` masking (OCI-compliant).
- **Zero external dependencies** — no libcap, no libseccomp, no libnetlink.

## Developer Experience

While the core runtime engine is pure Erlang for maximum stability, the configuration layer uses a clean Elixir DSL, and operations are managed via a dedicated shell.

### 1. Declarative Config (Elixir DSL)
An Elixir DSL compiles container definitions into Erlang terms at build time. No Elixir is needed at runtime — the output is a plain `.term` file loaded by the Erlang control plane.

```elixir
defmodule MyStack do
  use Erlkoenig.DSL

  container :web do
    binary "/opt/bin/server"
    ip {10, 0, 0, 10}
    ports [{80, 8080}]
    limits cpu: 2, memory: "256M", pids: 100
    firewall :strict, allow_tcp: [80, 443]
    restart :on_failure
    health_check port: 8080, interval: 5000
  end
end
```

### 2. Operator Shell
Deploy, inspect, and manage your containers live without restarting the daemon.

```bash
source /opt/erlkoenig/activate
ek-load mystack.ek     # compile + start
ek-reload mystack.ek   # delta update (no downtime)
ek-export backup.ek    # running state → config file

$ /opt/erlkoenig/bin/erlkoenig remote_console

1> ek:ps().
  NAME       STATE    IP            PIDS  RESTARTS
  --------------------------------------------------------
  proxy      running  10.0.0.10     5     0
  api        running  10.0.0.20     5     0
  db         running  10.0.0.30     8     0

2> ek:top().    %% live stats
3> ek:inspect(web). %% container details
4> ek:logs(web).    %% stream stdout/stderr
```

### 3. Under the Hood (Erlang API)
Under the hood, each container is an Erlang process. Crashes are detected in microseconds and restarts happen automatically via OTP supervision trees — the same architecture that runs phone networks at 99.999% uptime.

```erlang
{ok, Pid} = erlkoenig_core:spawn(<<"/opt/bin/server">>, #{
    name    => <<"web">>,
    ip      => {10, 0, 0, 10},
    limits  => #{memory => 64_000_000, pids => 100},
    restart => on_failure
}).
```

## Architecture & Security

For a deep dive into the supervision tree, container lifecycle state machine, port protocol wire format, zone networking, and crash semantics, see [**docs/ARCHITECTURE.md**](docs/ARCHITECTURE.md).

**Security Highlights:** The BEAM runs as unprivileged user `erlkoenig`. The C runtime gets capabilities via `setcap`, not SUID. EPMD and distribution are bound to `127.0.0.1`. The cookie is auto-generated on first deploy.

## Quick Start

### Requirements
- Linux >= 5.2 (cgroups v2, nf_tables batch API, eBPF cgroup device filter)
- Erlang/OTP >= 27

Tested on **Debian Trixie (13)**. Everything comes directly from the standard Debian repository (Kernel 6.12, Erlang 27, GCC 14.2).

```bash
apt-get install erlang erlang-dev rebar3 cmake build-essential musl-tools golang
```

### Building
Everything is Makefile-driven. No wrapper scripts, no build plugins:

```bash
make rt          # C runtime (static musl binary, 68 KB)
make erl         # Erlang control plane
make check       # all tests without root (eunit + dialyzer + DSL)
make release     # OTP release tarball
make deploy      # ship to server (scp + setcap + systemd)
```
See [**docs/BUILD.md**](docs/BUILD.md) and [**docs/STATIC_BINARIES.md**](docs/STATIC_BINARIES.md) for details.

### Install from Release
Don't want to build from source? Grab the pre-built release. It includes its own Erlang runtime — no dependencies, no conflicts with a system Erlang. See [**docs/INSTALL.md**](docs/INSTALL.md).

## Roadmap: Active Development

Erlkoenig currently runs on a single node, but the foundation for clustering is already in place via OTP distribution and `pg`. Coming soon:

- **Multi-node scheduling:** Spawn containers across a cluster.
- **Live migration:** Move running containers between nodes without downtime.
- **Distributed firewall:** Block an IP cluster-wide in microseconds via `pg` broadcast.
- **Federated DNS:** Container name resolution across nodes.

See [**docs/ROADMAP.md**](docs/ROADMAP.md) for details.

## License

[Apache-2.0](LICENSE)
