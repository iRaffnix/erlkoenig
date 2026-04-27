# Erlkoenig — Speed and Control

Container Runtime auf Erlang/OTP 28. Ein 168KB static-musl C-Binary spawnt Linux-Namespaces, der BEAM orchestriert alles drumherum: Netzwerk via Netlink, Firewall via nftables (pure Erlang, kein CLI), cgroups v2 mit PSI-Metriken, Ed25519-Binärsignaturen, tamper-evidenter Audit-Chain, AMQP-Events. Elixir-DSL kompiliert direkt zu Erlang-Termen — kein YAML, keine JSON-Schema-Gymnastik. 50ms Spawn pro Container, 23ms im Batch.

**Documentation:** https://iraffnix.github.io/erlkoenig/ — 23-Kapitel Book + API-Reference

## Example

```elixir
defmodule ThreeTier do
  use Erlkoenig.Stack

  host do
    ipvlan "dmz", parent: {:device, "eth0"}, subnet: {10, 0, 0, 0, 24}
    ipvlan "app", parent: {:dummy,  "ek_app"}, subnet: {10, 0, 1, 0, 24}

    nft_table :inet, "erlkoenig" do
      nft_counter "forward_drop"

      base_chain "forward", hook: :forward, type: :filter,
        priority: :filter, policy: :drop do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept,
          ip_saddr: {10, 0, 0, 0, 24},
          ip_daddr: {10, 0, 1, 0, 24},
          tcp_dport: 4000
        nft_rule :drop, counter: "forward_drop"
      end

      base_chain "postrouting", hook: :postrouting, type: :nat,
        priority: :srcnat, policy: :accept do
        nft_rule :masquerade, ip_saddr: {10, 0, 0, 0, 24}, oifname_ne: "eth0"
      end
    end
  end

  pod "web", strategy: :one_for_one do
    container "nginx",
      binary: "/opt/nginx",
      args: ["8443"],
      limits: %{memory: 268_435_456, pids: 100},
      restart: :permanent do

      # Declare what the workload needs from the platform.
      # No magic inject — operator wires the bind-mounts explicitly.
      requires :"dns.local"
      requires :"journal.local"

      nft do
        output do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_daddr: {10, 0, 1, 0, 24}, tcp_dport: 4000
          nft_rule :drop
        end

        # Rate-limit incoming SYN per source IP + cap concurrent conns.
        input do
          conn_limit per_ip: 50, global: 500
          nft_rule :accept, ct_state: [:established, :related]
          ip_allow [{1, 2, 3, 0, 24}, {10, 0, 0, 0, 8}]
          nft_rule :drop
        end
      end

      publish interval: 2000 do
        metric :memory
        metric :cpu
        metric :pids
      end
    end
  end

  pod "app", strategy: :one_for_all do
    container "api", binary: "/opt/api", args: ["4000"], restart: :permanent
  end

  attach "web", to: "dmz", replicas: 3
  attach "app", to: "app", replicas: 2
end
```

```bash
ek dsl compile stack.exs -o stack.term
ek config load /opt/stack.term
```

## What It Does

- **Containers** — Linux namespaces (PID, NET, MNT, UTS, IPC, CGROUP), 50ms spawn, OTP supervision per pod, three strategies (`:one_for_one`, `:one_for_all`, `:rest_for_one`)
- **Firewall** — nftables via pure Erlang Netlink, kein `nft`-CLI-Fork. Egress- und Ingress-Chains, Counters, NFLOG, NAT, Conntrack, `conn_limit`, `ip_allow`, `rate_limit`, JHash-basiertes DNAT-Loadbalancing
- **cgroups v2** — Memory, CPU, PIDs Limits + PSI-Pressure-Metriken + OOM-Detection + Cgroup-Devices-Filter
- **Observability** — 40+ Event-Typen über AMQP (Container-Lifecycle, Stats, Firewall, Conntrack, Guard, Security, Audit, Capabilities)
- **Audit Chain** — SHA-256 Hash-Chain über alle Security-relevanten Events, Ed25519-Signatur pro Eintrag, täglicher HMAC-Seal. Offline-Verifier in Go (`tools/audit-verifier`) rekonstruiert den ganzen Chain unabhängig vom Producer
- **PKI** — Ed25519-Binärsignaturen, X.509-Cert-Chain-Validation, Reject-unsigned-Policy
- **ELF Analysis** — Syscall-Extraktion aus `.text`, Seccomp-BPF-Profil-Generierung, Sprachdetection (Go/Rust/C via DWARF/Buildinfo)
- **Service Capabilities** — Deklarative Platform-Services: `:dns.local`, `:journal.local`, `:postgres.local`. Kein auto-inject — Operator mounted explizit (Glasbox-Prinzip)
- **Threat Detection** — Conntrack-basierter Per-IP Threat-Actor (gen_statem), Threat-Mesh für multi-node Ban-Convergence, automatischer nft-Set-Ban mit Timeout
- **Property-Based Testing** — PropEr-Fuzz auf jeden Binär-Parser (NLA, DWARF, ELF-Syscalls, TLV-Proto, Sig-Files, Audit-Chain), ~13k random inputs pro `rebar3 eunit`-Run

## Install

Erlkoenig targets Linux hosts. The installer aims to be distro-agnostic
across systemd Linux distributions, but the runtime depends on Linux kernel
features such as namespaces, cgroups v2, capabilities, seccomp, Landlock, and
nftables. macOS and BSD are not supported runtime targets.

```bash
# From GitHub release (production):
sudo sh install.sh --version v0.9.0

# Oder von lokalem Build:
sudo sh install.sh --local /path/to/artifacts
sudo make install          # aus dem source-tree

# Oder bauen + installieren in einem Rutsch:
git clone https://github.com/iRaffnix/erlkoenig.git
cd erlkoenig
make                       # full build
sudo make install          # nach /opt/erlkoenig
sudo systemctl start erlkoenig
```

Release installs bundle ERTS, so target hosts do not need a system Erlang
installation. Source builds require Erlang/OTP 28+, Elixir 1.18+, rebar3,
cmake, and musl-gcc.

Requires on target hosts: Linux 6.x, nftables, cgroups v2, file capabilities,
and systemd for managed service installation.

Manual installer smoke baseline for a fresh VM/LXC:

```bash
gh run download <run-id> -D /tmp/erlkoenig-artifacts
sudo sh tests/install/test-install-smoke.sh --artifacts /tmp/erlkoenig-artifacts
```

Run this before and after installer changes. It installs via `install.sh
--local`, restarts `erlkoenig.service`, then checks `ek node ping` and `ek ps`.

## Build

```bash
make              # full build: C-Runtime + Erlang + Tests + Release-Tarball
make check        # lint + eunit + dialyzer + DSL tests (non-root)
make release      # OTP-Release-Tarball (inkl. bundled Elixir)
make integration  # integration tests (braucht sudo)
make docs         # ExDoc HTML generieren (23 Book-Kapitel)
make verifier     # Go audit-verifier statisch bauen
```

## Operator CLI (`ek`)

Shell-Wrapper plus escript. Wird mit dem Release ausgeliefert und spricht per
Erlang distribution mit dem lokalen `erlkoenig@<hostname>`-Node. Lokale
Subcommands wie `doctor`, `explain` und `dsl compile` laufen ohne Verbindung
zur Runtime.

```bash
ek node ping                   # Runtime erreichbar?
ek node version                # laufende App-Version
ek --version                   # CLI-Version ohne Runtime-Verbindung
ek node health                 # Uptime + Supervisor-Kinder
ek doctor                      # Host-/Install-Diagnose mit EK_* Codes

ek up stack.exs                # .exs kompilieren + Stack laden
ek down stack.term             # deklarierte Container stoppen
ek down --all                  # alle laufenden Container stoppen

ek ps                          # Alias fuer ct list
ek ct inspect <name-or-id>     # voller Container-State + Timeline
ek ct stop <name-or-id>        # einzelnen Container stoppen
ek pod list                    # aktive Pod-Supervisoren
ek pod list --all              # inkl. terminaler Pods

ek dsl compile stack.exs -o stack.term
ek config validate stack.term  # low-level Validate-Only
ek config load stack.term      # low-level Load
ek config reload stack.term    # Delta-Reload

ek vol list [--container NAME]
ek vol inspect <uuid|persist-name>
ek vol set-quota <uuid> 1G
ek vol orphans

ek quarantine list
ek quarantine add <sha256-hex> --reason operator_ban
ek quarantine remove <sha256-hex>

ek admission snapshot
ek explain EK_RUNTIME_HANDSHAKE_FAILED
ek explain --component audit
ek --format json ct list
```

Globale Optionen: `--node <name>`, `--cookie-file <path>`, `--format table|json|plain`.
Vollstaendige Referenz: `docs/CLI.md`; Book-Kapitel: `doc/book/18-operator-cli.md`.
Falls `/opt/erlkoenig/bin` nicht im Shell-`PATH` ist, nutze
`/opt/erlkoenig/bin/ek`.

## Performance

| Containers | Spawn-Zeit | Pro Container |
|------------|-----------|---------------|
| 10         | 335ms     | 33ms          |
| 50         | 1.2s      | 24ms          |
| 200        | 4.7s      | 23ms          |
| 500        | 31s       | 62ms          |

Gemessen auf Hetzner CX22 (2 vCPU, 4 GB RAM). 500er-Wert durch BPF-Device-Filter-Ceiling auf kleinen Hosts — grössere VMs skalieren linear.

## Project Layout

```
apps/erlkoenig/           OTP-App (124+ Module, merged nft)
  src/                    Erlang-Source
  test/                   eunit + PropEr-Fuzz (~13 Properties)
c-runtime/                168KB static-musl C-Container-Spawner
dsl/                      Elixir-DSL (Erlkoenig.Stack)
examples/                 DSL-Beispiele + tutorials + scenarios
  tutorial/               6-stufige hands-on Tutorial-Serie
  agents/                 Go-Demo-Workloads (case_mgmt, deadline_worker)
  scenarios/              nft-VM-Scenarios für Simulation
tests/integration/        Integration-Test-Escripts (brauchen sudo)
tools/audit-verifier/     Offline Go-Verifier für Audit-Chain
doc/book/                 23-Kapitel Book (Markdown → ExDoc HTML)
```

## License

[Apache-2.0](LICENSE)
