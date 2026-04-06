# Erlkoenig — Speed and Control

Container Runtime auf Erlang/OTP 28. Ein 168KB C-Binary spawnt Linux-Namespaces, der BEAM orchestriert den Rest: Netzwerk via Netlink, Firewall via nftables (pure Erlang, kein CLI), cgroups v2 mit PSI-Metriken, Ed25519-Signaturen, AMQP-Events. Elixir DSL kompiliert zu Erlang-Termen, kein YAML. 50ms pro Container.

**Documentation:** https://iraffnix.github.io/erlkoenig/

## Example

```elixir
defmodule ThreeTier do
  use Erlkoenig.Stack

  host do
    interface "eth0", zone: :wan
    bridge "dmz", subnet: {10, 0, 0, 0, 24}, uplink: "eth0"
    bridge "app", subnet: {10, 0, 1, 0, 24}

    nft_table :inet, "erlkoenig" do
      nft_counter "forward_drop"

      base_chain "forward", hook: :forward, type: :filter,
        priority: :filter, policy: :drop do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :jump, iifname: {:veth_of, "web", "nginx"}, to: "from-web"
        nft_rule :accept,
          ip_saddr: {:replica_ips, "web", "nginx"},
          ip_daddr: {:replica_ips, "app", "api"},
          tcp_dport: 4000
        nft_rule :drop, counter: "forward_drop"
      end

      nft_chain "from-web" do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, tcp_dport: 4000
        nft_rule :drop
      end

      base_chain "postrouting", hook: :postrouting, type: :nat,
        priority: :srcnat, policy: :accept do
        nft_rule :masquerade, ip_saddr: {10, 0, 0, 0, 24}, oifname_ne: "dmz"
      end
    end
  end

  pod "web", strategy: :one_for_one do
    container "nginx",
      binary: "/opt/nginx",
      args: ["8443"],
      limits: %{memory: 268_435_456, pids: 100},
      restart: :always do

      publish interval: 2000 do
        metric :memory
        metric :cpu
        metric :pids
      end
    end
  end

  pod "app", strategy: :one_for_all do
    container "api",
      binary: "/opt/api",
      args: ["4000"],
      restart: :always
  end

  attach "web", to: "dmz", replicas: 3
  attach "app", to: "app", replicas: 2
end
```

```bash
# Compile + deploy
erlkoenig compile stack.exs -o stack.term
erlkoenig eval 'erlkoenig_config:load("/opt/stack.term").'
```

## What It Does

- **Containers**: Linux namespaces (PID, NET, MNT, UTS, IPC, CGROUP), 50ms spawn, OTP supervision per pod
- **Firewall**: nftables via pure Erlang Netlink — egress chains, counters, NFLOG, NAT, conntrack
- **cgroups v2**: Memory, CPU, PIDs limits + PSI pressure metrics + OOM detection
- **Observability**: 28 event types over AMQP (container lifecycle, stats, firewall, conntrack, guard, security)
- **PKI**: Ed25519 binary signing, X.509 chain validation, reject unsigned containers
- **ELF Analysis**: Syscall extraction, seccomp-BPF generation, language detection (Go/Rust/Zig/C)
- **Guard**: Conntrack-based threat detection, automatic IP banning

## Build

```bash
make              # full build (Erlang + C runtime + tests + release)
make check        # eunit + dialyzer + DSL tests (no root)
make release      # OTP release tarball
make integration  # integration tests (needs sudo)
```

Requires: Linux, Erlang/OTP 28+, Elixir 1.18+, musl-gcc (for C runtime).

## CLI

```bash
erlkoenig compile <file.exs> -o <out.term>   # compile DSL
erlkoenig validate <file.exs>                # check for errors
erlkoenig ps                                 # list containers
erlkoenig stop <id>                          # stop container
erlkoenig status                             # firewall status
erlkoenig counters                           # drop counter rates

erlkoenig sign <binary> --cert <pem> --key <key>
erlkoenig verify <binary>
erlkoenig pki create-root-ca --cn <name> --out <cert> --key-out <key>
```

## Performance

| Containers | Time | Per Container |
|------------|------|---------------|
| 10 | 335ms | 33ms |
| 50 | 1.2s | 24ms |
| 200 | 4.7s | 23ms |
| 500 | 31s | 62ms |

Measured on Hetzner CX22 (2 vCPU, 4 GB RAM).

## License

[Apache-2.0](LICENSE)
