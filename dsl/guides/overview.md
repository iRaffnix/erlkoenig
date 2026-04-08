# Overview

**Erlkoenig — Speed and Control.**

Container Runtime auf Erlang/OTP 28. Ein 168KB C-Binary spawnt Linux-Namespaces, der BEAM orchestriert den Rest: Netzwerk via Netlink, Firewall via nftables (pure Erlang, kein CLI), cgroups v2 mit PSI-Metriken, Ed25519-Signaturen, AMQP-Events. Elixir DSL kompiliert zu Erlang-Termen, kein YAML. 50ms pro Container.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  Elixir DSL (.exs)                                   │
│  defmodule MyStack do                                │
│    use Erlkoenig.Stack                               │
│    host / bridge / pod / container / nft_table / ... │
│  end                                                 │
└──────────────┬───────────────────────────────────────┘
               │ compile
               ▼
┌──────────────────────────────────────────────────────┐
│  Erlang Term (.term)                                 │
│  #{pods => [...], zones => [...], nft_tables => [...]}│
└──────────────┬───────────────────────────────────────┘
               │ erlkoenig_config:load/1
               ▼
┌──────────────────────────────────────────────────────┐
│  BEAM (Erlang/OTP 28)                                │
│                                                      │
│  erlkoenig_ct (gen_statem)     one per container     │
│  erlkoenig_pod_sup (supervisor) one per pod instance │
│  erlkoenig_zone (gen_server)   bridge + IP pool      │
│  erlkoenig_cgroup (gen_server) cgroup v2 hierarchy   │
│  erlkoenig_nft (netlink)       nftables firewall     │
│  erlkoenig_threat_actor        per-IP threat detection│
│  erlkoenig_threat_mesh         kernel ban gateway     │
│  erlkoenig_amqp_*              AMQP event bridge     │
│                                                      │
│  ┌────────────────────────────┐                      │
│  │  Unix Socket per container │                      │
│  └────────────┬───────────────┘                      │
│               │                                      │
└───────────────┼──────────────────────────────────────┘
               │
┌──────────────┴───────────────────────────────────────┐
│  erlkoenig_rt (C, 168KB static musl)                 │
│                                                      │
│  Creates: mount/pid/net/user/uts/cgroup namespaces   │
│  Applies: seccomp, capabilities, tmpfs, volumes      │
│  Communicates: TLV protocol over Unix Domain Socket  │
│  Survives: BEAM restarts (setsid, crash recovery)    │
└──────────────────────────────────────────────────────┘
               │
┌──────────────┴───────────────────────────────────────┐
│  Linux Kernel                                        │
│                                                      │
│  cgroups v2    — memory, cpu, pids limits + PSI      │
│  namespaces    — isolation (mount, pid, net, user)   │
│  nftables      — firewall (via netlink, not nft CLI) │
│  veth pairs    — container networking                │
│  bridges       — L2 segments                         │
└──────────────────────────────────────────────────────┘
```

## Repositories

| Repo | Language | Description |
|------|----------|-------------|
| **erlkoenig** | Erlang + Elixir | Core runtime, DSL, OTP application |
| **erlkoenig_rt** | C (musl) | Container spawner, namespace setup |
| **erlkoenig_nft** | Erlang | Pure Netlink nftables implementation |
| **erlkoenigin** | Markdown | Specs, ADRs, system designs |
| **erlkoenig_nfnl** | Erlang | Low-level Netfilter Netlink protocol |

## Quick Start

```elixir
# 1. Define your stack
defmodule MyStack do
  use Erlkoenig.Stack

  host do
    bridge "net", subnet: {10, 0, 0, 0, 24}
  end

  # Two tightly coupled containers — if one crashes, both restart
  pod "backend", strategy: :one_for_all do
    container "api",
      binary: "/opt/api",
      args: ["--port", "4000"],
      limits: %{memory: 536_870_912, pids: 100},
      restart: :always do

      publish interval: 2000 do
        metric :memory
        metric :cpu
      end
    end

    container "cache",
      binary: "/opt/cache",
      args: ["6379"],
      restart: :always
  end

  attach "backend", to: "net", replicas: 2
end
```

```bash
# 2. Compile
erlkoenig compile mystack.exs -o mystack.term

# 3. Deploy
erlkoenig eval 'erlkoenig_config:load("/path/to/mystack.term").'
```
