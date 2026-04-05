# SPEC: erlkoenig + erlkoenig_nft Merge

**Status:** Draft
**Date:** 2026-03-31

## Summary

Merge erlkoenig_nft into erlkoenig as a single OTP application.
Remove dead code from erlkoenig (old C runtime copy, Go demos).
Result: one repo, one app, one release, one socket, one protocol.

## Current State

```
erlkoenig/                      erlkoenig_nft/
  apps/erlkoenig/ (33 mod)   src/ (53 mod + 38 gen)
  c-runtime/ (DUPLICATE)          dsl/ (10 Elixir files)
  dsl/ (exists, partial)          src_otel/ (optional)
  demos/ (Go, unused)             codegen/
  stories/ (Go, unused)           examples/
  CMakeLists.txt (old)            tests/integration/
  integration-tests/              include/
```

Two repos. Two Erlang releases. Two epmd ports. Two sockets.
Two protocols (ETF binary on ctl.sock, JSON on nft api.sock).
erlkoenig depends on erlkoenig_nft as a rebar3 Git dep.

## Target State

```
erlkoenig/
  apps/erlkoenig/src/    ← ALL Erlang modules (33 + 53 + 38 gen = 124)
  dsl/                        ← ALL DSL macros + CLI (unified)
  codegen/                    ← nft_gen.escript (moved)
  include/                    ← nft_constants.hrl (moved)
  examples/                   ← Firewall + Stack examples (moved)
  integration-tests/          ← Erlang integration tests (existing)
  tests/integration/          ← nft kernel tests (moved)
  dist/                       ← systemd units (existing)
  docs/                       ← All docs
```

One repo. One OTP app. One release. One socket. One protocol (ETF).

## What Gets Removed from erlkoenig

| Path | Reason | Action |
|------|--------|--------|
| `c-runtime/` | Duplicate of erlkoenig_rt. The C runtime is a separate repo with its own CMakeLists.txt, tests, and release cycle. This copy is stale. | Delete |
| `CMakeLists.txt` | Builds the stale c-runtime/ copy. erlkoenig_rt has its own. | Delete |
| `demos/` | Go demo apps (echo-server, api-server, reverse-proxy). Should be EROFS images, not Go source in the control plane repo. | Delete |
| `stories/` | Go showcase apps (secure-doc-sign). Not part of the product. | Delete |
| rebar dep on erlkoenig_nft | No longer external — modules are local. | Remove from rebar.config |

## What Gets Moved from erlkoenig_nft

### Erlang Modules → `apps/erlkoenig/src/`

All modules keep their names. No renames needed — they already have
`erlkoenig_nft_` or `nfnl_` or `nft_` prefixes that don't collide
with erlkoenig's `erlkoenig_` prefix.

**Core (15 hand-written):**
- `erlkoenig_nft.erl` — Public facade
- `erlkoenig_nft_sup.erl` — Firewall supervisor (becomes child of erlkoenig_sup)
- `erlkoenig_nft_firewall.erl` — Config lifecycle
- `erlkoenig_nft_ct.erl` — Conntrack monitor
- `erlkoenig_nft_ct_guard.erl` — Threat detection
- `erlkoenig_nft_counter.erl` — Rate monitoring
- `erlkoenig_nft_watch_sup.erl` — Counter worker supervisor
- `erlkoenig_nft_audit.erl` — Audit log (nft-specific)
- `erlkoenig_nft_events.erl` — Event emission
- `erlkoenig_nft_config.erl` — Config path resolution
- `erlkoenig_nft_ip.erl` — IP normalization
- `erlkoenig_nft_nflog.erl` — NFLOG receiver

**Netlink Protocol (5):**
- `nfnl_server.erl` — Supervised netlink socket
- `nfnl_socket.erl` — Raw AF_NETLINK socket
- `nfnl_msg.erl` — Message header builder
- `nfnl_attr.erl` — Attribute codec
- `nfnl_response.erl` — Response parser
- `nfnl_nflog.erl` — NFLOG socket

**Rule Engine (12):**
- `nft_rules.erl` — High-level rule builders
- `nft_expr_ir.erl` — Intermediate representation
- `nft_encode.erl` — IR → netlink binary
- `nft_table.erl`, `nft_chain.erl`, `nft_rule.erl` — Kernel objects
- `nft_set.erl`, `nft_set_elem.erl` — Set management
- `nft_object.erl` — Named objects
- `nft_batch.erl` — Atomic transactions
- `nft_query.erl`, `nft_decode.erl` — Query & decode
- `nft_delete.erl` — Bulk deletion
- `nft_quota.erl`, `nft_flowtable.erl` — Quotas, offloading

**VM Simulator (4):**
- `nft_vm.erl` — nftables bytecode simulator
- `nft_vm_pkt.erl` — Synthetic packet builder
- `nft_vm_config.erl` — VM configuration
- `nft_vm_scenario.erl` — Test scenarios

**Generated (38):**
- `gen/nft_expr_*_gen.erl` — TLV encoders from kernel headers

**Total: ~70 modules moving into erlkoenig/src/**

### What Gets Deleted (not moved)

| Module | Reason |
|--------|--------|
| `erlkoenig_nft_api.erl` | JSON socket server — replaced by ctl.sock |
| `erlkoenig_nft_app.erl` | OTP app callback — erlkoenig_app handles startup |

### Other Files → erlkoenig/

| From | To | Notes |
|------|-----|-------|
| `erlkoenig_nft/codegen/nft_gen.escript` | `erlkoenig/codegen/nft_gen.escript` | Code generator |
| `erlkoenig_nft/include/nft_constants.hrl` | `erlkoenig/apps/erlkoenig/include/` | Kernel constants |
| `erlkoenig_nft/examples/` | `erlkoenig/examples/` | Firewall example configs |
| `erlkoenig_nft/tests/integration/` | `erlkoenig/tests/nft-integration/` | Kernel integration tests |
| `erlkoenig_nft/src_otel/` | `erlkoenig/apps/erlkoenig/src_otel/` | Optional OTel extension |
| `erlkoenig_nft/docs/EXTENSIONS.md` | `erlkoenig/docs/EXTENSIONS.md` | Extension boundary docs |
| `erlkoenig_nft/docs/FIREWALL.md` | `erlkoenig/docs/FIREWALL.md` | Firewall deep-dive |

### DSL → `erlkoenig/dsl/`

erlkoenig already has a `dsl/` directory. The nft DSL macros move there,
and the new Stack/Zone/Steering/Images macros are added:

```
erlkoenig/dsl/
  mix.exs                           ← Updated (name: :erlkoenig_dsl)
  lib/
    erlkoenig/
      stack.ex                      ← NEW: use Erlkoenig.Stack umbrella
      cli.ex                        ← REWRITE: unified CLI (ctl.sock, ETF)
      cli/ctl_client.ex             ← NEW: ctl.sock client ({packet,4} + ETF)
      cli/formatter.ex              ← MOVE + extend from erlkoenig_nft
      images/builder.ex             ← NEW
      zone/builder.ex               ← NEW
      steering/builder.ex           ← NEW
    erlkoenig_nft/
      firewall.ex                   ← MOVE from erlkoenig_nft/dsl/
      firewall/builder.ex           ← MOVE
      firewall/profiles.ex          ← MOVE
      guard.ex                      ← MOVE
      guard/builder.ex              ← MOVE
      watch.ex                      ← MOVE
      watch/builder.ex              ← MOVE
  test/
    firewall_test.exs               ← MOVE
    guard_test.exs                  ← MOVE
    watch_test.exs                  ← MOVE
    zone_test.exs                   ← NEW
    steering_test.exs               ← NEW
    stack_test.exs                  ← NEW
    examples_test.exs               ← MOVE
```

## Supervision Tree (after merge)

```
erlkoenig_sup (rest_for_one)
├── erlkoenig_pg                    Process groups
├── erlkoenig_zone                  Zone registry
├── erlkoenig_zone_sup              Per-zone supervisors
│   └── zone "default"
│       ├── erlkoenig_bridge        Linux bridge
│       ├── erlkoenig_ip_pool       IP allocation
│       └── erlkoenig_dns           DNS server
├── erlkoenig_cgroup                cgroup v2
├── erlkoenig_events                Event bus (gen_event)
├── erlkoenig_health                Health checks
├── erlkoenig_audit                 Audit log
├── erlkoenig_pki                   PKI/signatures
├── erlkoenig_nft_sup               ← MERGED: Firewall subtree
│   ├── nfnl_server                 AF_NETLINK socket
│   ├── erlkoenig_nft_nflog         NFLOG receiver
│   ├── erlkoenig_nft_ct            Conntrack monitor
│   ├── erlkoenig_nft_ct_guard      Threat detection
│   ├── erlkoenig_nft_watch_sup     Counter monitoring
│   │   └── erlkoenig_nft_counter   Per-counter workers
│   ├── erlkoenig_nft_audit         Firewall audit
│   └── erlkoenig_nft_firewall      Config lifecycle
├── erlkoenig_ctl                   Control socket (ONLY external API)
└── erlkoenig_ct_sup                Container supervisor
    └── erlkoenig_ct                Per-container state machine
```

`erlkoenig_nft_sup` is a child of `erlkoenig_sup` with strategy
`rest_for_one`. If it crashes, its children restart independently.
Container supervisor is unaffected.

Position matters: `erlkoenig_nft_sup` starts BEFORE `erlkoenig_ctl`
(control socket needs firewall ready) and BEFORE `erlkoenig_ct_sup`
(containers need firewall for per-container chains).

## Protocol: Unified ctl.sock

**One socket:** `/run/erlkoenig/ctl.sock`
**Transport:** Unix domain, `{packet, 4}` framing
**Encoding:** Erlang External Term Format (ETF)

### Wire Format

```
Request:  <<Length:32/big, Term/binary>>
Term = {Ref :: reference(), Cmd :: atom(), Args :: map()}

Response: <<Length:32/big, Term/binary>>
Term = {Ref :: reference(), ok, Result :: term()}
     | {Ref :: reference(), error, Reason :: term()}
```

The `Ref` correlates request → response. `{packet, 4}` handles framing.
ETF handles encoding. Zero custom protocol code.

### Commands

**Container operations (existing in erlkoenig_ctl, keep as-is):**

| Cmd | Args | Result |
|-----|------|--------|
| `spawn` | `#{binary, opts}` | `#{id, pid}` |
| `stop` | `#{id}` | `ok` |
| `ps` | `#{}` | `[#{id, name, state, ip, ...}]` |
| `inspect` | `#{id}` | `#{full container info}` |
| `kill` | `#{id, signal}` | `ok` |
| `status` | `#{}` | `#{node, uptime, memory, containers, ...}` |

**Artifact operations (existing, keep):**

| Cmd | Args | Result |
|-----|------|--------|
| `push` | `#{name, binary, tags, files, sig}` | `#{hash, name}` |
| `artifacts` | `#{tag}` | `[#{name, hash, tags, ...}]` |
| `artifact_info` | `#{name}` | `#{...}` |
| `artifact_tag` | `#{name, tag}` | `ok` |
| `artifact_delete` | `#{name}` | `ok` |

**Firewall operations (NEW — replaces JSON API):**

| Cmd | Args | Result |
|-----|------|--------|
| `ban` | `#{ip}` | `ok` |
| `unban` | `#{ip}` | `ok` |
| `reload_firewall` | `#{}` | `ok` |
| `firewall_status` | `#{}` | `#{table, chains, sets, ...}` |
| `counters` | `#{}` | `#{counter => #{pps, bps}}` |
| `guard_stats` | `#{}` | `#{floods, scans, bans}` |
| `guard_banned` | `#{}` | `[#{ip, reason, expires}]` |
| `list_chains` | `#{}` | `[#{name, hook, policy, rules}]` |
| `list_sets` | `#{}` | `[#{name, type}]` |
| `list_set` | `#{name}` | `#{elements}` |
| `list_counters` | `#{}` | `[#{name, pps, bps, packets, bytes}]` |
| `add_element` | `#{set, value}` | `ok` |
| `del_element` | `#{set, value}` | `ok` |
| `diff_live` | `#{}` | `#{diffs}` |

**Config operations (NEW — unified stack deployment):**

| Cmd | Args | Result |
|-----|------|--------|
| `apply` | `#{term}` | `#{firewall, zones, containers, steering}` |
| `load` | `#{path}` | `#{firewall, zones, containers, steering}` |
| `audit_log` | `#{n}` | `[#{ts, action, ...}]` |

**Steering operations (NEW):**

| Cmd | Args | Result |
|-----|------|--------|
| `steering_status` | `#{}` | `#{services, routes}` |

Implementation: `erlkoenig_ctl.erl` dispatches commands to the
appropriate module. Firewall commands call `erlkoenig_nft:*` directly
(same BEAM, Erlang function call, no socket roundtrip).

## What Dies

| Thing | Replacement |
|-------|-------------|
| erlkoenig_nft as separate repo | Merged into erlkoenig |
| erlkoenig_nft as separate OTP app | Modules in erlkoenig |
| erlkoenig_nft as separate release | Part of erlkoenig release |
| `/run/erlkoenig_nft/api.sock` | `/run/erlkoenig/ctl.sock` |
| JSON Lines protocol | ETF over `{packet, 4}` |
| `erlkoenig_nft_api.erl` | `erlkoenig_ctl.erl` handles all commands |
| `erlkoenig_nft_app.erl` | `erlkoenig_app.erl` starts nft_sup |
| Port 9101 (nft epmd) | Same node as erlkoenig |
| `erlkoenig_nft/dsl/` | `erlkoenig/dsl/` |
| `erlkoenig/c-runtime/` | erlkoenig_rt (separate repo) |
| `erlkoenig/CMakeLists.txt` | erlkoenig_rt has its own |
| `erlkoenig/demos/*.go` | Not part of product |
| `erlkoenig/stories/*.go` | Not part of product |
| `ErlkoenigNft.CLI.Daemon` (JSON client) | `Erlkoenig.CLI.CtlClient` (ETF client) |
| rebar dep `{erlkoenig_nft, {git, ...}}` | Local modules |

## Migration Steps

### Step 1: Clean erlkoenig
- Delete `c-runtime/`, `CMakeLists.txt`, `demos/`, `stories/`
- Remove erlkoenig_nft from rebar.config deps
- Update CLAUDE.md (remove C runtime references)

### Step 2: Move erlkoenig_nft Erlang modules
- Copy `erlkoenig_nft/src/*.erl` → `erlkoenig/apps/erlkoenig/src/`
- Copy `erlkoenig_nft/src/gen/` → `erlkoenig/apps/erlkoenig/src/gen/`
- Copy `erlkoenig_nft/include/` → `erlkoenig/apps/erlkoenig/include/`
- Copy `erlkoenig_nft/src_otel/` → `erlkoenig/apps/erlkoenig/src_otel/`
- Copy `erlkoenig_nft/codegen/` → `erlkoenig/codegen/`
- Delete `erlkoenig_nft_api.erl` and `erlkoenig_nft_app.erl`
- Update `erlkoenig.app.src` with new modules

### Step 3: Wire supervision tree
- Add `erlkoenig_nft_sup` as child of `erlkoenig_sup`
- Remove `erlkoenig_nft_api` from `erlkoenig_nft_sup` children
- Update `erlkoenig_app.erl` boot sequence

### Step 4: Extend ctl.sock
- Add firewall command handlers to `erlkoenig_ctl.erl`
- Direct Erlang calls to `erlkoenig_nft:ban/1`, `erlkoenig_nft:rates/0`, etc.
- Add steering command handlers

### Step 5: Move DSL
- Move `erlkoenig_nft/dsl/lib/erlkoenig_nft/*.ex` → `erlkoenig/dsl/lib/erlkoenig_nft/`
- Rewrite CLI to use ctl.sock (ETF) instead of nft api.sock (JSON)
- Add Stack/Zone/Steering/Images builders
- Update mix.exs

### Step 6: Move tests + examples
- Move `erlkoenig_nft/test/` (eunit) → `erlkoenig/apps/erlkoenig/test/`
- Move `erlkoenig_nft/tests/integration/` → `erlkoenig/tests/nft-integration/`
- Move `erlkoenig_nft/examples/` → `erlkoenig/examples/`

### Step 7: Archive erlkoenig_nft
- Update README: "Merged into erlkoenig. This repo is archived."
- Archive on GitHub

## Resulting Module Count

| Category | Count | Prefix |
|----------|-------|--------|
| Orchestrator | 33 | `erlkoenig_*`, `ek*` |
| Firewall engine | 53 | `erlkoenig_nft_*`, `nfnl_*`, `nft_*` |
| Generated | 38 | `nft_expr_*_gen` |
| **Total** | **124** | No collisions |

Zero module renames. The `erlkoenig_nft_` prefix naturally namespaces
the firewall modules within the same app.

## Build System

```makefile
make              # rebar3 compile + DSL compile
make check        # eunit + dialyzer + nft-integration + dsl tests
make release      # OTP release tarball (includes erlkoenig_rt binary)
make rt           # Build erlkoenig_rt (calls into erlkoenig_rt/ repo)
```

The `erlkoenig_rt` C binary is still built from its own repo.
The release tarball includes it as a pre-built artifact.

## .app.src Changes

```erlang
{application, erlkoenig, [
  {description, "Erlkoenig zero-trust container runtime"},
  {vsn, "0.4.0"},
  {registered, [
    %% existing
    erlkoenig_sup, erlkoenig_zone, erlkoenig_ctl, erlkoenig_events,
    erlkoenig_audit, erlkoenig_health, erlkoenig_pki, erlkoenig_cgroup,
    %% merged from erlkoenig_nft
    erlkoenig_nft_sup, erlkoenig_nft_srv, erlkoenig_nft_firewall,
    erlkoenig_nft_watch_sup
  ]},
  {applications, [kernel, stdlib, crypto, inets, ssl, public_key, compiler]},
  {mod, {erlkoenig_app, []}},
  {env, []}
]}.
```

No more `{erlkoenig_nft, ...}` in `{applications, [...]}`.
