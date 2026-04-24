## Chapter 23 — Edge Primitives: CIDR Sets, Connection Limits, and the Tracker Frame

Chapter 22 brought the first per-container egress policy to
erlkoenig: `:"dns.allowlist"`, a name-layer filter that sits on
top of operator-authored L4. This chapter broadens the toolbox
with two lower-layer primitives and the conceptual frame behind
them.

- **`nft_cidr_set`** — declare a CIDR range set once, reference
  it from any rule. Replaces a wall of `nft_rule ip_saddr ...`
  lines with something readable.
- **`conn_limit per_ip: N`** — bound concurrent connections per
  source IP, the way nginx's `limit_conn` does. First concrete
  column of SPEC-EK-028's Tracker abstraction. Lives at chain
  level, compiles to a single visible `connlimit_drop` nft rule.

All three keep the Glasbox contract from Chapter 19: the
operator reads a stack file and sees exactly what the container
can do. No auto-injected L4, no hidden chains.

---

## Why these, why now

The first version of erlkoenig's DSL let operators write raw nft:

```elixir
nft do
  input policy: :drop do
    nft_rule :accept, ct_state: [:established, :related]
    nft_rule :accept, ip_saddr: {10, 0, 0, 0, 8}
    nft_rule :accept, ip_saddr: {192, 168, 0, 0, 16}
  end
end
```

That reads like an iptables script because it *is* one. For
trusted-CIDR allow-listing and per-IP connection caps, nginx
and HAProxy settled on one-line primitives twenty years ago
(`limit_conn`, `allow 10.0.0.0/8`). We can match that ergonomics
over nft without giving up the Glasbox promise.

The reference memo `specs/erlkoenig/edge-primitives.md` in the
`erlkoenigin` architecture repository scanned nginx 1.27 and
HAProxy 3.x for primitives worth copying; the follow-up
`SPEC-EK-028-tracker.md` in the same repo names the data model
they all sit on top of ("stick-table" in HAProxy parlance).
This chapter ships the first two concrete primitives from that
roadmap.

## `nft_cidr_set` — CIDR ranges as a first-class thing

Inside an `nft_table` block, declare the range set once:

```elixir
nft_table :inet, "host" do
  nft_cidr_set "trusted", [
    "10.0.0.0/8",
    "192.168.0.0/16",
    "203.0.113.42"           # bare addresses are OK too
  ]

  base_chain "input", hook: :input, type: :filter,
    priority: :filter, policy: :drop do

    nft_rule :accept, ct_state: [:established, :related]
    nft_rule :accept, set: "trusted"
    nft_rule :accept, iifname: "lo"
  end
end
```

Compile-time checks:

- Empty list → `CompileError`
- Non-binary entry → `CompileError`
- Malformed CIDR (`"2001:db8::/32"`, `"notanip"`) → `CompileError`

At runtime this compiles to one nft interval set loaded with the
right `start`/`end` attribute pairs. Integration Test 30 proves
`nft get element` lookups return the expected CIDR for addresses
inside each range and report "no match" for anything outside.

### Why not a top-level `ip_allow` macro?

Because an allow-list is two separate things — a typed set *and*
a rule that consumes it — and the Glasbox principle says those
should both be visible. `nft_cidr_set` owns the set; the
operator writes the `accept, set: "trusted"` rule that uses it.
Tomorrow the same set can back a `saddr_map` or be consumed by
two chains; coupling it to one hidden "allow" rule would make
that harder to read.

## `conn_limit` — SPEC-EK-028 Tracker column #1

**Chain-scoped.** `conn_limit per_ip: N` is a sugar macro that
expands into a single nft rule inside the input chain the
operator wrote. No auto-synthesis, no hidden default policy.

```elixir
container "api", binary: "/opt/bin/api" do
  nft do
    input policy: :drop do
      nft_rule :accept, ct_state: [:established, :related]
      nft_rule :accept, tcp_dport: 8080
      conn_limit per_ip: 100
    end
  end
end
```

That DSL expands into an input chain of exactly three rules,
visible in the order written:

```
ct state { established, related } accept
tcp dport 8080 accept
ct count over 100 saddr drop
```

Running `nsenter --target <pid> --net nft list ruleset` on the
live container prints the chain and the operator sees each rule
next to the line they wrote in the stack file. This is the
Glasbox contract: the DSL is the only source of truth for what
the kernel does.

### What this replaces

An earlier iteration exposed `conn_limit per_ip: N` at
**container level** (outside any `nft` block) and auto-generated
a whole input chain if none existed, with `policy: accept` baked
in. That pattern is explicitly forbidden by our own Glasbox rule
(see `feedback_no_magic_inject` in the project memory) — the
operator had no way to read the kernel policy from the stack file
without also running `nft list` and reverse-engineering the
platform's synthesis logic. The chain-scoped form above replaces
it; writing `conn_limit` at container level is now a compile
error.

### Compile-time rules

- `per_ip:` must be a positive integer. Zero, negative, and
  non-integers all raise `CompileError` at `mix compile` time.
- `global:` and `audit:` options existed in the earlier version
  and have been **removed**. `global:` was cargo-culted from
  HAProxy's `maxconn` — the kernel's `listen()` backlog already
  provides per-container total-conn backpressure, so a second
  nft-layer cap was ceremony. `audit:` lived briefly to disable
  a lifecycle-boundary audit event that also got removed (see
  next section). Both are re-addable when a real use case
  surfaces.
- Writing `conn_limit` outside any chain block is a compile
  error (same failure mode as writing `nft_rule` out of context).

### Drop is kernel-side

No userspace. The fourth concurrent connection from a source IP
that has already consumed the cap gets SYN-dropped by netfilter
before it reaches the container's accept queue. Latency is
nanoseconds; cost is a single set lookup per packet. Integration
test 31 proves this end-to-end: two connections open, third
refused, close one — third-attempt succeeds immediately.

## Audit integration — phase 1 honesty

**Phase 1 emits no tracker-specific audit events.** This is a
deliberate downgrade from an earlier draft that claimed "audit by
default".

The earlier draft shipped `tracker_installed` / `tracker_torn_down`
events fired at container lifecycle transitions. They were
signed and chain-verifiable, but they captured *rule existence*,
not *enforcement*. An auditor asking "how many rejections
happened in the window from T1 to T2" would look at those events
and learn nothing useful. So they have been removed.

Rule existence remains fully auditable: the stack file IS the
contract, `ek inspect nft <container>` verifies the rule is
live, and `nft list counter` inside the container netns gives
rejection counts for ad-hoc checks. What phase 1 does *not* do
is produce signed chain entries per rejection — that needs
cross-netns NFLOG dispatch (SPEC-EK-028 §8bis) and is explicitly
deferred to phase 1-bis.

If you need enforcement evidence **today**, poll the kernel
counter from your own harness:

```bash
nsenter --target <ct-pid> --net nft list counter inet \
    ct_<name> <counter-name>
```

and record the deltas to your log system. This workaround used
to be automated inside erlkoenig (the deleted
`erlkoenig_tracker_poller`); we kept it out of the platform
because "it is audited" should not mean "interval-aggregated
counter polling" without the operator explicitly asking for
that.

## Full worked example

```elixir
defmodule AcmeApi do
  use Erlkoenig.Stack

  host do
    ipvlan "api", parent: {:dummy, "ek_api"}, subnet: {10, 70, 0, 0, 24}

    nft_table :inet, "host" do
      nft_cidr_set "trusted", ["10.0.0.0/8", "192.168.0.0/16"]

      base_chain "input", hook: :input, type: :filter,
        priority: :filter, policy: :drop do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, set: "trusted"
        nft_rule :accept, iifname: "lo"
      end
    end
  end

  pod "api", strategy: :one_for_one do
    container "web",
      binary: "/opt/bin/web",
      zone: "api",
      replicas: 1,
      restart: :permanent do

      requires :"dns.local"

      nft do
        input policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, tcp_dport: 8080
          # Per-source concurrent-connection cap, visible in the chain
          conn_limit per_ip: 100
        end
      end
    end
  end
end
```

Two defences compose:

1. **Host nft** — drops anything not from `trusted` CIDRs at the
   host border.
2. **Container `conn_limit per_ip`** — caps concurrent
   connections per remaining source IP.

Both are written explicitly; the stack file names every rule
installed in the kernel.

## Integration tests

Two escripts cover both primitives end-to-end.

| Test | What it proves |
|------|----------------|
| `30_nft_cidr_set.escript` | DSL CIDR set → nft interval set with correct encoding; `nft get element` membership checks match expectation |
| `31_conn_limit.escript` | DSL-equivalent nft term installs `ct count over 2 saddr drop` visible in the container netns; the 3rd concurrent connection is SYN-dropped; closing one frees the slot |

Both are in `tests/integration/run_all.sh` and run as root.

## Reference: the Tracker frame

`conn_limit` is the first concrete column of the Tracker
abstraction described in `SPEC-EK-028-tracker.md`. The spec's
phase roadmap:

| Phase | Column | Status |
|-------|--------|--------|
| 1 | `conn_cur` (this chapter) | shipped |
| 2 | `conn_rate` (leaky bucket) | next |
| 3 | Explicit multi-column `track do ... end` | after phase 2 proves itself |
| 4 | `gpc` — app-writable counters | use-case driven |
| 5 | `gpt` — runtime-mutable tag column | pair with `ip_tag_map` |
| 6 | `peers: :mesh` replication | multi-node showcase |
| 7 | Byte-rate via TC-BPF | needs `erlkoenig_bpf` kernel bridge |
| 8 | Composite keys `{src_ip, dst_port}` | port-scan-detection-light |

Phase 1 + 2 are the Minimum-Viable-Ship. Everything from phase 3
on waits for real workload pressure. The flat DSL today
(`conn_limit`, future `rate_limit`) compiles internally to
single-column trackers; when a container needs multiple metrics
on the same key, the explicit `track do ... end` block will
expose the shared structure without breaking the flat sugar.

## What this chapter does NOT cover

- **Per-packet audit** — phase 1-bis; see SPEC-EK-028 §8bis.
- **`rate_limit per_ip: "50/s"`** — Tracker column #2, specced,
  not yet shipped. Will slot next to `conn_limit` with the same
  ergonomics.
- **HTTP-layer rate limiting** — URI/header/cookie-based caps.
  Not our layer; belongs in a userspace reverse proxy that a
  customer deploys themselves.
- **Dynamic limit tuning from Erlang** — the tracker's kernel
  state is readable at runtime (`nft list counter`) but the
  spec's `erlkoenig_tracker:set_threshold/4` runtime-tune API
  lands with phase 2.
- **Active health-check circuit-breakers** — already the
  orchestrator's concern, not an edge primitive.

## Reference

- **SPEC-EK-028 (Tracker)** — the full data-model rationale,
  phase roadmap, and audit contract. Lives in the `erlkoenigin`
  architecture repository at
  `specs/erlkoenig/SPEC-EK-028-tracker.md`.
- **`specs/erlkoenig/edge-primitives.md`** (same repo) — the
  nginx/HAProxy scan that seeded this work; §10 names the
  Tracker frame that ties the primitives together.
- **`Erlkoenig.Nft.ChainBuilder.add_conn_limit/2`** + the
  shared `compile_conn_limit!/1` validator — where the DSL sugar
  is wired.
- **`erlkoenig_ct_firewall:compile_generic_special(connlimit_drop, …)`**
  — the rule expansion to nftables expressions.
- **Chapter 19** — capability framework this composes with.
- **Chapter 20** — the audit verifier that re-checks chain
  integrity for the events erlkoenig DOES emit (no
  tracker-specific events in phase 1).
- **Chapter 22** — DNS Egress Allowlist, the peer primitive on
  the L7 DNS side.
