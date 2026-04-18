# Chapter 7 — Threat Detection

erlkoenig ships with a DSL for describing what counts as hostile
traffic and what to do about it. Detection runs as one Erlang
`gen_statem` per suspicious source IP. Bans are synchronised across
nodes via a `pg`-based mesh, enforced in the kernel through nftables
sets with timeouts, and surfaced as AMQP events for operators.

## Why per-IP state machines

Every source IP that triggers at least one detector gets its own
process. The process carries the full history for that IP —
connection counts, distinct ports touched, escalation level, ban
expiry. Per-IP isolation has three concrete benefits: detection
logic stays local (no shared data structures to lock), memory is
reclaimed automatically when an IP goes quiet, and the process
supervision story is the standard OTP one.

## The `guard` block

The DSL carries a dedicated `guard do ... end` inside `host`:

```elixir
host do
  ipvlan "dmz", parent: {:device, "eth0"}, subnet: {10, 0, 0, 0, 24}

  guard do
    detect do
      flood     over: 50,  within: s(10)
      port_scan over: 10,  within: m(1)
      slow_scan over: 20,  within: h(1)
      honeypot  [21, 23, 445, 3389]
    end

    respond do
      suspect after: 3, distinct: :ports
      ban_for h(1)
      honeypot_ban_for h(24)
      escalate [h(1), h(6), h(24), d(7)]
      observe_after_unban m(2)
      forget_after m(5)
    end
  end
end
```

Each detector answers a different question:

| Detector     | Condition                                          |
|--------------|----------------------------------------------------|
| `flood`      | N connections within T seconds (internal: `conn_flood`) |
| `port_scan`  | N distinct ports within T (typically minutes)      |
| `slow_scan`  | N distinct ports within T (typically hours)        |
| `honeypot`   | any touch on the listed ports → immediate ban      |

**Never include your SSH port in the honeypot list.** A single
connection triggers an instant ban of the source IP for
`honeypot_ban_for` (default 24h). If SSH is on port 22 and port 22
is a honeypot, the operator's first reconnect locks themselves out
of the host. The same applies to any port that legitimate tools
touch during operations — HTTP/HTTPS, database ports you actually
use, Prometheus scrape endpoints. The honeypot list is
**unconditionally opt-in**: the runtime ships with an empty
default, nothing fires until the operator writes an explicit
`honeypot [...]` line in a `guard do ... end` block.

`s(10)`, `m(1)`, `h(24)`, `d(7)` are time units — seconds, minutes,
hours, days. They expand at compile time to integers.

## The `respond` block

Response is policy, separate from detection:

| Directive              | Meaning                                              |
|------------------------|------------------------------------------------------|
| `suspect after: N, distinct: :ports` | N distinct ports before ban kicks in   |
| `ban_for <duration>`   | first-offence ban duration                           |
| `honeypot_ban_for <d>` | ban duration specifically for honeypot hits         |
| `escalate [h(1), h(6), h(24), d(7)]` | ban duration per repeat offence        |
| `observe_after_unban <d>` | how long to watch for re-offending after a ban    |
| `forget_after <d>`     | idle timeout; the actor process exits after this    |

Escalation multiplies the pain on repeat offenders. The first ban is
the first element of the list, the second is the second, and so on;
the list stops at its end (last element repeats).

## The actor state machine

A threat actor walks through a small set of states:

```
observing ─── detector matches ──→ banned
observing ── distinct-ports>=N ──→ suspicious
suspicious ── detector matches ──→ banned
banned ── timer expires ──→ probation
probation ── any traffic ──→ observing (ban_count incremented)
probation ── observe-timer expires ──→ (process exits, IP forgotten)
```

`observing` is the default: the actor tracks connections, waits for
a detector to fire. `suspicious` is the in-between: enough activity
to warrant attention but no detector has matched yet. `banned` is
live — the IP sits in the kernel's ban set with a timeout.
`probation` is the post-ban watch window; any re-offence escalates.

The actor process dies when it's idle long enough. No explicit
cleanup is needed; supervisor garbage collects the memory.

## The mesh

A single node detects; the cluster acts on it. Every actor broadcasts
its bans into a `pg` group `erlkoenig_threats`; every node listens.
When a ban arrives from a peer, the receiver writes the IP into its
local kernel ban set with the same expiry. Unbans work the same way.

Conflict resolution is deliberately simple: expiry is the maximum
across all sources. If node A bans for one hour and node B then bans
for six, the six-hour ban wins everywhere. A kernel unban fires only
when every known source has expired.

Nodes rejoining the cluster re-announce their active bans; anti-
entropy happens on `nodeup` automatically. The source of truth for a
ban is the local actor — the mesh is a replication layer on top.

## Hands-on: trigger a ban, watch the actor, lift it

This walkthrough takes a host with the daemon running and shows each
stage of the detection+ban lifecycle. The config defines a honeypot
on port 65432 (a random high port — choose one you never serve) and a
`port_scan` trigger at 5 distinct ports in 1 minute.

**1. Declare a guard block.** Save as `~/guard_demo.exs`:

```elixir
defmodule GuardDemo do
  use Erlkoenig.Stack

  host do
    interface "eth0", zone: :wan

    guard do
      detect do
        honeypot  [65432]                     # one port, any touch = ban
        port_scan over: 5, within: s(60)      # 5 distinct ports/min
      end

      respond do
        ban_for          h(1)                 # standard ban duration
        honeypot_ban_for h(24)                # honeypot hits = 24h
        suspect          after: 3, distinct: :ports
        escalate         [h(1), h(6), h(24), d(7)]
        observe_after_unban m(2)
        forget_after     m(5)
      end

      allowlist [ {127, 0, 0, 1}, {10, 0, 0, 0, 8} ]
    end

    # Minimal host firewall so the honeypot port is actually reachable
    nft_table :inet, "host" do
      nft_set "ban", :ipv4_addr
      nft_counter "banned"

      base_chain "prerouting", hook: :prerouting, type: :filter,
                 priority: :raw, policy: :accept do
        nft_rule :drop, set: "ban", counter: "banned"
      end

      base_chain "input", hook: :input, type: :filter,
                 priority: :filter, policy: :drop do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, tcp_dport: 22             # SSH — always first
        nft_rule :accept, tcp_dport: 65432          # the honeypot port
        nft_rule :drop,   log_prefix: "HOST: "
      end
    end
  end
end
```

```bash
ek dsl compile ~/guard_demo.exs -o /tmp/guard.term
ek config load /tmp/guard.term
```

**2. Watch the event stream.** In a separate terminal:

```bash
tools/event_consumer.py amqp://erlkoenig@localhost 'guard.threat.*'
```

Leave it running. You should see nothing until traffic arrives.

**3. Trigger the honeypot from a non-allowlisted IP.** From an external
machine (not 127.0.0.1, not 10.0.0.0/8):

```bash
nc -w1 <host-ip> 65432
```

Within seconds, the event consumer prints:

    guard.threat.ban
    { "ip": "203.0.113.17",
      "reason": "honeypot",
      "duration": 86400,
      "ban_count": 0 }

Confirm the kernel got the ban:

```bash
nft list set inet host ban
# elements = { 203.0.113.17 timeout 1d }
```

Any further packets from that IP hit the raw-priority drop rule
(→ Chapter 6); the counter grows:

```bash
watch -n1 'nft list counter inet host banned'
```

**4. Observe the actor's process.** Every banned IP has its own
`gen_statem` in the BEAM:

```erlang
%% In an `erlkoenig remote_console`:
lists:filter(
  fun(Pid) ->
    {_, D} = sys:get_state(Pid),
    IP = element(2, D),   %% #data.ip
    IP =:= <<203, 0, 113, 17>>
  end,
  gen_statem:get_members(erlkoenig_threat_sup)).
%% => [<0.1423.0>]

sys:get_state(<0.1423.0>).
%% => {banned, {data, <<203,0,113,17>>, #{...}, ..., 0, registry}}
```

Memory footprint of the actor is about 2 KB. It exits automatically
after `forget_after` (5 min of inactivity post-unban).

**5. Escalation in action.** From a second non-allowlisted IP, hit
the honeypot twice in a row separated by 10 seconds. The first touch
bans for 24 h; the second — after the first timeout expires in our
configured `observe_after_unban` window — would escalate to 6 h
(second element of the escalation list). You can simulate faster by
manually unbanning, then hitting again:

```bash
ek quarantine list             # (empty — this is the threat mesh, not quarantine)
# Direct: unban via remote_console
erlkoenig eval 'erlkoenig_threat_mesh:local_unban(<<203,0,113,17>>).'

# Now the next honeypot hit bumps ban_count from 0 to 1
nc -w1 <host-ip> 65432
# event: guard.threat.ban { ..., "ban_count": 1, "duration": 21600 }
```

**6. Lift a ban manually.** Operators sometimes need to unban an IP
that was caught by mistake — a colleague's penetration test, a
legitimate but aggressive monitoring system:

```bash
erlkoenig eval 'erlkoenig_threat_mesh:local_unban(<<203,0,113,17>>).'
```

The mesh broadcasts the unban; all nodes remove the IP from their
kernel `ban` set. The actor transitions to `probation` (if it still
exists), then exits after `observe_after_unban + forget_after`.

**7. Tear down.**

```bash
ek down ~/guard_demo.exs
```

The guard config is ephemeral — no DETS persistence. A daemon
restart clears all bans (threat_mesh is in-memory).

## What this chapter connects to

- The nft `"ban"` set and how rules consume it → Chapter 6.
- `guard.threat.*` AMQP routing keys — one per ban, unban,
  suspicion, honeypot hit → Chapter 9.
- The `erlkoenig_threat_actor` and `erlkoenig_threat_mesh` modules
  are the single source of truth for cluster-wide threat state; they
  persist nothing, everything is in-process and pg-replicated.
