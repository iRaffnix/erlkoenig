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
      observe_after_unban m(10)
      forget_after h(2)
    end
  end
end
```

Each detector answers a different question:

| Detector     | Condition                                          |
|--------------|----------------------------------------------------|
| `flood`      | N connections within T seconds                     |
| `port_scan`  | N distinct ports within T (typically minutes)      |
| `slow_scan`  | N distinct ports within T (typically hours)        |
| `honeypot`   | any touch on the listed ports → immediate ban      |

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

## What this chapter connects to

- The nft `"ban"` set and how rules consume it → Chapter 6.
- `guard.threat.*` AMQP routing keys — one per ban, unban,
  suspicion, honeypot hit → Chapter 9.
- The `erlkoenig_threat_actor` and `erlkoenig_threat_mesh` modules
  are the single source of truth for cluster-wide threat state; they
  persist nothing, everything is in-process and pg-replicated.
