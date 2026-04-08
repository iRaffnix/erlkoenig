# Reactive Threat Detection

erlkoenig's guard system detects and bans malicious source IPs
automatically. Each suspicious IP gets its own Erlang process
that tracks behavior through a lifecycle:

```
observing → suspicious → banned → probation → (process dies)
```

No log files, no manual intervention. The kernel bans IPs at
wire speed, and bans auto-expire even if the BEAM crashes.

## How It Works

```
Incoming packet
    │
    ▼
Kernel: nftables evaluates rules, conntrack creates event
    │
    ▼ (Netlink multicast, ~1ms)
ct_guard: routes event to per-IP threat actor
    │
    ▼ (one Erlang process per suspicious IP)
threat_actor: checks thresholds, decides ban/suspect/clear
    │
    ▼ (ban intention, not direct kernel call)
threat_mesh: single process that writes to kernel blocklist
    │
    ▼ (nft set element with timeout)
Kernel: IP in blocklist, DROP at wire speed, auto-expiry
```

The actor never speaks to the kernel directly. This prevents
race conditions where a local timer expiry would briefly open
the firewall while a remote ban is still active.

## DSL

The guard block has three sections — what to detect, how to
respond, and who to exempt:

```elixir
guard do
  detect do
    flood over: 50, within: s(10)
    port_scan over: 20, within: m(1)
    slow_scan over: 5, within: h(1)
    honeypot [21, 22, 23, 445, 1433, 1521, 3306,
              3389, 5900, 6379, 8080, 8888, 9200, 27017]
  end

  respond do
    suspect after: 3, distinct: :ports
    ban_for h(1)
    honeypot_ban_for h(24)
    escalate [h(1), h(6), h(24), d(7)]
    observe_after_unban m(2)
    forget_after m(5)
  end

  allowlist [
    {127, 0, 0, 1},
    {10, 0, 0, 1}
  ]
end
```

Time units: `s()` seconds, `m()` minutes, `h()` hours, `d()` days.

## Detectors

### flood

Counts new connections per source IP within a time window.

```elixir
flood over: 50, within: s(10)   # 50 connections in 10s → ban
```

Catches SYN floods, HTTP floods, SSH brute force.

### port_scan

Counts distinct destination ports per source IP.

```elixir
port_scan over: 20, within: m(1)   # 20 ports in 60s → ban
```

Catches Nmap, Masscan, Zmap.

### slow_scan

Like port_scan but over a longer window for stealthy scanners.

```elixir
slow_scan over: 5, within: h(1)   # 5 ports in 1 hour → ban
```

Catches Shodan, Censys, manual reconnaissance.

### honeypot

Ports that no service on the host uses. Any single connection
triggers an instant ban. Zero false positives.

```elixir
honeypot [21, 22, 23, 445, 3389, 6379, 27017]
```

If SSH runs on port 22222, put port 22 in the honeypot list.
Every bot scanning port 22 gets instantly banned.

## Response Configuration

### suspect

When an IP contacts N distinct ports without triggering a ban,
it's marked as suspicious. An AMQP alert fires for monitoring.

```elixir
suspect after: 3, distinct: :ports   # 3 ports → suspect event
```

### ban_for / honeypot_ban_for

Default ban duration for threshold triggers, and a separate
(typically longer) duration for honeypot triggers.

```elixir
ban_for h(1)              # 1 hour for flood/scan
honeypot_ban_for h(24)    # 24 hours for honeypot
```

### escalate

Repeat offenders get progressively longer bans. The list defines
the ban duration for the 1st, 2nd, 3rd, and subsequent bans.

```elixir
escalate [h(1), h(6), h(24), d(7)]
# 1st ban: 1 hour
# 2nd ban: 6 hours
# 3rd ban: 24 hours
# 4th+ bans: 7 days
```

### observe_after_unban

After a ban expires, the actor enters probation. If the IP
reappears during probation, it restarts with an incremented
ban count (triggering escalation).

```elixir
observe_after_unban m(2)   # 2 minutes probation
```

### forget_after

If no events arrive for this duration, the actor process dies.
No garbage collection needed — process death is cleanup.

```elixir
forget_after m(5)   # 5 minutes idle → process dies
```

## Allowlist

IPs that are never banned, regardless of behavior.

```elixir
allowlist [
  {127, 0, 0, 1},        # localhost
  {10, 0, 0, 1},         # bridge gateway
  {10, 20, 30, 2}        # management host
]
```

## Kernel Integration

Bans are stored in nft sets with the `timeout` flag. The kernel
manages expiry autonomously:

```
$ nft list set inet erlkoenig blocklist

set blocklist {
    type ipv4_addr
    flags timeout
    elements = {
        79.124.59.130 timeout 1h expires 47m12s,
        83.241.136.174 timeout 24h expires 23h41m
    }
}
```

If the BEAM crashes, bans persist in the kernel and expire
on schedule. No orphaned bans, no manual cleanup.

## AMQP Events

All guard actions publish to `erlkoenig.events` (topic exchange):

| Routing Key | When | Payload |
|-------------|------|---------|
| `guard.threat.ban` | IP banned | ip, reason, duration, ban_count |
| `guard.threat.unban` | Ban expired | ip |
| `guard.threat.honeypot` | Honeypot triggered | ip, port, duration |
| `guard.threat.slow_scan` | Slow scanner | ip, ports, window |
| `guard.threat.suspect` | 3+ ports, no ban yet | ip, ports |
| `guard.threat.ban_failed` | Kernel ban failed | ip, reason |
| `guard.stats.summary` | Every 5s | actors, bans, events_seen |

## Architecture Details

### Per-IP Actors

Each actor is a `gen_statem` process (~500 bytes overhead).
Thousands can run concurrently. Each is fully isolated — a crash
for one IP has zero effect on any other.

The actor registry (IP → Pid) uses ETS with `ets:insert_new/2`
for race-free creation. The ETS table is owned by `ct_guard`
(a stable, long-lived process), not by the actor supervisor.

### Threat Mesh

The mesh tracks ban sources: `#{IP => #{Node => ExpiryMs}}`.
When multiple sources hold a ban for the same IP, the effective
expiry is `max(all sources)`. A local unban only removes the
local source — the kernel ban stays if a remote source is active.

Ban timestamps use `os:system_time(millisecond)` (epoch millis)
for cluster-wide comparability. On `nodeup`, all active bans
are re-broadcast for anti-entropy.

### Supervision Tree

```
erlkoenig_nft_sup (rest_for_one)
├── ...
├── erlkoenig_nft_ct_guard     ← event router, owns actor registry
├── erlkoenig_threat_sup       ← dynamic supervisor for actors
├── erlkoenig_threat_mesh      ← kernel ban gateway
├── ...
```
