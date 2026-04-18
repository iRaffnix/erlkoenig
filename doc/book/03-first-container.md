# Chapter 3 — Your First Stack

Fifteen minutes, one `.exs` file, three containers, real tier isolation
proven end-to-end. Prerequisite: erlkoenig is installed and the systemd
service is up (→ Chapter 2).

Everything in this chapter runs through the operator CLI `ek`. The
underlying `erlkoenig eval` / `erlkoenig_config:load/1` path still
exists and is documented in → Chapter 18; `ek` is the convenience
wrapper that knows how to compile DSL, load, reconcile, and stop.

## Sanity check

Before writing anything, confirm the node is reachable:

```bash
ek node ping
# → pong

ek node version
# → 0.6.0
```

If you get `can't reach erlkoenig at ...`, the service is not running
or the cookie file is in a non-default location. Back to → Chapter 2.

## What you will build

A two-tier stack:

```
          ┌─── 10.99.0.2 app-0-web ─┐
  host ───┤                         ├─── 10.99.0.4 app-0-api
          └─── 10.99.0.3 app-1-web ─┘
```

Two web replicas on port 8080, one api on port 4000, both sitting in
an IPVLAN-L3S zone on a dummy parent `ek_tut`. Web may call api; api
may not call web back; peer web-to-web is denied. The host firewall
drops everything on `input` except SSH, loopback, ICMP, and return
traffic.

## Step 1: Write the stack file

The release ships the file ready to go:

```bash
cp /opt/erlkoenig/examples/tutorial.exs ~/tutorial.exs
```

The file is reproduced below without comments so you can read the
structure in one pass. The version on disk carries additional
explanatory banners — the Erlang behaviour is identical:

```elixir
defmodule Tutorial do
  use Erlkoenig.Stack

  pod "app", strategy: :one_for_one do

    container "web",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["8080"],
      zone: "tutorial",
      replicas: 2,
      restart: :permanent,
      limits: %{memory: 128_000_000, pids: 64} do

      publish interval: 2000 do
        metric :memory
        metric :cpu
        metric :pids
      end

      stream retention: {7, :days} do
        channel :stdout
        channel :stderr
      end

      nft do
        input policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_protocol: :icmp
          nft_rule :accept, tcp_dport: 8080
        end

        output policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_protocol: :icmp
          nft_rule :accept, ip_daddr: {10, 99, 0, 4}, tcp_dport: 4000
          nft_rule :accept, ip_daddr: {10, 99, 0, 1}
        end
      end
    end

    container "api",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["4000"],
      zone: "tutorial",
      replicas: 1,
      restart: :transient,
      limits: %{memory: 256_000_000, pids: 128} do

      publish interval: 2000 do
        metric :memory
        metric :cpu
      end

      nft do
        input policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_protocol: :icmp
          nft_rule :accept, ip_saddr: {10, 99, 0, 2}, tcp_dport: 4000
          nft_rule :accept, ip_saddr: {10, 99, 0, 3}, tcp_dport: 4000
        end

        output policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_protocol: :icmp
          nft_rule :accept, ip_daddr: {10, 99, 0, 1}
        end
      end
    end
  end

  host do
    ipvlan "tutorial",
      parent: {:dummy, "ek_tut"},
      subnet: {10, 99, 0, 0, 24}

    nft_table :inet, "host" do
      nft_set "ban", :ipv4_addr
      nft_counter "input_drop"
      nft_counter "input_ban"

      base_chain "prerouting", hook: :prerouting, type: :filter,
        priority: :raw, policy: :accept do
        nft_rule :drop, set: "ban", counter: "input_ban"
      end

      base_chain "input", hook: :input, type: :filter,
        priority: :filter, policy: :drop do

        # ── Standard hardening ──────────────────────────────
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp
        nft_rule :accept, tcp_dport: 22222          # SSH

        # ── Runtime services ────────────────────────────────
        # erlkoenig's per-zone DNS resolver listens on the
        # gateway IP. Without this rule, every getaddrinfo()
        # inside containers times out. → Chapter 6 explains.
        nft_rule :accept, ip_saddr: {10, 99, 0, 0, 24}, udp_dport: 53

        nft_rule :drop, counter: "input_drop", log_prefix: "HOST-DROP: "
      end
    end
  end

  guard do
    detect do
      flood over: 50, within: s(10)
      port_scan over: 20, within: m(1)
      honeypot [21, 22, 23, 445, 1433, 3306, 3389, 5900, 6379]
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
      {10, 99, 0, 1}
    ]
  end
end
```

Three blocks, three distinct concepts:

- **`pod "app"`** — OTP supervisor group. Two container specs: `web`
  (replicas 2, `:permanent`) and `api` (replicas 1, `:transient`).
  Each container carries its own `nft do ... end` — the firewall that
  erlkoenig installs inside that container's network namespace.
- **`host do ... end`** — the zone (IPVLAN-L3S on dummy parent
  `ek_tut`, subnet 10.99.0.0/24) plus the host-side nft table that
  protects the BEAM node itself.
- **`guard do ... end`** — per-IP threat-detection policy.

These layer onto each other but stay independent: pod drives restart,
zone decides who can address whom, per-container netns + nft drives
who actually gets through. → Chapter 5 has the full model.

**SSH port.** The host-firewall `input` chain above accepts
`tcp_dport: 22222`. If your sshd listens on a different port, change
that number in the stack file **before** `ek up` — otherwise the
reload will drop your session.

## Step 2: Bring it up

```bash
ek up ~/tutorial.exs
```

Expected output (order of names may vary):

```
compiled /root/tutorial.exs -> /root/tutorial.term
up: 3 container(s) running
  app-0-web, app-0-api, app-1-web
```

`ek up` may also print one or two `=NOTICE REPORT===` lines from the
remote logger (firewall install + guard reconfigure). Those travel
over the RPC's standard-I/O channel and are informational — not
errors. If you need them reliably, check `journalctl -u erlkoenig`
instead.

`ek up` accepts `.exs` or `.term`. With `.exs` the bundled Elixir
runtime compiles the DSL in a short-lived subprocess and writes the
`.term` next to the source. Subsequent `ek up` calls on the same file
are idempotent — only drifted containers restart (→ Step 6).

To confirm the firewall landed:

```bash
nft list table inet host
```

— shows the `input` chain with the rules from the stack file.

## Step 3: Observe

Three views of the running stack:

```bash
ek ps
```

```
name       state    ip         zone      restart_count
---------  -------  ---------  --------  -------------
app-0-web  running  10.99.0.2  tutorial  0
app-1-web  running  10.99.0.3  tutorial  0
app-0-api  running  10.99.0.4  tutorial  0
```

```bash
ek pod list
```

```
name   pid             children
-----  --------------  --------
app-0  <0.987.0>       2
app-1  <0.990.0>       1
```

Two pod supervisors, because the web container's `replicas: 2` expands
into two pod instances — `app-0` carries the replica-0 web *and* the
api, `app-1` carries only the replica-1 web.

Naming rule: `<pod>-<replica-idx>-<container>`. The api has `replicas:
1`, so `app-0-api` is the only api process.

```bash
ek ct inspect app-0-web
```

...shows the full gen_statem map: `state`, `os_pid`, `netns_path`,
`stats`, `net_info`, and so on. Add `--format json` if you want to
pipe it through `jq` or `python -m json.tool`.

Try a roundtrip from the host:

```bash
echo hello | nc -w2 10.99.0.2 8080        # web-0 → echoes "hello"
echo hello | nc -w2 10.99.0.3 8080        # web-1 → echoes "hello"
echo hello | nc -w2 10.99.0.4 4000        # api   → silent, BLOCKED
```

The third one doesn't reply: api's input chain accepts only from
`10.99.0.2` and `10.99.0.3`. The host sits on `10.99.0.1` (the
IPVLAN-L3S host-side slave `h.ek_tut`), which is not in the allow
list. That is the point — api is reachable from web, not from
operators.

## Step 4: Prove the isolation

Enter the netns of one of the containers and call out from inside:

```bash
NG=$(ek --format json ct inspect app-0-web | \
       python3 -c 'import json,sys; print(json.load(sys.stdin)["netns_path"])')
AP=$(ek --format json ct inspect app-0-api | \
       python3 -c 'import json,sys; print(json.load(sys.stdin)["netns_path"])')

# web → api:4000 (allowed)
echo web-to-api | nsenter --net=$NG nc -w2 10.99.0.4 4000
# → web-to-api

# api → web:8080 (blocked)
timeout 2 nsenter --net=$AP nc -w1 10.99.0.2 8080 < /dev/null \
  && echo LEAK || echo BLOCKED
# → BLOCKED

# web-0 → web-1:8080 (blocked, peer-tier jump)
timeout 2 nsenter --net=$NG nc -w1 10.99.0.3 8080 < /dev/null \
  && echo LEAK || echo BLOCKED
# → BLOCKED
```

The first command echoes `web-to-api`. The other two print `BLOCKED`.
You can inspect the live rules with:

```bash
nsenter --net=$NG nft list table inet ct_container
```

— that's the firewall table erlkoenig writes into the container's
netns when it spawns.

## Step 5: Restart semantics

Kill one web container's OS process directly, bypassing erlkoenig:

```bash
OSPID=$(ek --format json ct inspect app-0-web | \
          python3 -c 'import json,sys; print(json.load(sys.stdin)["os_pid"])')
kill -KILL $OSPID

# Poll until the new gen_statem has re-entered the erlkoenig_cts
# process group. During the transient stopped → restarting → creating
# window `ek ct inspect` returns "container not found"; wait it out.
until ek ct inspect app-0-web 2>/dev/null | grep -q '^state .*running'; do
  sleep 1
done
ek ct inspect app-0-web | grep -E '^(state|os_pid|restart_count)'
echo hi | nc -w2 10.99.0.2 8080
```

A new `os_pid`, `restart_count: 1`, and the echo works. The
`restart: :permanent` policy makes the pod supervisor bring the
container back; the IPVLAN slave is recreated, the nft rules are
reinstalled in the new netns. Clients see a brief connection blip and
then the service again.

`ek ct inspect` also shows `restart always` — not a typo, and not an
override. The DSL's OTP-style terms (`:permanent`, `:transient`,
`:temporary`) are mapped onto erlkoenig's internal policy names
(`always`, `on_failure`, `no_restart`) at load time. Same semantics,
older naming surfaces through `inspect`.

## Step 6: Drift detection

Change a field in the DSL that the runtime cares about — the port the
web app listens on — and reload. Remember to update **both** the
`args` and the `nft_rule :accept, tcp_dport:` lines. erlkoenig does
not synchronise application config with firewall rules; the stack file
is the single source of truth:

```bash
sed -i 's/"8080"/"8888"/'              ~/tutorial.exs
sed -i 's/tcp_dport: 8080/tcp_dport: 8888/' ~/tutorial.exs
ek up ~/tutorial.exs
```

Output:

```
up: 2 container(s) running
  app-0-web, app-1-web
```

Only the two web containers restart — `args` and `nft` are on the
drift field list, api was not touched, so its state machine keeps
running. `ek ct inspect app-0-web | grep args` shows the new argument;
`echo drift | nc 10.99.0.2 8888` now works, `... 10.99.0.2 8080` now
does not.

`restart_count` carries across the reconcile: the web container that
was already at `1` from Step 5 is at `2` after the drift-driven
restart. The counter lives in `persistent_term` keyed by container
name, so teardown-and-respawn under the same name bumps it rather
than resetting. A container only returns to zero when its name
disappears from the stack file entirely.

The drift check compares old and new config per container on
`binary, args, zone, limits, seccomp, uid, gid, caps, volumes, image,
publish, stream, nft, restart`. Anything else in the container map is
noise and does not trigger a restart.

## Step 7: Down

Two variants:

```bash
ek down ~/tutorial.exs
```

```
compiled /root/tutorial.exs -> /root/tutorial.term
down: stopped 3/3 container(s)
```

```bash
ek down
```

```
down: nothing running
```

`down <file>` reads the declared names out of the term and stops each
by name. `down` alone takes the live process-group list and stops all
of it — useful as an emergency brake.

## Cleanup

Reset the ports in the local `.exs` so a later run of this chapter
starts from a known state, and verify the node is quiet:

```bash
sed -i 's/"8888"/"8080"/'              ~/tutorial.exs
sed -i 's/tcp_dport: 8888/tcp_dport: 8080/' ~/tutorial.exs
ek down
ek ps
ek pod list
```

Expected:

```
down: nothing running
name  state  ip  zone  restart_count
----  -----  --  ----  -------------
name  pid  children
----  ---  --------
```

The zone dummy `ek_tut` and its host-side slave `h.ek_tut` stay on
the host even after `ek down` — they are per-zone kernel state, not
per-container. They'll be reused on the next `ek up`. If you want a
fully clean host, `ip link del ek_tut` removes the dummy and the
host-slave together.

## Common pitfalls

**SSH port mismatch.** The host `nft_table` in `tutorial.exs`
whitelists port 22222. Applying the stack on a box whose sshd listens
elsewhere drops your session the moment `ek up` reloads the firewall.
Always confirm the `tcp_dport:` values match your sshd configuration
before loading.

**App port changed but firewall didn't.** Editing `args:` without
updating the matching `tcp_dport:` in the container's `nft input`
chain leaves you with a silently unreachable container: the app binds
the new port, the netns drops packets for it. Step 6 demonstrates the
correct dual edit.

**Zone parent conflict.** Two stacks referencing the same dummy name
under `ipvlan "...", parent: {:dummy, "ek_shared"}` share one parent
interface and one IP pool — usually intended, occasionally surprising.
Pick a unique dummy name per stack for true separation.

**Stale zone dummies.** `ek down` leaves `ek_<zone>` and `h.ek_<zone>`
in place. They cost nothing and speed up the next `ek up`; remove
them manually with `ip link del ek_<zone>` for a spotless host.

## What you have now

You can write, compile, load, inspect, test, edit, reload, and stop a
stack. You have seen real L3S isolation between containers, pod-driven
restart, drift-aware reconcile, and the CLI surfaces that operators
use day-to-day.

From here, the book goes deep on the individual subsystems:

- **Container options in depth** (restart policies, limits, caps,
  seccomp) → Chapter 4
- **IPVLAN L3S, zones, DNS, host-slave** → Chapter 5
- **Firewall rules — host and per-container** → Chapter 6
- **Threat detection, honeypots, ban propagation** → Chapter 7
- **Persistent volumes with XFS project quotas** → Chapter 8
- **Observability: cgroup stats, log streams, AMQP** → Chapter 9
- **Operator CLI reference** → Chapter 18
