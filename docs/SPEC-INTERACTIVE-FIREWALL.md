# Interactive Firewall Architecture

Status: review draft

This document proposes the target architecture for making the Erlkoenig firewall
interactive: not only applying nftables state, but observing live traffic,
detecting suspicious behavior, explaining it in operator terms, and reacting
through the existing threat pipeline. The core claim is simple: the right
foundation is **NFLOG plus Erlang event processes plus ontology-backed
explanation**, not shell scraping, journal parsing, or an external IDS bolted on
beside Erlkoenig.

## Goal

The operator should be able to ask and see live questions like:

```text
Were we scanned?
Why was 203.0.113.44 banned?
Which rule produced this drop counter?
Which pod or service was targeted?
Show me firewall events now.
Explain this nft event in terms of host/zone/ct ownership.
```

The first implemented CLI surface is:

```bash
ek firewall watch
ek firewall events --limit 20
ek nft counters
```

Later explanation and threat-inspection phases may add commands such as:

```bash
ek firewall explain-event <id>
ek nft ask "why is counter erlkoenig_host/banned high"
ek threat inspect 203.0.113.44
```

The deeper product behavior is:

```text
05:41:22 drop  src=203.0.113.44 table=erlkoenig_host chain=prerouting_ban counter=banned
05:41:24 scan  src=203.0.113.44 ports=22,80,443,5432 window=30s confidence=suspect
05:41:25 ban   src=203.0.113.44 duration=15m reason=slow_scan
```

This is different from a passive log stream. The firewall becomes an evented
runtime surface. Each event has machine-readable identity, source, rule context,
table ownership, packet metadata, and a path to a human explanation.

## Existing Erlkoenig Fit

Erlkoenig already has most of the right primitives:

* `erlkoenig_nft_nflog` receives NFLOG packets and broadcasts
  `{nflog_event, Event}` through the `nflog_events` pg group.
* `nfnl_nflog` owns the Netlink/NFLOG socket boundary.
* `erlkoenig_nft_events` broadcasts `ct_events`, `nflog_events`, and
  `counter_events`.
* `erlkoenig_amqp_nft_sub` subscribes to the internal event groups and bridges
  them to AMQP when enabled.
* `erlkoenig_nft_counter` and the watch supervisor already poll named counters
  and produce rates.
* `erlkoenig_nft_ct_guard` consumes conntrack events and routes suspicious IPs
  into per-IP threat actors.
* `erlkoenig_threat_actor`, `erlkoenig_threat_sup`, and
  `erlkoenig_threat_mesh` already model the Erlang-native part of this design:
  one process per suspicious source, timers, state transitions, and kernel ban
  enforcement through a single owner.

That means the proposal is not a rewrite. It is a contract and composition
layer over existing parts. The missing piece is a canonical firewall event
envelope and a correlation/explanation layer that joins NFLOG, counters,
conntrack, nft rule identity, and Erlkoenig's table-owned firewall model.

## Why NFLOG Is The Right Sensor

For interactive firewall behavior, Erlkoenig needs packet-level signals at the
rules that matter. Counters answer "how much"; conntrack answers "which flows";
NFLOG answers "which packet hit this instrumented rule right now".

NFLOG is the correct mechanism because it is structured and meant for userspace
packet observation. An nft rule can log selected packets to a numeric NFLOG
group. Erlkoenig can run one receiver per group and receive packet metadata over
Netlink. That metadata can include the layer 3 and layer 4 fields needed for
security decisions: source IP, destination IP, protocol, ports, packet length,
hook context, and prefix/group identity.

This is exactly the shape Erlang is good at. A receiver process owns the socket.
It parses bounded messages. It emits internal events. A per-IP actor aggregates
those events over time. A supervisor controls failure. Timers express windows
like "10 ports in 30 seconds" or "100 new connections in 10 seconds" naturally.

NFLOG is also controllable. Erlkoenig should not NFLOG every accepted packet.
The instrumented rules should be:

* default drops,
* ban-set hits,
* honeypot ports,
* rate-limit overflow,
* reject/drop rules with operator interest,
* selected zone-forward drops,
* later: explicit debug rules enabled temporarily by the operator.

That keeps event volume meaningful and prevents the interactive firewall from
becoming a packet capture product.

## Canonical Event Envelope

The next architectural unit should be a canonical event map. Today different
subsystems can emit different shapes. That is fine internally, but the operator
surface needs a stable representation.

Proposed envelope:

```erlang
#{
  id => <<"evt-...">>,
  ts_mono => integer(),
  ts_wall => integer(),
  source => nflog | counter | conntrack | threat,
  severity => info | notice | warning | critical,
  kind => firewall_packet | counter_rate | scan_suspect | threat_ban,

  table => <<"erlkoenig_host">>,
  table_owner => host | zone | ct | unknown,
  chain => <<"prerouting_ban">>,
  rule_ref => #{table => <<"erlkoenig_host">>, chain => <<"prerouting_ban">>, index => 1},
  counter => <<"banned">>,

  src_ip => <<"203.0.113.44">>,
  dst_ip => <<"10.20.30.2">>,
  proto => tcp | udp | icmp | unknown,
  src_port => 54321,
  dst_port => 22,
  verdict => drop | accept | reject | observe,

  reason => ban_set_hit | honeypot | default_drop | slow_scan | conn_flood,
  evidence => #{packets => 12, ports => [22, 80, 443], window_ms => 30000},
  labels => [firewall, threat, interactive]
}
```

The exact fields can change during implementation, but the contract should obey
these rules:

* Events are maps with stable atom keys internally.
* JSON encoding uses stable string keys.
* Packet payload is not stored by default.
* IPs are binary strings in operator surfaces, not new atoms.
* Every event has enough identity to be joined back to the nft table/rule world.
* If rule index is unavailable from the kernel event, Erlkoenig attaches it when
  compiling/applying the rule or uses a generated rule tag.

The event envelope is the hinge between low-level kernel observation and
high-level explanations.

## Correlation Model

An isolated dropped packet is usually not an incident. A scan is a pattern. The
interactive firewall therefore needs correlation, not just streaming.

The correlation layer should maintain time-windowed state keyed by source IP:

```text
source IP -> actor process -> recent ports, counters, chains, zones, decisions
```

The existing threat actor model is the right foundation. A per-IP process can
receive normalized events and update state:

* distinct destination ports seen in the last window,
* honeypot ports touched,
* ban-set hits,
* target zones/pods/services,
* connection rates,
* counter deltas,
* previous warnings or bans.

When thresholds are crossed, the actor emits a higher-level event:

```erlang
#{kind => scan_suspect,
  src_ip => <<"203.0.113.44">>,
  evidence => #{ports => [22, 80, 443, 5432], window_ms => 30000}}
```

If the policy says to enforce, the actor asks `erlkoenig_threat_mesh` for a ban.
The mesh remains the single kernel-ban writer. That preserves the same explicit
ownership principle used in the nft ownership split: one process owns mutation;
other processes send intentions.

## Ontology Role

The ontology should not read NFLOG sockets and should not SSH into hosts. Its
role is explanation and relationship modeling.

Runtime Erlkoenig has the live facts:

* current nft table terms,
* rule identity,
* counters and rates,
* NFLOG packet events,
* container/pod/service metadata,
* threat actor state,
* active bans.

The ontology layer should turn those facts into a queryable world:

```text
packet event -> rule -> chain -> table owner -> pod/zone/service -> decision
```

This is where operator questions become valuable:

```text
"why was this IP banned?"
  because it hit 7 distinct ports in 30 seconds,
  including honeypot port 23,
  then hit erlkoenig_host/prerouting_ban[1],
  and threat_mesh applied a 15 minute ban.

"what was targeted?"
  host ssh, zone webserver, postgres service.
```

The ontology should stay data-native: it consumes maps/lists from Erlkoenig,
not files as the primary interface. File snapshots remain useful for tests,
offline debugging, bug reports, and demos.

## Operator Surfaces

The first interactive surface should be CLI, not a web UI. CLI is lower risk,
fits the current operator model, and validates the event contract.

Implemented commands:

```bash
ek firewall watch
ek firewall events --limit 20
ek nft counters
```

Proposed follow-up commands:

```bash
ek firewall explain-event <id>
ek threat list
ek threat inspect <ip>
ek nft ask "why is counter erlkoenig_host/banned high"
```

AMQP remains a machine integration surface:

```text
firewall.<chain>.packet
firewall.<chain>.drop
guard.threat.suspect
guard.threat.slow_scan
guard.threat.ban
guard.threat.unban
```

Later, a dashboard can subscribe to the same event stream. The dashboard must
not invent a second event model. It should render the same envelopes that `ek`
shows and that AMQP publishes.

## RabbitMQ / AMQP Symbiosis

RabbitMQ fits this architecture well when used as an external distribution
surface, not as the local decision engine. Erlkoenig already has an AMQP event
contract in `docs/AMQP_EVENTS.md`, an AMQP codec, a publisher, and
`erlkoenig_amqp_nft_sub`, which joins the internal nft pg groups:

* `control_events`
* `ct_events`
* `nflog_events`
* `counter_events`
* `ct_guard_events`

That is almost exactly the event topology the interactive firewall needs. The
internal Erlang runtime can keep fast local decisions inside OTP processes,
while RabbitMQ fans out normalized results to dashboards, SIEM consumers,
automation, and long-running analytics.

The clean boundary is:

```text
local enforcement path:
  NFLOG / counters / conntrack
    -> Erlang sensors
    -> canonical firewall event
    -> threat actor
    -> threat_mesh
    -> kernel ban

external visibility path:
  canonical firewall event
    -> erlkoenig_amqp_codec
    -> RabbitMQ topic exchange
    -> dashboard / SIEM / archive / notification worker
```

RabbitMQ should therefore receive events like:

```text
firewall.<chain>.packet
firewall.<chain>.drop
firewall.<name>.threshold
guard.threat.suspect
guard.threat.slow_scan
guard.threat.ban
guard.threat.unban
guard.stats.summary
```

These families already exist in the AMQP contract. The implementation work is
to make the new canonical firewall envelope encode cleanly into those families
without creating a second shape that only AMQP understands.

Good RabbitMQ use cases:

* **Dashboard fan-out.** A web UI can subscribe to `firewall.#` and
  `guard.threat.#` without polling `ek`.
* **Notifications.** A small worker can subscribe to `guard.threat.ban` and
  send Slack, email, PagerDuty, or Matrix notifications.
* **SIEM ingestion.** Security tooling can bind to `guard.threat.#`,
  `firewall.#`, and `error.threat.#`.
* **Audit/archive.** A durable queue can retain security-relevant envelopes for
  later incident review.
* **Multi-consumer decoupling.** Adding an observer should not add load to the
  NFLOG receiver or threat actor.
* **Remote UI.** A dashboard can live off-host without opening direct Erlang
  distribution or shell access.

Bad RabbitMQ use cases:

* **Local ban decisions.** Erlkoenig must not publish an event to RabbitMQ and
  wait for a consumer to decide whether to ban. Broker outage would become a
  firewall outage.
* **Internal state recovery.** Threat actor state should not depend on replaying
  AMQP messages. OTP state and Erlkoenig snapshots own local runtime truth.
* **Packet backpressure control.** NFLOG load shedding must happen before AMQP.
  RabbitMQ confirms or queue depth are too late to protect the Netlink receiver.
* **A second schema.** AMQP payloads should be encoded from the canonical event
  envelope; they should not invent parallel field names.

Operationally, AMQP publishing is off by default today. That is the correct
fail-closed posture: a misconfigured broker must not wedge the firewall. For an
interactive deployment, enabling AMQP should add observability and remote
notifications, but the CLI and local threat enforcement must continue to work
when RabbitMQ is disabled or unavailable.

## Good Alternatives

### Counter-first detection

Counters are good for cheap, continuous telemetry. They are low volume and easy
to expose. A counter spike can trigger "something is happening". This is already
partially present in Erlkoenig.

Counter-first detection is good for:

* top noisy rules,
* rate thresholds,
* "banned counter is increasing",
* dashboards,
* low overhead monitoring.

It is insufficient alone because a counter does not identify source IP, port
mix, or target service. It can tell the operator a rule is hot, but not who is
scanning or what was targeted. So counters should trigger attention and provide
rates, while NFLOG and conntrack provide attribution.

### Conntrack-first detection

Conntrack events are excellent for connection behavior: floods, new-flow rate,
source IP behavior, and port-scan patterns. Erlkoenig already has `ct_guard`
and threat actors, so this is a strong base.

Conntrack-first is good for:

* connection floods,
* slow scans across ports,
* per-source state machines,
* bans based on flow behavior.

It is weaker for rule-level explanation. Conntrack says a flow existed; it does
not naturally say "this nft rule dropped that packet" or "this ban-set rule was
hit". NFLOG complements conntrack by attaching packet/rule context.

### AMQP-first integration

AMQP is a good external integration contract. Existing docs already describe
firewall and threat routing keys. It is useful for dashboards, SIEM pipelines,
and external automation.

AMQP should not be the internal source of truth. Erlkoenig should publish AMQP
from its internal event model, not consume its own AMQP events to decide local
security action. Local enforcement must stay inside Erlang supervision and
threat_mesh to avoid latency, broker dependency, and ambiguous failure modes.

## Bad Alternatives

### Parsing `journalctl` or kernel log strings

This is the tempting shortcut when nft `log` already writes visible messages.
It is the wrong foundation for an interactive firewall.

Problems:

* strings are not a stable API,
* parsing log lines loses typed data,
* kernel/journal rate limiting can hide events,
* multiple tools may write similar prefixes,
* correlation back to Erlkoenig rule identity is fragile,
* there is no clean backpressure or supervision path.

Journal logs are useful as a human fallback. They should not drive detection.

### Running `nft monitor` as the main sensor

`nft monitor` is useful for debugging ruleset changes, not for high-quality
packet/rule event handling. It is process-output driven, format-sensitive, and
awkward to supervise as the core runtime sensor. Erlkoenig already has Netlink
code; it should own Netlink directly.

### Shelling out to `nft -j list counters` in a loop

This was useful for the ontology prototype because the installed host did not
yet have `ek nft counters`. It is not the target architecture.

Problems:

* polling whole counter dumps is coarse,
* rates require local delta logic,
* it bypasses existing Erlang counter workers,
* it cannot produce per-packet attribution,
* it creates another runtime truth path.

The correct path is the existing Erlang counter watchers and operator API.

### External IDS as the primary brain

Tools like Suricata or Zeek are powerful, but making one of them the primary
Erlkoenig firewall brain would weaken the product architecture. Erlkoenig
already owns the runtime, containers, nft tables, counters, and bans. External
IDS can be integrated later as another sensor, but not as the first source of
truth.

If external IDS events arrive later, they should enter the same canonical event
envelope as `source => external_ids`, then be correlated by the same actors and
explained by the same ontology.

## Safety Constraints

Interactivity must not mean noisy or dangerous automation.

Required constraints:

* NFLOG only selected rules by default.
* Never capture or store packet payload by default.
* Bound event queue sizes and drop low-severity samples first.
* Per-source actors must expire when idle.
* Bans go through `erlkoenig_threat_mesh`, never direct from NFLOG receiver.
* Whitelist checks happen before enforcement.
* Operator lockout preflight must consider threat/honeypot policy.
* Event JSON is a contract and needs decoded-structure tests.
* Unknown event fields should be preserved as diagnostics, not crash detection.

Two risks deserve explicit design treatment rather than a later operational
note.

### NFLOG saturation

Even if Erlkoenig instruments only selected rules, an attacker can deliberately
hammer an instrumented rule: a honeypot port, a default-drop path, or a ban-set
hit. That can create an NFLOG storm. The system must treat NFLOG as an
attacker-adjacent input, not as a trusted low-volume telemetry channel.

Required mitigations:

* Configure bounded Netlink socket buffers and document the default.
* Keep NFLOG receivers small: parse, normalize, enqueue or drop. They should
  not run expensive correlation logic inline.
* Add per-group and global event queue limits.
* Drop low-severity packet samples before dropping threat decisions.
* Emit a `firewall_nflog_dropped` or equivalent health event when load shedding
  happens, with counters for dropped samples.
* Prefer sampling on very noisy observe rules.
* Keep packet payload capture disabled by default; header metadata is enough
  for the interactive firewall use case.

The important product behavior is that overload degrades explanation fidelity,
not node stability and not kernel enforcement. If packet samples are dropped,
counters and conntrack still continue to provide coarse detection signals.

### Actor cardinality and IP churn

The per-source actor model is the right shape for correlation, but it has an
obvious abuse case: a distributed or spoofed scan can touch the host from
thousands of source addresses. Spawning one actor per source without admission
control would turn the correlation layer into a process-count attack surface.

Required mitigations:

* Aggressive idle timeouts for actors with low evidence.
* A global cap on live threat actors.
* A cheaper pre-actor sketch or ETS bucket for first sightings, so Erlkoenig
  only starts an actor after a source crosses a low threshold.
* LRU-style eviction for lowest-severity actors when the cap is reached.
* Metrics for actor count, actor starts, actor evictions, and dropped dispatches.
* Whitelist handling before actor creation where possible.
* Clear operator health output when detection is degraded by actor pressure.

This keeps the actor model as a correlation tool, not as an unbounded allocation
policy.

## Interactive Correlation Simulator

A useful review and demo artifact for Phase 3 is a tiny simulator that models
the threat actor state machine without touching nftables. It should accept
synthetic packet events and show how isolated NFLOG observations become
operator-level decisions.

Example interaction:

```text
event src=203.0.113.44 dst_port=22 action=drop
event src=203.0.113.44 dst_port=80 action=drop
event src=203.0.113.44 dst_port=443 action=drop
event src=203.0.113.44 dst_port=5432 action=drop

actor 203.0.113.44:
  state=suspect
  ports=[22,80,443,5432]
  window=30s
  decision=scan_suspect
```

The simulator should be intentionally separate from enforcement. Its purpose is
to validate thresholds, event envelopes, and operator language before wiring the
same model into live NFLOG and conntrack events. It can start as a test helper
or example script, then later become a documentation/demo command.

## Implementation Phases

### Phase 1: Event envelope and watch command

Add an internal module that normalizes raw NFLOG/counter/guard events into the
canonical event envelope. Add `ek firewall watch` for live event streaming from
the operator API. Start with existing events; do not change firewall rules yet.

Exit criteria:

* `ek firewall watch --format json` emits stable JSON envelopes.
* Unit tests cover NFLOG, counter, and guard inputs.
* AMQP bridge can publish the same envelope shape.

### Phase 2: NFLOG rule instrumentation contract

Define which DSL rule forms emit NFLOG. Prefer explicit operator intent:

```elixir
nft_host do
  nft_nflog_group 1, name: "host"

  base_chain "input", hook: :input, type: :filter,
    priority: :filter, policy: :drop do
    nft_rule :drop, counter: "input_drop",
      log_prefix: "HOST: ", nflog_group: 1
  end
end
```

NFLOG ownership metadata must come from the explicit group declaration in the
DSL/IR, not from chain names, table names, prefixes, or numeric conventions.
Default instrumentation can be added for ban-set hits and honeypots, but it
must be documented and backed by the same explicit group registry.

Exit criteria:

* Applied nft rules start the required NFLOG receivers.
* Receivers are stable per table/zone/group.
* A logged DSL rule without `nflog_group: N` fails validation.
* A rule referencing `nflog_group: N` requires `nft_nflog_group N` in the
  enclosing owner block.
* Reload removes stale receivers or marks them inactive.

### Phase 3: Correlation actors

Route normalized packet events into per-source threat actors. Reuse the current
ct_guard actor pattern rather than creating a second actor system.

The first implementation slice should stay pure: `erlkoenig_firewall_correlator`
accepts canonical events, applies the same time-window rules, and returns
higher-level canonical decisions. That module is the reviewable simulation core.
Only after the event language and thresholds are stable should the live
`erlkoenig_threat_actor` path call the same logic from per-source processes.

Exit criteria:

* A source touching many ports emits `scan_suspect`.
* Honeypot hits emit `honeypot`.
* Enforcement requests still go through threat_mesh.
* Actor state is inspectable via `ek threat inspect`.

### Phase 4: Ontology-backed explanation

Join event envelopes with the live nft world and container/zone metadata.

Exit criteria:

* `ek firewall explain-event <id>` shows rule, chain, table owner, counter,
  source IP, target service when known, and threat decision.
* Offline snapshots can reproduce the same explanation in
  `erlkoenig_ontology`.

### Phase 5: Dashboard/API

Only after the CLI and event contract are stable, expose a richer UI through
AMQP, SSE, or WebSocket. The dashboard renders events and explanations; it does
not invent detection logic.

## Recommendation

The right approach is to make Erlkoenig's firewall interactive from inside the
runtime:

```text
nftables kernel
  -> Netlink NFLOG/counters/conntrack
  -> Erlang supervised sensors
  -> canonical firewall events
  -> per-source threat actors
  -> threat_mesh enforcement
  -> ontology-backed explanation
  -> ek / AMQP / dashboard
```

This fits Erlkoenig's architecture and avoids hidden ownership. The kernel owns
packet matching, Erlkoenig owns runtime interpretation and enforcement,
threat_mesh owns bans, and the ontology owns explanation. That separation is
strong enough to build an operator-grade interactive firewall without turning
the system into a pile of log parsers or a thin wrapper around external tools.
