## Chapter 22 — DNS Egress Allowlist

The sandbox claim — *"you ship a static binary, we guarantee what
it can reach"* — needs more than L4 nftables. A container that's
allowed to talk to TCP/443 can still reach any host on the
internet: curl, pip, a beaconing dependency, an LLM that convinced
the agent to POST secrets. The allow-list that actually matters is
at the name layer.

Chapter 22 introduces the `:"dns.allowlist"` capability: a
declarative, per-container DNS filter that answers any unapproved
lookup with authoritative NXDOMAIN and routes the decision into
the audit chain. It is the **L7 half of SPEC-AS-009**; the L4 half
(which ports the container may reach) stays where it always has —
in the operator's `nft output` block.

This chapter covers what the capability does, how the two layers
compose, the full matcher semantics, how registrations flow
through the container lifecycle, and what this deliberately does
*not* do. The worked example at the end runs inside the case_mgmt
showcase (→ Chapter 21).

---

## Why name-based filtering

A sandboxed container typically needs to talk to a handful of
well-known destinations: the tenant's Postgres, an inference API,
a blob store. Everything else is noise at best, exfiltration at
worst. Restricting by IP range works for a fixed Postgres but
falls apart for `api.openai.com` behind anycast CDNs with
rotating IP blocks.

Name-based filtering inverts the problem: the tenant declares
which **names** a container may resolve. Anything else returns
NXDOMAIN and is recorded. The agent can still try to connect to
a raw IP, but it'll be missing DNS-returned addresses for
everything it didn't declare — and combined with operator-owned
L4 policy, the reachable set is the intersection of the two.

## The Glasbox split: operator-L4, platform-L7

erlkoenig does not auto-inject firewall rules from capability
declarations. That would break the principle laid down in
Chapter 19: *the operator reads the stack file and sees
everything the container can reach.* If capabilities silently
widened the output chain, that reading would be a lie.

The rule for this chapter:

| Layer | Owned by | Written where | Effect |
|-------|----------|---------------|--------|
| L4 egress (ports, CIDRs) | **Operator** | `nft output` block in the container's DSL | Which IP:port pairs the container can even attempt to reach |
| L7 DNS allowlist | **Platform** (via capability) | `requires :"dns.allowlist", hosts: [...]` | Which hostnames the per-zone resolver will return addresses for |

Both must agree for a destination to be reachable. A container
with `requires :"dns.allowlist", hosts: ["api.openai.com"]` but
no `tcp_dport: 443 accept` in its `nft output` will resolve
OpenAI's IP and then get packet-dropped. A container with port
443 open but no `dns.allowlist` entry for the target will fail
at name resolution. The layers are multiplicative.

> **Why not auto-inject L4?** Because a stack file you can't read
> is a stack file you can't review. The test for whether a
> capability is too magical is: *given only the DSL source, could
> a reviewer tell me every hostname and port this container can
> reach?* With the Glasbox split the answer is yes.

## DSL syntax

The capability is declared inside a `container` block like any
other `requires`, with one extra keyword list:

```elixir
pod "case_mgmt", strategy: :one_for_one do
  container "agent",
    binary: "/opt/erlkoenig/rt/demo/case_mgmt",
    zone: "ops" do
    # ── Capabilities ────────────────────────────────────────
    requires :"postgres.local"
    requires :"journal.local"
    requires :"dns.local"

    # L7 egress allowlist — operator-visible, platform-enforced.
    requires :"dns.allowlist",
      hosts: [
        "api.openai.com",
        "*.s3.amazonaws.com",
        "*.postgres.internal"
      ]

    # ── L4 policy stays explicit ────────────────────────────
    nft do
      output policy: :drop do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, ip_daddr: {10, 70, 0, 1}, udp_dport: 53
        nft_rule :accept, tcp_dport: 443
      end
    end
  end
end
```

Two kinds of pattern are supported:

| Pattern | Matches | Does NOT match |
|---------|---------|----------------|
| `"api.openai.com"` | exact `api.openai.com` (case-insensitive, trailing dot tolerated) | `foo.api.openai.com`, `openai.com` |
| `"*.s3.amazonaws.com"` | any label prefix: `a.s3.amazonaws.com`, `my-bucket.eu-west-1.s3.amazonaws.com` | `s3.amazonaws.com` (bare), `evil-s3.amazonaws.com` |

Patterns are compiled once at registration into internal tuples
(`{:exact, Name}` / `{:suffix, Dotted}`). The hot path of every
DNS query is a single ETS lookup by source IP plus a short
pattern walk.

### Compile-time validation

The DSL rejects nonsense at `mix compile` time, not at runtime:

- **Empty list** → `CompileError: needs a non-empty :hosts list`
- **Missing `:hosts` key** → same error
- **Non-string patterns** → `CompileError: host pattern must be a
  non-empty string`
- **Unknown capability name** → `ArgumentError: unknown capability
  :foo; known: […]`

A typo in a hostname obviously cannot be caught — `"opnai.com"`
compiles fine and denies everything. The audit chain picks this
up at the first production request.

## Runtime lifecycle

The capability's effect is a pair of calls wired into
`erlkoenig_ct` next to the existing DNS-name registration
(→ `dns_register/1`):

```
  container spawn → DSL emits dns_allowlist => [Host, ...] in opts
  ↓
  erlkoenig_ct init/1 populates #ct_data{dns_allowlist = Hosts}
  ↓
  running(enter) → dns_filter_register(Data)
     → erlkoenig_dns_filter:register_allowlist(Ip, Hosts)
     → compile_patterns/1 + ETS insert
  ↓
  container runs; queries to per-zone DNS are filtered
  ↓
  stopped(enter) → dns_filter_unregister(Data)
     → erlkoenig_dns_filter:unregister(Ip)
     → ETS delete — next tenant of this IP starts clean
```

A container without the capability never appears in the filter's
ETS; queries from its source IP return `:no_filter` from
`check/2` and flow through to upstream as always. The filter is a
net **addition**, never a subtraction, for workloads that don't
declare it.

### Fail-open

If `erlkoenig_dns_filter` is somehow missing (a staged rollout,
a crashed supervisor, a test harness that skipped the child),
`check/2` catches the ETS-table-missing error and returns
`:no_filter`. DNS keeps working for everyone; the capability
simply stops enforcing until the filter recovers. The alternative
— fail-closed — would take down every container's name resolution
the moment this one subsystem glitched, and that cost isn't
justified for a policy layer that only tightens defaults.

## What happens on deny

When `erlkoenig_dns` receives a query from a filtered source IP
and the name isn't in the allowlist, it:

1. Emits an audit event of type `dns_filter` with `result = deny`,
   subject set to the source IP, and `details = {query, reason}`.
   This lands in the hash chain (→ Chapter 19) and the seal
   (→ Chapter 20).
2. Synthesises an authoritative NXDOMAIN response with AA=1 and
   sends it back to the container on the DNS server's socket.
3. **Does not** forward the query to the upstream resolver. No
   traffic leaves the node for denied names.

The AA=1 bit is the test's easy knob: an upstream NXDOMAIN comes
back with AA=0, so integration tests can distinguish
filter-NXDOMAIN from upstream-NXDOMAIN without parsing content.

An allowed name is forwarded exactly as before — the filter
decision is a **veto over forwarding**, not a replacement for it.
Upstream behaviour is unchanged.

## Example audit entries

A denied lookup produces one line in the chain (one fact per
line, trimmed to the load-bearing fields):

```json
{
  "seq": 123,
  "ts": "2026-04-20T10:32:39Z",
  "type": "dns_filter",
  "subject": "10.0.0.210",
  "result": "deny",
  "query": "evil.com",
  "reason": "not_in_allowlist",
  "prev_hash": "e208…0816",
  "this_hash": "c685…f95b",
  "signature": "6adf…0d0c"
}
```

The Go verifier (`make verifier`, → Chapter 20) recomputes the
hash chain and Ed25519 signature with no knowledge of what
`dns_filter` means — the event is opaque to the verifier, only
the canonical JSON + chain structure matter. That separation is
deliberate: future capabilities add new event types without
breaking customer verification binaries.

## Showcase wiring

The showcase stack source from Chapter 21,
`examples/showcase/case_mgmt_stack.exs`, already declares the
capability:

```elixir
requires :"dns.allowlist",
  hosts: [
    "*.postgres.internal",
    "audit.erlkoenig.internal"
  ]
```

The repo-supported showcase deployment path is still the Makefile:

```bash
make showcase
```

That target runs `make agents-build`, copies the two Go agents to
the showcase host, resets the `cases` database, and deploys the
long-running runner:

```text
/opt/erlkoenig/rt/demo/case_mgmt
/opt/erlkoenig/rt/demo/deadline_worker
/root/erlkoenig/tests/integration/showcase_case_mgmt.escript
```

Start the operator-facing demo with:

```bash
ssh erlkoenig-2__root /root/erlkoenig/tests/integration/showcase_case_mgmt.escript
```

That runner starts the `case_mgmt` API container and the
`deadline_worker` container, then prints:

```text
case_mgmt:        http://10.0.0.210:8080
deadline_worker:  polls case_mgmt every 30s
audit log:        /var/log/erlkoenig/case_mgmt_audit.jsonl
```

The runner is useful for the chapter-21 workload and audit-chain
demo. It is not the DNS allowlist conformance test: the current
`showcase_case_mgmt.escript` spawns direct runtime opts instead of
loading `examples/showcase/case_mgmt_stack.exs`. For DNS
enforcement, use the dedicated integration tests below.

## Manual namespace probe

When the `case_mgmt` container is running with the allowlist from
the stack file, exercise the filter from inside its net namespace:

```bash
PID=$(pgrep -f "/opt/erlkoenig/rt/demo/case_mgmt" | head -1)

# Registered hosts resolve
nsenter --target $PID --net /usr/bin/nslookup \
    audit.erlkoenig.internal 10.0.0.1
# → Non-authoritative answer: ...

# Random external name is denied
nsenter --target $PID --net /usr/bin/nslookup google.com 10.0.0.1
# → ** server can't find google.com: NXDOMAIN

# And the deny surfaces in the audit log
grep '"type":"dns_filter"' /var/log/erlkoenig/case_mgmt_audit.jsonl
# → {"seq":…,"query":"google.com","reason":"not_in_allowlist",…}
```

The long-running showcase log can be re-checked offline through the
Makefile wrapper:

```bash
make showcase-verify
```

`make showcase-verify` pulls
`/var/log/erlkoenig/case_mgmt_audit.jsonl` from the showcase host
and runs `dist/audit-verifier verify-chain` against the local copy.

## Integration tests

The DNS capability itself is covered by the DNS-specific tests.
The case-management tests cover the workload path:

| Test | What it proves |
|------|----------------|
| `28_dns_allowlist.escript` | Runtime UDP path — denied name gets AA=1 NXDOMAIN within milliseconds, allowed name is not filter-NXDOMAIN'd, audit chain captures the deny, `unregister/1` returns to pass-through |
| `29_dns_allowlist_dsl.escript` | DSL lifecycle — spawning with `dns_allowlist => [...]` auto-registers in the filter's ETS at `running`, exact + wildcard `check/2` results, and stopping the container auto-unregisters |
| `45_case_mgmt.escript` | One-shot `case_mgmt` API path — Postgres socket mount, journal.local writes, and audit-chain verification |
| `showcase_case_mgmt.escript` | Long-running demo pod — `/opt/erlkoenig/rt/demo/case_mgmt` plus `/opt/erlkoenig/rt/demo/deadline_worker` |

The DNS tests run as root because the default-zone DNS binds UDP/53.
The case-management scripts also run as root because they spawn
erlkoenig containers.

## What this deliberately does NOT do

The capability is narrow by design. Things it does **not** cover:

- **SNI matching.** A container may resolve `api.openai.com`,
  then connect to the resolved IP and send any SNI in its TLS
  ClientHello — including one that doesn't match. Proper L7
  enforcement for TLS is phase 2 of SPEC-AS-009 and needs either
  NFQUEUE or a TC/BPF classifier. Until then, an agent can still
  use a resolved IP as a proxy to a different host if the
  destination cooperates.
- **HTTP Host-header filtering.** We don't parse plaintext HTTP.
  If you care enough to filter it, use TLS.
- **TLS certificate pinning.** Seeing the server cert requires
  catching the whole handshake, not just the first packet.
  Phase 3.
- **IP-literal destinations.** A container can skip DNS entirely
  and `connect(2)` to a raw IP. That path is blocked by L4 nft
  rules, not by this capability.
- **IPv6.** The filter is IPv4-only (`{_, _, _, _}` tuple guard).
  IPv6 support lands when the rest of SPEC-AS-009 gets its v0.10
  pass.
- **Auto-injection of L4 rules.** Declaring `dns.allowlist`
  doesn't magically open port 443. Operator owns L4. Forever.

These gaps are honest because the capability's own claim is
honest: *"names this container can resolve"*, not *"hosts this
container can reach"*. The composed guarantee — resolve + L4 + TLS
pin — comes online layer by layer.

## Reference

- **SPEC-AS-009** — full specification, including phase 2 SNI
  and phase 3 pinning.
- **`erlkoenig_dns_filter`** — register/unregister/check API,
  pattern compilation, fail-open semantics.
- **`erlkoenig_dns:handle_dns_query/4`** — the hook site.
- **Chapter 19** — the capability framework this builds on.
- **Chapter 20** — the audit verifier that re-checks chain
  integrity including `dns_filter` events.
- **Chapter 21** — the case_mgmt showcase that uses all three
  together.
