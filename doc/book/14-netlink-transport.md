# Chapter 14 — Netlink Transport

erlkoenig speaks to the Linux kernel through `AF_NETLINK` directly.
No `ip`, no `nft`, no `iproute2` fork on any hot path — just an
in-tree codec that builds NLMSG binaries, sends them, and drains
replies. This chapter documents the wire format the runtime uses
and the protocol invariants that keep it reliable.

## Why AF_NETLINK direct

A pure-Erlang Netlink codec removes three classes of failure. There
is no shell to escape, no CLI output to parse, no forked process
whose exit code needs interpretation. A DSL change compiles to a
batch, the batch becomes bytes, the bytes go onto a socket, and the
kernel either applies the batch atomically or rejects it. The
compiler and the runtime share a single view of the wire — no
translation layer in between.

Performance is a side effect. A `nft reload` via CLI needs to parse
rule strings, fork, exec, serialise, and re-parse kernel replies.
The in-tree path skips all of that: the batch is ready as bytes the
moment the DSL is compiled.

## Supported families

The runtime uses four Netlink families:

| Family       | Subsys | Purpose                                            |
|--------------|--------|----------------------------------------------------|
| `RTM`        | 0      | Link, address, route management                    |
| `NFNL`       | 10     | nftables batch operations                          |
| `CTNL`       | 1      | Conntrack flow events (multicast, on its own socket) |
| `NFLOG`      | 4      | Packet logging                                     |

Each family has its own message types, attributes, and conventions.
The codec modules (`erlkoenig_netlink.erl` and the `nfnl_*.erl`
family) share primitives — NLMSG header building, attribute
packing, byte-order handling — and specialise above them.

## The NLMSG frame

Every request follows the same layout:

```
┌────────────┬────────┬────────┬───────┬─────────┬────────────┐
│ Length:32  │ Type:16│ Flags:16│ Seq:32│ PortID:32│ Payload... │
└────────────┴────────┴────────┴───────┴─────────┴────────────┘
```

The flags field carries the important bits. `NLM_F_REQUEST` marks
the message as a request (not a notification). `NLM_F_ACK` asks the
kernel to confirm applied; without it the kernel is silent on
success. `NLM_F_DUMP` turns a query into a multi-message reply
terminated by `NLMSG_DONE`.

The sequence number is client-assigned and has to be unique within a
socket. `nfnl_server` holds the counter, initialises it from
`erlang:system_time(second)` at boot, and increments on every send.
Restart-after-crash doesn't collide with any leftover replies from
the previous BEAM.

## nftables batches

All nftables operations are wrapped in a batch envelope:

```
NFNL_MSG_BATCH_BEGIN   (seq N, no ACK requested)
... N inner messages, each with NLM_F_ACK ...
NFNL_MSG_BATCH_END     (seq N+M+1, no ACK requested)
```

The kernel treats the envelope as a transaction: every inner
message applies, or none do. No half-installed firewall. The
`BATCH_BEGIN` and `BATCH_END` don't ask for ACKs themselves, so N
inner messages produce exactly N acknowledgements.

Inside the batch, message ordering respects dependencies: counters
and maps come before rules that reference them; chains come before
rules that live in them; `SET_ID` attributes let the kernel resolve
same-batch references without needing names.

## The drain-and-ack discipline

Every batch send is matched by a deterministic wait. The key
function is `collect_until_seq`: the caller supplies the set of
sequence numbers it expects ACKs for, and the function reads the
socket until every expected ACK has arrived. Two invariants make it
robust:

1. **On first error, remember the error but keep reading.** The
   kernel may have already queued replies for subsequent messages;
   aborting the drain leaves them on the socket for the next batch
   to misinterpret. The function collects every reply regardless of
   success or failure, then returns the first error once every
   expected sequence number is accounted for.

2. **Stale ACKs are discarded, not matched.** The expected set is
   keyed by sequence number, not by count — an old ACK that
   arrives late doesn't consume a slot reserved for a new batch.

Together these ensure the socket is clean the moment the function
returns. The next batch starts on a fresh state.

## The single server

One gen_server (`nfnl_server`) owns the Netlink socket and the
sequence counter. Every Erlang process that wants to send a batch
calls through it. The server serialises sends, guarantees sequence
uniqueness, and centralises the drain discipline. There is no
shared socket without coordinated access — all of that lives behind
the gen_server's call queue.

The socket is configured with `NETLINK_EXT_ACK`, which gives the
kernel an extended-ACK channel for detailed error reporting. A
failing rule doesn't just report `EINVAL`: it reports the specific
attribute offset and a text message pointing at what went wrong.
The extended info flows into the same ACK stream; the drain
captures it alongside the regular ACK bytes.

## What's still coming

Two areas are known-open work.

**Dump responses** — `NLM_F_DUMP` requests return a multi-message
stream terminated by `NLMSG_DONE`. The current codec sends dumps
fine but the structured collection helper for dumps is not yet
unified with `collect_until_seq`. For now, dump-style queries are
handled in the specific caller modules.

**Extended-ACK attribute parsing** — the raw extended-ACK payload is
captured, but the `NLMSGERR_ATTR_*` decoder has only the essentials.
Richer error reporting (attribute-level offsets, context strings) is
a planned addition.

## Hands-on: watch the transport in action

Three experiments against a running daemon that make the abstract
transport concrete.

**1. Round-trip a tiny request.**

```erlang
erlkoenig eval '
  R = nfnl_server:apply_msgs(erlkoenig_nft_srv, [
    fun(S) -> nft_table:add(1, <<"ek_handson_t14">>, S) end,
    fun(S) -> nft_delete:table(1, <<"ek_handson_t14">>, S) end
  ]),
  io:format("result: ~p~n", [R]).'
```

Output: `result: ok`. One send, one recv — a batch with 2 inner
messages (each ACKed) wrapped in BATCH_BEGIN/BATCH_END (not ACKed).

**2. Inspect the sequence counter.**

```erlang
erlkoenig eval '
  io:format("~p~n", [sys:get_state(erlkoenig_nft_srv)]).'
```

You see the current `seq`, the open socket reference. Every
`apply_msgs` bumps `seq` by the message count plus 2 (the envelope).

**3. Force a kernel error.**

```erlang
erlkoenig eval '
  R = nfnl_server:apply_msgs(erlkoenig_nft_srv, [
    fun(S) -> nft_delete:table(1, <<"no_such_table">>, S) end
  ]),
  io:format("~p~n", [R]).'
%% => {error, #{code => noent, attrs => []}}
```

`noent` = `ENOENT` translated. In a larger batch each ACK's
sequence number maps back to the specific message that failed — no
guessing which op the kernel rejected.

**4. Dump the ruleset.**

```erlang
erlkoenig eval '
  {ok, Ruleset} = nfnl_server:get_ruleset(erlkoenig_nft_srv, 1),
  io:format("~p messages~n", [length(Ruleset)]).'
```

Each message is one object (table, chain, rule, set, counter). A
vanilla daemon shows ~10-15; a production firewall shows hundreds.

**5. Watch seq advance under load.** One terminal drives traffic:

```bash
while true; do ek vol list --format plain >/dev/null; sleep 0.1; done
```

Another samples state:

```bash
for i in {1..5}; do
  erlkoenig eval 'io:format("~p~n",
    [maps:get(seq, sys:get_state(erlkoenig_nft_srv))]).'
  sleep 1
done
```

The counter climbs monotonically. A stuck counter would mean a
hung gen_server call — something to investigate. In healthy
operation it just counts up.
