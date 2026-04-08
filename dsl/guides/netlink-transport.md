# Netlink Transport

erlkoenig communicates with the Linux kernel's nf_tables subsystem over a
single `AF_NETLINK` / `NETLINK_NETFILTER` socket. No `nft` CLI, no libnftnl,
no C library — pure Erlang binary encoding on a raw datagram socket.

This guide explains the wire protocol, how batches work, how the gen_server
manages the socket, and how Erlang patterns map to Netlink semantics.

## Socket Layer

`nfnl_socket` opens a raw Netlink socket via OTP's `socket` module:

```erlang
{ok, Sock} = socket:open(?AF_NETLINK, raw, ?NETLINK_NETFILTER),
socket:bind(Sock, #{family => ?AF_NETLINK, addr => <<...>>}).
```

The socket is bound with `pid=0` (kernel assigns the port ID) and
`groups=0` (no multicast subscriptions — this is a request-only socket).

`NETLINK_EXT_ACK` is enabled via `setopt_native` so the kernel includes
human-readable error text and byte offsets in error responses.

Netlink is datagram-based: each `sendto` is one datagram, each `recv`
is one datagram. A single datagram can carry multiple Netlink messages.

## Message Structure

Every Netlink message starts with a 16-byte header (`nlmsghdr`):

```
Bytes   Field              Encoding
0..3    Length             32-bit little-endian (includes header)
4..5    Type               16-bit little-endian
6..7    Flags              16-bit little-endian
8..11   Sequence Number    32-bit little-endian
12..15  Port ID            32-bit little-endian
```

For nf_tables, the Type field encodes both subsystem and message type:
`(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_*`. After the Netlink header
comes the `nfgenmsg` (4 bytes: family, version, resource ID), then
TLV-encoded attributes.

`nfnl_msg:build_hdr/5` constructs this:

```erlang
Type = (?NFNL_SUBSYS_NFTABLES bsl 8) bor MsgType,
NfGenMsg = <<Family:8, ?NFNETLINK_V0:8, 0:16/big>>,
Len = ?NLMSGHDR_SIZE + ?NFGENMSG_SIZE + byte_size(Attrs),
<<Len:32/little, Type:16/little, Flags:16/little,
  Seq:32/little, 0:32/little, NfGenMsg/binary, Attrs/binary>>.
```

## Sequence Numbers

The Sequence Number (`nlmsg_seq`) correlates requests with responses.
The kernel copies it verbatim into the ACK. erlkoenig maintains a
monotonically increasing 32-bit counter in the gen_server state:

```erlang
init(_Opts) ->
    Seq = erlang:system_time(second) band 16#FFFFFFFF,
    {ok, #{socket => Sock, seq => Seq}}.

next_seq(Seq) -> (Seq + 1) band 16#FFFFFFFF.
```

Starting from the current unix timestamp avoids collisions with
previous incarnations of the process after a restart.

`build_msgs` assigns a fresh sequence number to each message function
and collects the assigned numbers:

```erlang
build_msgs([Fun | Rest], Seq, MsgAcc, SeqAcc) ->
    Msg = Fun(Seq),
    build_msgs(Rest, next_seq(Seq), [Msg | MsgAcc], [Seq | SeqAcc]).
```

The caller passes closures that accept a Seq and return encoded binary.
This ensures the gen_server is the single source of sequence numbers.

## Batches

nf_tables supports atomic batch operations. All messages between
`NFNL_MSG_BATCH_BEGIN` and `NFNL_MSG_BATCH_END` form a single
kernel transaction: either all succeed or none.

```
BATCH_BEGIN   (Seq=100, Flags=NLM_F_REQUEST)
  MSG_1       (Seq=101, Flags=NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE)
  MSG_2       (Seq=102, Flags=NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE)
  MSG_3       (Seq=103, Flags=NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE)
BATCH_END     (Seq=104, Flags=NLM_F_REQUEST)
```

`BATCH_BEGIN` and `BATCH_END` carry only `NLM_F_REQUEST`, not `NLM_F_ACK`.
The kernel generates ACKs exclusively for messages with `NLM_F_ACK` set.
For a batch with N messages, exactly **N ACKs** come back.

`nft_batch:wrap/2` assembles this:

```erlang
wrap(Messages, Seq) ->
    iolist_to_binary([
        nfnl_msg:batch_begin(Seq),
        Messages,
        nfnl_msg:batch_end(Seq + length(Messages) + 1)
    ]).
```

The batch control messages use `NFNL_SUBSYS_NONE` (not `NFNL_SUBSYS_NFTABLES`)
with a `nfgenmsg` that carries `NFNL_SUBSYS_NFTABLES` as the resource ID.
This tells the kernel which subsystem handles the batch content.

## ACK Processing

An ACK is an `NLMSG_ERROR` message with error code 0 (success) or a
negative errno (failure). `nfnl_response:parse_with_seq/1` extracts
both the sequence number and the result:

```erlang
parse_messages_seq(
    <<Len:32/little, ?NLMSG_ERROR:16/little, _Flags:16/little,
      Seq:32/little, _Pid:32/little,
      Error:32/signed-little, _Rest/binary>> = Bin, Acc)
  when Len >= 20 ->
    Result = case Error of
        0 -> ok;
        N -> {error, {N, errno_name(N)}}
    end,
    <<_:Len/binary, Tail/binary>> = Bin,
    parse_messages_seq(Tail, [{Seq, Result} | Acc]);
```

One `recv()` can deliver multiple ACKs in a single datagramm.
The parser iterates through all of them.

## The Drain Loop

`collect_until_seq` reads from the socket until all expected sequence
numbers have been answered:

```erlang
collect_until_seq(_Sock, Expected, Acc) when map_size(Expected) =:= 0 ->
    Acc;
collect_until_seq(Sock, Expected, Acc) ->
    case nfnl_socket:recv(Sock) of
        {ok, Data} ->
            Parsed = nfnl_response:parse_with_seq(Data),
            {Expected2, Acc2} = process_acks(Parsed, Expected, Acc),
            collect_until_seq(Sock, Expected2, Acc2);
        ...
    end.
```

`Expected` is a `#{Seq => true}` map built from the actual assigned
sequence numbers (not an arithmetic range — that would break on
32-bit wraparound). `process_acks` removes matched entries:

```erlang
process_acks([{Seq, Result} | Rest], Expected, Acc) ->
    case maps:take(Seq, Expected) of
        {true, Expected2} ->
            NewAcc = case {Acc, Result} of
                {ok, ok}         -> ok;
                {ok, {error, _}} -> Result;
                {{error, _}, _}  -> Acc
            end,
            process_acks(Rest, Expected2, NewAcc);
        error ->
            %% Unknown Seq — discard
            process_acks(Rest, Expected, Acc)
    end.
```

Two properties are critical:

1. **First error wins.** If any message fails, the error is captured
   but reading continues. The caller gets the first error after all
   ACKs are consumed.

2. **Guaranteed clean socket.** After `collect_until_seq` returns,
   no stale ACKs remain in the buffer. The next `apply_msgs` call
   reads only its own responses.

## gen_server Integration

`nfnl_server` is a `gen_server` that owns the socket and the sequence
counter. All operations are `gen_server:call` — synchronous and
serialized through the mailbox.

```erlang
handle_call({apply_msgs, MsgFuns}, _From, #{socket := Sock, seq := Seq} = State) ->
    FirstMsgSeq = next_seq(Seq),
    {Msgs, MsgSeqs, LastMsgSeq} = build_msgs(MsgFuns, FirstMsgSeq, [], []),
    BatchBeginSeq = Seq,
    BatchEndSeq = next_seq(LastMsgSeq),
    Batch = nft_batch:wrap(Msgs, BatchBeginSeq),
    Expected = maps:from_keys(MsgSeqs, true),
    Result = case nfnl_socket:send(Sock, Batch) of
        ok -> collect_until_seq(Sock, Expected, ok);
        {error, _} = Err -> Err
    end,
    {reply, Result, State#{seq => BatchEndSeq}}.
```

The sequence counter advances past `BatchEndSeq` so the next call
gets fresh numbers. No two batches ever share sequence numbers.

Multiple Erlang processes can call `apply_msgs` concurrently — the
gen_server serializes them. The socket sees one batch at a time.

## SET_ID: Intra-Batch References

When a map and its elements are created in the same batch, the kernel
cannot find the map by name (it is not committed yet). Instead, the
element insertion references the map by a client-assigned `SET_ID`:

```
Batch:
  NEWSET       name="__lb_web"  NFTA_SET_ID=42
  NEWSETELEM   set="__lb_web"   NFTA_SET_ELEM_LIST_SET_ID=42
  NEWRULE      lookup set="__lb_web" NFTA_LOOKUP_SET_ID=42
```

The kernel correlates these IDs within the transaction context.
`SET_ID=0` means "find by name only" (works only for committed objects).

In erlkoenig, the ID is derived from the map name:

```erlang
MapId = erlang:phash2(MapName) band 16#FFFF,
```

This ID appears in three places: set creation (`nft_set:add_data_map`),
element insertion (`nft_set_elem:add_data_map_elems`), and rule lookup
expressions (`nft_expr_ir:lookup_data`).

## Batch Ordering

Message order within a batch matters. The kernel processes them
sequentially, and later messages can reference objects from earlier
messages (via SET_ID):

```erlang
AllMsgs = CounterMsgs       %% 1. Named counters
       ++ AllMapCreates      %% 2. Map creation + element insertion
       ++ AllChainCreates    %% 3. Chains (base chains + regular)
       ++ AllRuleCreates,    %% 4. Rules (reference maps + chains)
```

`AllMapCreates` contains `[CreateMap, AddElems, ...]` pairs. The order
is significant: elements reference the map by SET_ID, so the map must
come first. Chains must exist before rules can be added to them.

## Selective Cleanup

Multiple subsystems share the `erlkoenig` nft table:

- **Container Firewall** (`erlkoenig_firewall_nft`): per-container chains
- **DSL Configuration** (`erlkoenig_config`): user-defined chains, maps, rules
- **Threat Guard** (`erlkoenig_nft_ct_guard`): ban sets

Each subsystem cleans up only its own objects before rebuilding.
No subsystem deletes the shared table. Chain flush and chain delete
operations that target non-existent objects (first startup) return
`ENOENT` and are silently ignored:

```erlang
lists:foreach(fun(ChainName) ->
    _ = nfnl_server:apply_msgs(Server, [
        fun(S) -> nft_delete:flush_chain(Family, Table, ChainName, S) end
    ]),
    _ = nfnl_server:apply_msgs(Server, [
        fun(S) -> nft_delete:chain(Family, Table, ChainName, S) end
    ])
end, OwnChains).
```

Each delete is its own batch because a failing delete in a multi-message
batch would roll back the entire transaction (including successful deletes).

## Data Maps and jhash Load Balancing

Named data maps store key-value pairs where values are data (IP addresses),
not verdicts. Combined with the `jhash` hash expression, they implement
kernel-native source-IP sticky load balancing:

```
table inet erlkoenig {
    map __lb_web {
        type mark : ipv4_addr
        elements = { 0x00000000 : 10.0.0.2,
                     0x00000001 : 10.0.0.3,
                     0x00000002 : 10.0.0.4 }
    }
    chain prerouting_nat {
        type nat hook prerouting priority dstnat; policy accept;
        dnat ip to jhash @nh,96,32 mod 3 seed 0x0 map @__lb_web:8443
    }
}
```

The rule reads the source IP (`@nh,96,32` = network header offset 96,
length 32 bits = IPv4 source address), hashes it with Jenkins hash
modulo N, looks up the result in the data map, and DNATs to the
corresponding container IP on port 8443.

In erlkoenig, the map and rule are explicit DSL constructs:

```elixir
nft_map "web_jhash", :mark, :ipv4_addr,
  entries: {:replica_ips, "web", "nginx"}

nft_rule :dnat_jhash,
  iifname: "eth0", tcp_dport: 8443,
  map: "web_jhash", mod: 3, port: 8443
```

The developer names the map, sets the modulus, and references it
explicitly. No auto-generated hidden maps.

## Concatenated Verdict Maps

Concat verdict maps use composite keys for O(1) policy lookups.
Instead of N individual accept rules, one hashtable lookup decides
the verdict for `ip saddr . ip daddr . tcp dport`.

On Kernel 6.12, concat field descriptors are encoded as
`NFTA_SET_USERDATA` (attribute 13) using a libnftnl-specific TLV
format — not `NFTA_SET_DESC` + `DESC_CONCAT` (which is nf-next only).

Concat lookups require 32-bit registers (`NFT_REG32_00` = 8,
`NFT_REG32_01` = 9, etc.) packed consecutively. The old 128-bit
registers (`NFT_REG_1` = 1) are too wide — the kernel returns
`ENODATA` if registers between payload loads are "uninitialized"
in its 32-bit register tracking.

## Architecture Overview

```
Erlang Processes                    Kernel
─────────────────                   ──────

erlkoenig_config ──┐
                   │  gen_server:call
erlkoenig_firewall ┤──────────────────→ nfnl_server ──→ AF_NETLINK ──→ nf_tables
                   │                    (single socket)
erlkoenig_ct_guard ┘                    (single seq)

                   serialized           datagram-based
                   via mailbox          request/response
```

All nft operations flow through one gen_server, one socket, one
sequence counter. The gen_server provides mutual exclusion. The
seq-based drain loop provides correct response correlation.
The batch mechanism provides atomicity.
