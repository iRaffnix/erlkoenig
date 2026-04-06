%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%

-module(nft_expr_ir).
-moduledoc """
nf_tables expression intermediate representation.

Builds semantic terms that describe VM instructions without encoding
them to Netlink bytes. These terms are understood by both:

  - nft_vm:eval_expr/3 — for simulation and testing
  - nft_encode:expr/1  — for Netlink binary encoding

This is the common language between Erlkönig (the firewall) and
nft_vm (the simulator). Rules are built once as terms, then either
sent to the kernel or tested in the VM.

Expression term format: {ExprType, #{options}}.

Example:
    Rule = [
        nft_expr_ir:meta(l4proto, 1),
        nft_expr_ir:cmp(eq, 1, <<6>>),
        nft_expr_ir:tcp_dport(1),
        nft_expr_ir:cmp(eq, 1, <<22:16/big>>),
        nft_expr_ir:accept()
    ],

    %% Test it
    {accept, _} = nft_vm:eval_chain([Rule], Pkt),

    %% Send to kernel
    Bin = nft_encode:rule(inet, Table, Chain, Rule, Seq),
    nfnl_server:apply_msgs(Srv, [Bin]).
""".

-export([
    %% Producers
    payload/4,
    meta/2,
    ct/2,
    ct_mark/1,
    ct_mark_set/1,
    %% Payload convenience — IPv4
    tcp_sport/1,
    tcp_dport/1,
    udp_sport/1,
    udp_dport/1,
    ip_saddr/1,
    ip_daddr/1,
    ip_protocol/1,
    %% Payload convenience — IPv6
    ip6_saddr/1,
    ip6_daddr/1,
    ip6_next_header/1,
    %% Consumers
    cmp/3,
    cmp_neq/2,
    range/4,
    bitwise/4,
    lookup/2,
    lookup_data/3,
    lookup_inv/2,
    vmap_lookup/2,
    concat_lookup/3,
    %% Actions
    counter/0,
    counter/2,
    objref_counter/1,
    objref_quota/1,
    log/1, log/0,
    limit/2,
    limit_over/2,
    %% Terminals / Immediate
    accept/0,
    drop/0,
    return/0,
    jump/1,
    goto/1,
    reject/0, reject/2,
    immediate_data/2,
    %% NAT / Masquerade / Redirect
    snat/2, snat/3,
    snat_addr/2,
    dnat/2, dnat/3,
    masq/0, masq/2,
    redir/1,
    %% Queue / Quota / Hash
    queue/1, queue/2,
    quota/2,
    hash/4,
    %% Extension headers / Byte order
    exthdr/4,
    byteorder/5,
    %% Routing / FIB / Socket / Tunnel
    rt/2,
    fib/3,
    fib_rpf/0,
    socket/2,
    socket_cgroup/1,
    tunnel/2,
    %% Dynamic sets / Connection limits / Meters
    dynset/3,
    meter/5,
    connlimit/2,
    %% Packet duplication / Forwarding
    dup/2,
    fwd/3,
    %% Inner headers (tunnel payload matching)
    inner/3,
    %% Number generator
    numgen/3,
    %% OS fingerprinting
    osf/1,
    osf_match/2,
    %% Hardware offload
    offload/1,
    flow_offload/1,
    %% Security marking
    secmark/1,
    %% SYN proxy
    synproxy/3,
    synproxy_filter_rule/2,
    %% Transparent proxy
    tproxy/3,
    %% IPsec / xfrm
    xfrm/3,
    %% Last match timestamp
    last/0,
    %% Conntrack bypass
    notrack/0,
    %% Generic
    generic/2
]).

-export_type([expr/0, rule/0]).

%% --- Types ---

-doc "A single VM instruction as a semantic term.".
-type expr() :: {atom(), map()}.

-doc "A rule: ordered list of expressions.".
-type rule() :: [expr()].

%% ===================================================================
%% PRODUCERS
%% ===================================================================

-doc "Load bytes from a packet layer into a register.".
-spec payload(atom() | non_neg_integer(), non_neg_integer(), pos_integer(), non_neg_integer()) ->
    expr().
payload(Base, Offset, Len, DReg) ->
    {payload, #{base => Base, offset => Offset, len => Len, dreg => DReg}}.

-doc "Load packet metadata into a register.".
-spec meta(atom() | non_neg_integer(), non_neg_integer()) -> expr().
meta(Key, DReg) ->
    {meta, #{key => Key, dreg => DReg}}.

-doc "Load conntrack state into a register.".
-spec ct(atom() | non_neg_integer(), non_neg_integer()) -> expr().
ct(Key, DReg) ->
    {ct, #{key => Key, dreg => DReg}}.

-doc "Load conntrack mark into a register.".
-spec ct_mark(non_neg_integer()) -> expr().
ct_mark(DReg) ->
    {ct, #{key => mark, dreg => DReg}}.

-doc "Set conntrack mark from a register.".
-spec ct_mark_set(non_neg_integer()) -> expr().
ct_mark_set(SReg) ->
    {ct, #{key => mark, sreg => SReg}}.

%% --- Payload convenience ---

-doc "Load TCP source port (2 bytes) into register.".
-spec tcp_sport(non_neg_integer()) ->
    {payload, #{
        base := atom(), offset := non_neg_integer(), len := pos_integer(), dreg := non_neg_integer()
    }}.
tcp_sport(Reg) -> payload(transport, 0, 2, Reg).

-doc "Load TCP destination port (2 bytes) into register.".
-spec tcp_dport(non_neg_integer()) ->
    {payload, #{
        base := atom(), offset := non_neg_integer(), len := pos_integer(), dreg := non_neg_integer()
    }}.
tcp_dport(Reg) -> payload(transport, 2, 2, Reg).

-doc "Load UDP source port (2 bytes) into register.".
-spec udp_sport(non_neg_integer()) ->
    {payload, #{
        base := atom(), offset := non_neg_integer(), len := pos_integer(), dreg := non_neg_integer()
    }}.
udp_sport(Reg) -> payload(transport, 0, 2, Reg).

-doc "Load UDP destination port (2 bytes) into register.".
-spec udp_dport(non_neg_integer()) ->
    {payload, #{
        base := atom(), offset := non_neg_integer(), len := pos_integer(), dreg := non_neg_integer()
    }}.
udp_dport(Reg) -> payload(transport, 2, 2, Reg).

-doc "Load IPv4 source address (4 bytes) into register.".
-spec ip_saddr(non_neg_integer()) ->
    {payload, #{
        base := atom(), offset := non_neg_integer(), len := pos_integer(), dreg := non_neg_integer()
    }}.
ip_saddr(Reg) -> payload(network, 12, 4, Reg).

-doc "Load IPv4 destination address (4 bytes) into register.".
-spec ip_daddr(non_neg_integer()) ->
    {payload, #{
        base := atom(), offset := non_neg_integer(), len := pos_integer(), dreg := non_neg_integer()
    }}.
ip_daddr(Reg) -> payload(network, 16, 4, Reg).

-doc "Load IPv4 protocol field (1 byte) into register.".
-spec ip_protocol(non_neg_integer()) ->
    {payload, #{
        base := atom(), offset := non_neg_integer(), len := pos_integer(), dreg := non_neg_integer()
    }}.
ip_protocol(Reg) -> payload(network, 9, 1, Reg).

-doc "Load IPv6 source address (16 bytes) into register.".
-spec ip6_saddr(non_neg_integer()) ->
    {payload, #{
        base := atom(), offset := non_neg_integer(), len := pos_integer(), dreg := non_neg_integer()
    }}.
ip6_saddr(Reg) -> payload(network, 8, 16, Reg).

-doc "Load IPv6 destination address (16 bytes) into register.".
-spec ip6_daddr(non_neg_integer()) ->
    {payload, #{
        base := atom(), offset := non_neg_integer(), len := pos_integer(), dreg := non_neg_integer()
    }}.
ip6_daddr(Reg) -> payload(network, 24, 16, Reg).

-doc "Load IPv6 next-header field (1 byte) into register.".
-spec ip6_next_header(non_neg_integer()) ->
    {payload, #{
        base := atom(), offset := non_neg_integer(), len := pos_integer(), dreg := non_neg_integer()
    }}.
ip6_next_header(Reg) -> payload(network, 6, 1, Reg).

%% ===================================================================
%% CONSUMERS
%% ===================================================================

-doc "Compare register against a constant. BREAKs on failure.".
-spec cmp(atom(), non_neg_integer(), binary()) -> expr().
cmp(Op, SReg, Data) ->
    {cmp, #{sreg => SReg, op => Op, data => Data}}.

-doc "Shorthand: compare register not-equal to zero.".
-spec cmp_neq(non_neg_integer(), binary()) ->
    {cmp, #{sreg := non_neg_integer(), op := neq, data := binary()}}.
cmp_neq(SReg, Data) ->
    cmp(neq, SReg, Data).

-doc "Check if register value is within [From, To]. BREAKs if outside.".
-spec range(atom(), non_neg_integer(), binary(), binary()) -> expr().
range(Op, SReg, From, To) ->
    {range, #{sreg => SReg, op => Op, from_data => From, to_data => To}}.

-doc "Apply bitwise mask and XOR: dreg = (sreg & Mask) ^ Xor.".
-spec bitwise(non_neg_integer(), non_neg_integer(), binary(), binary()) -> expr().
bitwise(SReg, DReg, Mask, Xor) ->
    {bitwise, #{sreg => SReg, dreg => DReg, mask => Mask, xor_val => Xor}}.

-doc "Check if register value exists in a named set. BREAKs if not found.".
-spec lookup(non_neg_integer(), binary()) -> expr().
lookup(SReg, SetName) ->
    {lookup, #{sreg => SReg, set => SetName}}.

-doc "Data map lookup: load value from map into DReg (for jhash DNAT).".
-spec lookup_data(non_neg_integer(), binary(), non_neg_integer()) -> expr().
lookup_data(SReg, SetName, DReg) ->
    {lookup, #{sreg => SReg, set => SetName, dreg => DReg}}.

-spec lookup_inv(non_neg_integer(), binary()) -> expr().
lookup_inv(SReg, SetName) ->
    {lookup, #{sreg => SReg, set => SetName, flags => 1}}.

-doc "Look up register value in a verdict map. Result goes to verdict register (dreg=0).".
-spec vmap_lookup(non_neg_integer(), binary()) -> expr().
vmap_lookup(SReg, SetName) ->
    {lookup, #{sreg => SReg, set => SetName, dreg => 0}}.
-doc """
Concatenated set lookup. Loads multiple fields into consecutive
registers and performs a single set lookup on the concatenated key.

KeyExprs is a list of {LoadExpr, ByteLen} tuples, where LoadExpr is
an IR expression that loads data into a register, and ByteLen is the
number of bytes that field occupies in the concatenated key.

The fields are loaded into registers starting at SReg, with each
subsequent field at the next register offset (each register holds
4 bytes in the kernel, so fields are packed at 4-byte aligned offsets).

Example:
    %% ip saddr . tcp dport { 10.0.0.1 . 22 }
    concat_lookup(<<"allowpairs">>, [ip_saddr, tcp_dport], accept)

See nft_rules:concat_set_lookup/3 for the high-level builder.
""".
-spec concat_lookup(binary(), [{expr(), pos_integer()}], atom()) -> [expr()].
concat_lookup(SetName, KeyExprs, Verdict) ->
    %% Load each field into consecutive register space starting at reg 1.
    %% The kernel uses NFT_REG32 sub-registers; each 4 bytes = 1 reg slot.
    %% We assign registers sequentially, packing at 4-byte boundaries.
    {LoadExprs, TotalLen} = build_concat_loads(KeyExprs, 1, [], 0),
    LoadExprs ++
        [
            {lookup, #{
                sreg => 1,
                set => SetName,
                concat => true,
                key_len => TotalLen
            }},
            {immediate, #{verdict => Verdict}}
        ].

%% Build load expressions for concatenated fields.
%% Each field is loaded into the next available register.
%% Registers are 4 bytes each; fields are padded to 4-byte alignment.
build_concat_loads([], _Reg, Acc, TotalLen) ->
    {lists:reverse(Acc), TotalLen};
build_concat_loads([{LoadExpr0, FieldLen} | Rest], Reg, Acc, TotalLen) ->
    %% Replace the dreg in the load expression with current register
    LoadExpr = set_dreg(LoadExpr0, Reg),
    %% Each register holds 4 bytes; advance by ceil(FieldLen/4) registers
    RegsUsed = (FieldLen + 3) div 4,
    build_concat_loads(
        Rest,
        Reg + RegsUsed,
        [LoadExpr | Acc],
        TotalLen + FieldLen
    ).

%% Replace the destination register in an expression.
set_dreg({Type, Opts}, NewDReg) ->
    {Type, Opts#{dreg := NewDReg}}.

%% ===================================================================
%% ACTIONS
%% ===================================================================

-doc "Zero-initialized anonymous counter.".
-spec counter() -> {counter, #{packets := 0, bytes := 0}}.
counter() ->
    {counter, #{packets => 0, bytes => 0}}.

-doc "Counter with initial values.".
-spec counter(non_neg_integer(), non_neg_integer()) -> expr().
counter(Packets, Bytes) ->
    {counter, #{packets => Packets, bytes => Bytes}}.

-doc "Reference a named counter object.".
-spec objref_counter(binary()) -> expr().
objref_counter(Name) ->
    {objref, #{type => counter, name => Name}}.

-doc "Reference a named quota object.".
-spec objref_quota(binary()) -> expr().
objref_quota(Name) ->
    {objref, #{type => quota, name => Name}}.

-doc "Log with default settings.".
-spec log() -> {log, #{}}.
log() ->
    {log, #{}}.

-doc "Log with options (prefix, group, level, snaplen).".
-spec log(map()) -> expr().
log(Opts) ->
    {log, Opts}.

-doc """
Rate limiter. Rate is packets per Unit seconds. Burst is token bucket depth.
Normal mode: BREAKs when over the limit.
""".
-spec limit(non_neg_integer(), non_neg_integer()) -> expr().
limit(Rate, Burst) ->
    {limit, #{rate => Rate, unit => 1, burst => Burst, type => 0, flags => 0}}.

-doc """
Inverted rate limiter. BREAKs when UNDER the limit.
Used for 'drop excess traffic' patterns: over-limit packets pass through to a drop verdict.
""".
-spec limit_over(non_neg_integer(), non_neg_integer()) -> expr().
limit_over(Rate, Burst) ->
    {limit, #{rate => Rate, unit => 1, burst => Burst, type => 0, flags => 1}}.

%% ===================================================================
%% TERMINALS
%% ===================================================================

-doc "Accept the packet.".
-spec accept() -> {immediate, #{verdict := accept}}.
accept() ->
    {immediate, #{verdict => accept}}.

-doc "Drop the packet.".
-spec drop() -> {immediate, #{verdict := drop}}.
drop() ->
    {immediate, #{verdict => drop}}.

-doc "Return to calling chain.".
-spec return() -> {immediate, #{verdict := return}}.
return() ->
    {immediate, #{verdict => return}}.

-doc "Jump to a named chain (with return).".
-spec jump(binary()) -> expr().
jump(Chain) ->
    {immediate, #{verdict => {jump, Chain}}}.

-doc "Goto a named chain (no return).".
-spec goto(binary()) -> expr().
goto(Chain) ->
    {immediate, #{verdict => {goto, Chain}}}.

-doc "Drop and send ICMPx port-unreachable (family-independent, for inet tables).".
-spec reject() -> {reject, #{type := 2, icmp_code := 1}}.
reject() ->
    %% type=2 = NFT_REJECT_ICMPX_UNREACH (family-independent)
    %% icmpx codes: 0=no-route, 1=port-unreachable, 2=host-unreachable, 3=admin-prohibited
    {reject, #{type => 2, icmp_code => 1}}.

-doc "Reject with explicit type and ICMP code.".
-spec reject(non_neg_integer(), non_neg_integer()) -> expr().
reject(Type, Code) ->
    {reject, #{type => Type, icmp_code => Code}}.

-doc "Load arbitrary data into a register (for NAT addresses, ports, etc.).".
-spec immediate_data(non_neg_integer(), binary()) -> expr().
immediate_data(DReg, Data) ->
    {immediate, #{dreg => DReg, data => Data}}.

%% ===================================================================
%% NAT / MASQUERADE / REDIRECT
%% ===================================================================

-doc """
Source NAT. Rewrite source address/port.
Family: 2 = IPv4, 10 = IPv6.
""".
-spec snat(non_neg_integer(), non_neg_integer(), non_neg_integer()) -> expr().
snat(AddrReg, ProtoReg, Family) ->
    {nat, #{
        type => snat,
        family => Family,
        reg_addr_min => AddrReg,
        reg_proto_min => ProtoReg
    }}.

-spec snat(non_neg_integer(), non_neg_integer()) ->
    {nat, #{
        type := snat,
        family := non_neg_integer(),
        reg_addr_min := non_neg_integer(),
        reg_proto_min := non_neg_integer()
    }}.
snat(AddrReg, ProtoReg) ->
    snat(AddrReg, ProtoReg, 2).

-doc "Source NAT address-only (no port rewrite).".
-spec snat_addr(non_neg_integer(), non_neg_integer()) -> expr().
snat_addr(AddrReg, Family) ->
    {nat, #{
        type => snat,
        family => Family,
        reg_addr_min => AddrReg
    }}.

-doc "Destination NAT. Rewrite destination address/port.".
-spec dnat(non_neg_integer(), non_neg_integer(), non_neg_integer()) -> expr().
dnat(AddrReg, ProtoReg, Family) ->
    {nat, #{
        type => dnat,
        family => Family,
        reg_addr_min => AddrReg,
        reg_proto_min => ProtoReg
    }}.

-spec dnat(non_neg_integer(), non_neg_integer()) ->
    {nat, #{
        type := dnat,
        family := non_neg_integer(),
        reg_addr_min := non_neg_integer(),
        reg_proto_min := non_neg_integer()
    }}.
dnat(AddrReg, ProtoReg) ->
    dnat(AddrReg, ProtoReg, 2).

-doc "Masquerade (dynamic SNAT using outgoing interface address).".
-spec masq() -> {masq, #{}}.
masq() ->
    {masq, #{}}.

-doc "Masquerade with port range.".
-spec masq(non_neg_integer(), non_neg_integer()) -> expr().
masq(ProtoMinReg, ProtoMaxReg) ->
    {masq, #{reg_proto_min => ProtoMinReg, reg_proto_max => ProtoMaxReg}}.

-doc "Redirect to local port (transparent proxy).".
-spec redir(non_neg_integer()) -> expr().
redir(ProtoReg) ->
    {redir, #{reg_proto_min => ProtoReg}}.

%% ===================================================================
%% QUEUE / QUOTA / HASH
%% ===================================================================

-doc "Send packet to NFQUEUE for userspace processing.".
-spec queue(non_neg_integer()) -> expr().
queue(Num) when is_integer(Num) ->
    {queue, #{num => Num, flags => 0}}.

-doc "Queue packet to userspace NFQUEUE with options (flags, range).".
-spec queue(non_neg_integer() | {non_neg_integer(), non_neg_integer()}, map()) -> expr().
queue(Num, Opts) when is_map(Opts) ->
    Flags = queue_flags(maps:get(flags, Opts, [])),
    case Num of
        {From, To} ->
            {queue, #{num => From, total => To - From + 1, flags => Flags}};
        N when is_integer(N) ->
            {queue, #{num => N, flags => Flags}}
    end.

-spec queue_flags([atom()]) -> non_neg_integer().
queue_flags(Flags) when is_list(Flags) ->
    lists:foldl(
        fun
            %% NFT_QUEUE_FLAG_BYPASS
            (bypass, Acc) -> Acc bor 16#01;
            %% NFT_QUEUE_FLAG_CPU_FANOUT
            (fanout, Acc) -> Acc bor 16#02;
            (_, Acc) -> Acc
        end,
        0,
        Flags
    );
queue_flags(N) when is_integer(N) -> N.

-doc "Byte quota. Flags: 0 = until, 1 = over.".
-spec quota(non_neg_integer(), non_neg_integer()) -> expr().
quota(Bytes, Flags) ->
    {quota, #{bytes => Bytes, flags => Flags}}.

-doc "Hash packet data for load balancing.".
-spec hash(non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()) -> expr().
hash(SReg, Len, Modulus, DReg) ->
    {hash, #{
        sreg => SReg,
        len => Len,
        modulus => Modulus,
        dreg => DReg,
        type => 0,
        seed => 0,
        offset => 0
    }}.

%% ===================================================================
%% EXTENSION HEADERS / BYTE ORDER
%% ===================================================================

-doc "Load extension header field into a register (IPv6 ext headers, TCP options).".
-spec exthdr(non_neg_integer(), non_neg_integer(), pos_integer(), non_neg_integer()) -> expr().
exthdr(Type, Offset, Len, DReg) ->
    {exthdr, #{type => Type, offset => Offset, len => Len, dreg => DReg}}.

-doc "Convert byte order: Op 0 = host-to-big, 1 = big-to-host.".
-spec byteorder(
    non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()
) -> expr().
byteorder(Op, SReg, DReg, Len, Size) ->
    {byteorder, #{op => Op, sreg => SReg, dreg => DReg, len => Len, size => Size}}.

%% ===================================================================
%% ROUTING / FIB / SOCKET / TUNNEL
%% ===================================================================

-doc "Load routing data into a register (classid, nexthop, mtu, tcpmss).".
-spec rt(non_neg_integer(), non_neg_integer()) -> expr().
rt(Key, DReg) ->
    {rt, #{key => Key, dreg => DReg}}.

-doc "FIB lookup. Result: 1=oif, 2=oifname, 3=addrtype. Flags: bitmask of saddr/daddr/mark/iif/oif.".
-spec fib(non_neg_integer(), non_neg_integer(), non_neg_integer()) -> expr().
fib(Result, Flags, DReg) ->
    {fib, #{result => Result, flags => Flags, dreg => DReg}}.

-doc """
FIB reverse-path filter check.

Performs `fib saddr . iif oif == 0 drop` — if the FIB lookup for the
source address restricted to the input interface returns no output
interface (oif == 0), the packet has a spoofed source and is dropped.

Returns a list of expressions suitable for use as a rule.

Flags: SADDR(1) | IIF(8) = 9.  Result: OIF = 1.
""".
-spec fib_rpf() ->
    [
        {fib, #{result := non_neg_integer(), flags := non_neg_integer(), dreg := non_neg_integer()}}
        | {cmp, #{sreg := non_neg_integer(), op := atom(), data := binary()}}
        | {immediate, #{verdict := drop}},
        ...
    ].
fib_rpf() ->
    [
        fib(1, 9, 1),
        cmp(eq, 1, <<0:32>>),
        drop()
    ].

-doc "Match socket attributes. Key: 0=transparent, 1=mark, 2=wildcard, 3=cgroupv2.".
-spec socket(non_neg_integer(), non_neg_integer()) -> expr().
socket(Key, DReg) ->
    {socket, #{key => Key, dreg => DReg}}.

-doc "Load cgroupv2 socket ID into a register (for per-service matching).".
-spec socket_cgroup(non_neg_integer()) -> expr().
socket_cgroup(Level) ->
    {socket, #{key => cgroupv2, level => Level, dreg => 1}}.

-doc "Load tunnel metadata into a register.".
-spec tunnel(non_neg_integer(), non_neg_integer()) -> expr().
tunnel(Key, DReg) ->
    {tunnel, #{key => Key, dreg => DReg}}.

%% ===================================================================
%% DYNAMIC SETS / CONNECTION LIMITS
%% ===================================================================

-doc "Add/update element in a dynamic set. Op: 0=add, 1=update.".
-spec dynset(binary(), non_neg_integer(), non_neg_integer()) -> expr().
dynset(SetName, SRegKey, Op) ->
    {dynset, #{set_name => SetName, sreg_key => SRegKey, op => Op}}.

-doc "Per-key rate limiting via dynamic set (meter).".
-spec meter(binary(), non_neg_integer(), non_neg_integer(), non_neg_integer(), atom()) -> expr().
meter(SetName, SReg, Rate, Burst, Unit) ->
    {dynset, #{
        set_name => SetName,
        sreg_key => SReg,
        op => 1,
        set_id => 1,
        exprs => [
            {limit, #{
                rate => Rate,
                burst => Burst,
                unit => unit_val(Unit),
                type => 0,
                flags => 1
            }}
        ]
    }}.

-doc "Limit concurrent connections. Flags: 0=until, 1=over.".
-spec connlimit(non_neg_integer(), non_neg_integer()) -> expr().
connlimit(Count, Flags) ->
    {connlimit, #{count => Count, flags => Flags}}.

%% ===================================================================
%% PACKET DUPLICATION / FORWARDING
%% ===================================================================

-doc "Duplicate packet to address (register) via device (register).".
-spec dup(non_neg_integer(), non_neg_integer()) -> expr().
dup(AddrReg, DevReg) ->
    {dup, #{sreg_addr => AddrReg, sreg_dev => DevReg}}.

-doc "Forward packet to device (register) with optional nexthop address.".
-spec fwd(non_neg_integer(), non_neg_integer(), non_neg_integer()) -> expr().
fwd(DevReg, AddrReg, NfProto) ->
    {fwd, #{sreg_dev => DevReg, sreg_addr => AddrReg, nfproto => NfProto}}.

%% ===================================================================
%% INNER HEADERS (tunnel payload matching)
%% ===================================================================

-doc "Match inner (tunneled) packet headers. Type: tunnel type, Hdrsize: inner header size.".
-spec inner(non_neg_integer(), non_neg_integer(), binary()) -> expr().
inner(Type, Hdrsize, Expr) ->
    {inner, #{type => Type, hdrsize => Hdrsize, expr => Expr}}.

%% ===================================================================
%% NUMBER GENERATOR
%% ===================================================================

-doc "Generate a number (0..Modulus-1). Type: 0=incremental, 1=random.".
-spec numgen(non_neg_integer(), non_neg_integer(), non_neg_integer()) -> expr().
numgen(Modulus, Type, DReg) ->
    {ng, #{modulus => Modulus, type => Type, dreg => DReg, offset => 0}}.

%% ===================================================================
%% OS FINGERPRINTING
%% ===================================================================

-doc "Passive OS fingerprinting. Loads OS name string into register.".
-spec osf(non_neg_integer()) -> expr().
osf(DReg) ->
    {osf, #{dreg => DReg}}.

-doc "Load OS fingerprint into a register and compare against a name string.".
-spec osf_match(non_neg_integer(), binary()) ->
    [
        {osf, #{dreg := non_neg_integer()}}
        | {cmp, #{sreg := non_neg_integer(), op := atom(), data := binary()}},
        ...
    ].
osf_match(DReg, OsName) when is_binary(OsName) ->
    [osf(DReg), cmp(eq, DReg, OsName)].

%% ===================================================================
%% HARDWARE OFFLOAD
%% ===================================================================

-doc "Offload flow to hardware via a named flowtable.".
-spec offload(binary()) -> expr().
offload(TableName) ->
    {offload, #{table_name => TableName}}.

-doc """
Build a rule fragment for flow offload: offload established connections
to the named flowtable. Returns a list of expressions suitable for
appending to a rule (ct state established + flow add @FlowtableName).
""".
-spec flow_offload(binary()) ->
    [
        {ct, #{key := atom(), dreg := non_neg_integer()}}
        | {bitwise, #{
            sreg := non_neg_integer(),
            dreg := non_neg_integer(),
            mask := binary(),
            xor_val := binary()
        }}
        | {cmp, #{sreg := non_neg_integer(), op := atom(), data := binary()}}
        | {offload, #{table_name := binary()}},
        ...
    ].
flow_offload(FlowtableName) ->
    CT_ESTABLISHED = 16#02,
    [
        ct(state, 1),
        bitwise(1, 1, <<CT_ESTABLISHED:32/native>>, <<0:32>>),
        cmp(neq, 1, <<0:32/native>>),
        offload(FlowtableName)
    ].

%% ===================================================================
%% SECURITY MARKING
%% ===================================================================

-doc "Set SELinux security context on a packet.".
-spec secmark(binary()) -> expr().
secmark(Ctx) ->
    {secmark, #{ctx => Ctx}}.

%% ===================================================================
%% SYN PROXY
%% ===================================================================

-doc "SYN proxy for TCP handshake offload. MSS/Wscale sent to backend.".
-spec synproxy(non_neg_integer(), non_neg_integer(), non_neg_integer()) -> expr().
synproxy(Mss, Wscale, Flags) ->
    {synproxy, #{mss => Mss, wscale => Wscale, flags => Flags}}.

-doc """
Build a synproxy filter rule for a TCP port.

Matches ct state invalid,untracked TCP traffic to the given port,
then applies a synproxy expression. The kernel handles SYN cookies
for untracked connections and passes completed handshakes through.

Requires a corresponding notrack rule in the raw prerouting chain
(see nft_rules:notrack_rule/2).
""".
-spec synproxy_filter_rule(0..65535, map()) -> rule().
synproxy_filter_rule(Port, #{mss := Mss, wscale := Wscale} = Opts) ->
    %% CT state bits: invalid=1, untracked=64 (0x40)
    CT_INVALID = 16#01,
    CT_UNTRACKED = 16#40,
    StateMask = CT_INVALID bor CT_UNTRACKED,
    Flags = synproxy_flags(Opts),
    Reg1 = 1,
    TCP = 6,
    [
        ct(state, Reg1),
        bitwise(Reg1, Reg1, <<StateMask:32/native>>, <<0:32>>),
        cmp(neq, Reg1, <<0:32/native>>),
        meta(l4proto, Reg1),
        cmp(eq, Reg1, <<TCP>>),
        tcp_dport(Reg1),
        cmp(eq, Reg1, <<Port:16/big>>),
        synproxy(Mss, Wscale, Flags)
    ].

synproxy_flags(Opts) ->
    F0 =
        case maps:get(timestamp, Opts, false) of
            true -> 1;
            false -> 0
        end,
    F1 =
        case maps:get(sack_perm, Opts, false) of
            true -> 2;
            false -> 0
        end,
    F0 bor F1.

%% ===================================================================
%% TRANSPARENT PROXY
%% ===================================================================

-doc "Transparent proxy. Redirect to local socket by address/port registers.".
-spec tproxy(non_neg_integer(), non_neg_integer(), non_neg_integer()) -> expr().
tproxy(Family, AddrReg, PortReg) ->
    {tproxy, #{family => Family, reg_addr => AddrReg, reg_port => PortReg}}.

%% ===================================================================
%% IPSEC / XFRM
%% ===================================================================

-doc "Match IPsec/xfrm state. Key: spi/reqid/addr etc. Dir: 0=in, 1=out.".
-spec xfrm(non_neg_integer(), non_neg_integer(), non_neg_integer()) -> expr().
xfrm(Key, Dir, DReg) ->
    {xfrm, #{key => Key, dir => Dir, dreg => DReg}}.

%% ===================================================================
%% LAST MATCH TIMESTAMP
%% ===================================================================

-doc "Track timestamp of last rule match.".
-spec last() -> {last, #{set := 0, msecs := 0}}.
last() ->
    {last, #{set => 0, msecs => 0}}.

%% ===================================================================
%% CONNTRACK BYPASS
%% ===================================================================

-doc "Skip connection tracking for matched packets.".
-spec notrack() -> {notrack, #{}}.
notrack() ->
    {notrack, #{}}.

%% ===================================================================
%% GENERIC (for any generated expression)
%% ===================================================================

-doc """
Generic expression builder. Use for any nft_tables expression that has
a generated _gen module but no dedicated IR helper.

    nft_expr_ir:generic(dynset, #{set => <<"myset">>, sreg_key => 1, op => 0})
    nft_expr_ir:generic(fib, #{result => 0, flags => 3, dreg => 1})
    nft_expr_ir:generic(osf, #{dreg => 1})
""".
-spec generic(atom(), map()) -> expr().
generic(ExprName, Opts) when is_atom(ExprName), is_map(Opts) ->
    {ExprName, Opts}.

%% ===================================================================
%% Internal helpers
%% ===================================================================

-spec unit_val(atom() | non_neg_integer()) -> non_neg_integer().
unit_val(second) -> 1;
unit_val(minute) -> 60;
unit_val(hour) -> 3600;
unit_val(day) -> 86400;
unit_val(N) when is_integer(N) -> N.
