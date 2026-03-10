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

-module(nft_vm).
-moduledoc """
nf_tables virtual machine simulator.

A pure Erlang digital twin of the kernel's nft_do_chain() function.
Evaluates rules against synthetic packets without touching the kernel.

The VM implements the same register-based execution model:
- 16 general-purpose 4-byte data registers (reg32 0-15)
- 1 verdict register (reg 0, separate from data registers)
- Strict left-to-right expression evaluation
- BREAK on match failure (skip to next rule)
- Terminal verdicts end evaluation

Usage:
    %% Build a packet
    Pkt = nft_vm_pkt:tcp(
        #{saddr => {192,168,1,100}, daddr => {10,0,0,1}},
        #{sport => 54321, dport => 22}),

    %% Define rules as expression lists
    Rules = [
        %% Rule 1: tcp dport 22 accept
        [{meta, #{key => l4proto, dreg => 1}},
         {cmp, #{sreg => 1, op => eq, data => <<6>>}},
         {payload, #{base => transport, offset => 2, len => 2, dreg => 1}},
         {cmp, #{sreg => 1, op => eq, data => <<22:16/big>>}},
         {immediate, #{verdict => accept}}],

        %% Rule 2: drop (default)
        [{immediate, #{verdict => drop}}]
    ],

    %% Evaluate
    {accept, Trace} = nft_vm:eval_chain(Rules, Pkt),
    nft_vm:print_trace(Trace).
""".

-export([eval_chain/2, eval_chain/3,
         eval_rule/3,
         eval_expr/3,
         print_trace/1,
         new_regs/0]).

-export_type([packet/0, regs/0, verdict/0, expr/0, rule/0, trace_entry/0]).

%% --- Types ---

-doc "VM verdict. Mirrors the kernel's NFT_BREAK, NF_ACCEPT, NF_DROP, NFT_JUMP, NFT_GOTO, NFT_RETURN.".
-type verdict() :: accept | drop | continue | break
                 | {jump, binary()} | {goto, binary()} | return.

-doc "VM register file. Contains a verdict and a map of data register contents.".
-type regs() :: #{
    verdict := verdict(),
    data := #{non_neg_integer() => binary()}
}.

-doc "Synthetic packet. Contains raw layer bytes, metadata, conntrack state, and set membership.".
-type packet() :: #{
    %% Raw layer bytes
    network    => binary(),   %% IP header
    transport  => binary(),   %% TCP/UDP header
    link       => binary(),   %% Ethernet header
    %% Metadata (meta expression reads these)
    nfproto    => 2 | 10,     %% 2=IPv4, 10=IPv6
    l4proto    => 0..255,     %% 6=TCP, 17=UDP, 1=ICMP
    iif        => non_neg_integer(),
    oif        => non_neg_integer(),
    iifname    => binary(),
    oifname    => binary(),
    len        => non_neg_integer(),
    mark       => non_neg_integer(),
    %% Conntrack state (ct expression reads these)
    ct_state   => non_neg_integer(),
    ct_mark    => non_neg_integer(),
    ct_status  => non_neg_integer(),
    %% Sets (lookup expression checks these)
    sets       => #{binary() => sets:set(binary())},
    %% Limit state (injected by with_limit_state/2 for rate limiting)
    limit_state => map()
}.

-doc "A single VM instruction: {type, Options}.".
-type expr() :: {atom(), map()}.
-doc "A rule is a list of expressions evaluated left to right.".
-type rule() :: [expr()].

-doc "One step in the execution trace: the expression, register state before/after, and result.".
-type trace_entry() :: #{
    expr := expr(),
    regs_before := regs(),
    regs_after := regs(),
    result := ok | break | {verdict, verdict()}
}.

%% --- Public API ---

-doc """
Evaluate a chain of rules against a packet.

Returns {Verdict, Trace} where Verdict is accept | drop and
Trace is a list of trace entries showing each expression evaluation.

The default chain policy is drop (if no rule matches).
""".
-spec eval_chain([rule()], packet()) -> {verdict(), [trace_entry()]}.
eval_chain(Rules, Pkt) ->
    eval_chain(Rules, Pkt, drop).

-doc """
Evaluate a chain with explicit default policy.
""".
-spec eval_chain([rule()], packet(), verdict()) -> {verdict(), [trace_entry()]}.
eval_chain(Rules, Pkt, DefaultPolicy) ->
    eval_rules(Rules, Pkt, DefaultPolicy, []).

-doc """
Evaluate a single rule against a packet with given register state.

Returns {Verdict, NewRegs, Trace} where Verdict is the rule's
outcome: a terminal verdict, break, or continue.
""".
-spec eval_rule(rule(), packet(), regs()) -> {verdict(), regs(), [trace_entry()]}.
eval_rule(Exprs, Pkt, Regs) ->
    eval_exprs(Exprs, Pkt, Regs, []).

-spec eval_expr(expr(), packet(), regs()) -> {ok | break | {verdict, verdict()}, regs()}.

%% ===================================================================
%% PRODUCERS — load data into registers
%% ===================================================================

%% --- payload: load bytes from packet layers ---
-doc """
Evaluate a single expression against a packet with given register state.

Returns {ok, NewRegs} if the expression succeeded,
{break, Regs} if a match failed (skip rest of rule),
or {{verdict, V}, Regs} if a terminal verdict was set.
""".
eval_expr({payload, #{base := Base, offset := Offset, len := Len, dreg := DReg}}, Pkt, Regs) ->
    Layer = case Base of
        link      -> maps:get(link, Pkt, <<>>);
        network   -> maps:get(network, Pkt, <<>>);
        transport -> maps:get(transport, Pkt, <<>>);
        N when is_integer(N), N =:= 0 -> maps:get(link, Pkt, <<>>);
        N when is_integer(N), N =:= 1 -> maps:get(network, Pkt, <<>>);
        N when is_integer(N), N =:= 2 -> maps:get(transport, Pkt, <<>>)
    end,
    case byte_size(Layer) >= Offset + Len of
        true ->
            <<_:Offset/binary, Val:Len/binary, _/binary>> = Layer,
            {ok, reg_store(DReg, Val, Regs)};
        false ->
            %% Packet too short — kernel would skip
            {break, Regs}
    end;

%% --- meta: load metadata into register ---
eval_expr({meta, #{key := Key, dreg := DReg}}, Pkt, Regs) ->
    Val = case Key of
        l4proto  -> <<(maps:get(l4proto, Pkt, 0))>>;
        nfproto  -> <<(maps:get(nfproto, Pkt, 2))>>;
        iif      -> <<(maps:get(iif, Pkt, 0)):32/native>>;
        oif      -> <<(maps:get(oif, Pkt, 0)):32/native>>;
        iifname  -> pad_to(maps:get(iifname, Pkt, <<>>), 16);
        oifname  -> pad_to(maps:get(oifname, Pkt, <<>>), 16);
        len      -> <<(maps:get(len, Pkt, 0)):32/native>>;
        mark     -> <<(maps:get(mark, Pkt, 0)):32/native>>;
        protocol -> <<(maps:get(nfproto, Pkt, 2)):16/native>>;
        N when is_integer(N) -> <<0:32>>
    end,
    {ok, reg_store(DReg, Val, Regs)};

%% --- ct: load conntrack state ---
eval_expr({ct, #{key := Key, dreg := DReg}}, Pkt, Regs) ->
    Val = case Key of
        state  -> <<(maps:get(ct_state, Pkt, 0)):32/native>>;
        mark   -> <<(maps:get(ct_mark, Pkt, 0)):32/native>>;
        status -> <<(maps:get(ct_status, Pkt, 0)):32/native>>;
        _ -> <<0:32>>
    end,
    {ok, reg_store(DReg, Val, Regs)};

%% ===================================================================
%% CONSUMERS — test register values
%% ===================================================================

%% --- cmp: compare register against constant ---
eval_expr({cmp, #{sreg := SReg, op := Op, data := Expected}}, _Pkt, Regs) ->
    Actual = reg_load(SReg, Regs),
    %% Ensure both are same length for comparison
    Result = case compare(Actual, Expected) of
        equal   -> Op =:= eq orelse Op =:= lte orelse Op =:= gte;
        less    -> Op =:= lt orelse Op =:= lte orelse Op =:= neq;
        greater -> Op =:= gt orelse Op =:= gte orelse Op =:= neq
    end,
    case Result of
        true  -> {ok, Regs};
        false -> {break, Regs}
    end;

%% --- range: check if register value is within [from, to] ---
eval_expr({range, #{sreg := SReg, op := Op, from_data := From, to_data := To}}, _Pkt, Regs) ->
    Val = reg_load(SReg, Regs),
    InRange = compare(Val, From) =/= less andalso compare(Val, To) =/= greater,
    Match = case Op of
        eq  -> InRange;
        neq -> not InRange
    end,
    case Match of
        true  -> {ok, Regs};
        false -> {break, Regs}
    end;

%% --- bitwise: reg_dreg = (reg_sreg & mask) ^ xor ---
eval_expr({bitwise, #{sreg := SReg, dreg := DReg, mask := Mask, xor_val := Xor}}, _Pkt, Regs) ->
    Val = reg_load(SReg, Regs),
    Masked = bin_and(Val, Mask),
    Result = bin_xor(Masked, Xor),
    {ok, reg_store(DReg, Result, Regs)};

%% --- lookup: check if register value is in a set ---
eval_expr({lookup, #{sreg := SReg, set := SetName} = Opts}, Pkt, Regs) ->
    Val = reg_load(SReg, Regs),
    Sets = maps:get(sets, Pkt, #{}),
    Set = maps:get(SetName, Sets, sets:new()),
    Found = sets:is_element(Val, Set),
    Inverted = maps:get(flags, Opts, 0) band 1 =/= 0,
    Match = case Inverted of
        false -> Found;
        true  -> not Found
    end,
    case Match of
        true  -> {ok, Regs};
        false -> {break, Regs}
    end;

%% ===================================================================
%% ACTIONS — side effects (no register or flow impact)
%% ===================================================================

%% --- counter: increment counters (no-op in simulator, tracked in trace) ---
eval_expr({counter, _Opts}, _Pkt, Regs) ->
    {ok, Regs};

%% --- objref: reference a named object (no-op in simulator) ---
eval_expr({objref, _Opts}, _Pkt, Regs) ->
    {ok, Regs};

%% --- log: log the packet (no-op in simulator, visible in trace) ---
eval_expr({log, _Opts}, _Pkt, Regs) ->
    {ok, Regs};

%% --- limit: token bucket rate limiter ---
%% In the simulator, limit can be configured to match or not match.
%% By default, the limit expression succeeds (token available).
%% Set #{over => true} in the packet's limit_state to simulate
%% being over the rate limit.
eval_expr({limit, #{rate := _Rate} = Opts}, Pkt, Regs) ->
    LimitState = maps:get(limit_state, Pkt, #{}),
    LimitName = maps:get(name, Opts, default),
    IsOver = maps:get(LimitName, LimitState, false),
    %% Kernel limit with NFT_LIMIT_F_INV (flags=1) BREAKs when under limit.
    %% Without the flag, it BREAKs when over limit.
    Inverted = maps:get(flags, Opts, 0) band 1 =/= 0,
    ShouldBreak = case Inverted of
        false -> IsOver;      %% normal: BREAK when over
        true  -> not IsOver   %% inverted: BREAK when under
    end,
    case ShouldBreak of
        true  -> {break, Regs};
        false -> {ok, Regs}
    end;

%% ===================================================================
%% TERMINALS — set verdict
%% ===================================================================

%% --- immediate: set verdict or load data ---
eval_expr({immediate, #{verdict := V}}, _Pkt, Regs) ->
    {{verdict, V}, Regs#{verdict := V}};

%% --- immediate: load raw data into register ---
eval_expr({immediate, #{dreg := DReg, data := Data}}, _Pkt, Regs) ->
    {ok, reg_store(DReg, Data, Regs)};

%% --- reject: drop + send ICMP (in simulator, just drop) ---
eval_expr({reject, _Opts}, _Pkt, Regs) ->
    {{verdict, drop}, Regs#{verdict := drop}};

%% ===================================================================
%% FALLBACK — unknown expression
%% ===================================================================
eval_expr({Unknown, _Opts}, _Pkt, Regs) ->
    error({unknown_expression, Unknown, Regs}).

%% --- Trace Printing ---

-doc """
Print a human-readable execution trace.

Shows each expression evaluated, register state, and whether
it matched (ok), failed (BREAK), or set a verdict.
""".
-spec print_trace([trace_entry()]) -> ok.
print_trace(Trace) ->
    io:format("~n=== nft_vm trace ===~n", []),
    lists:foreach(fun(#{expr := {Type, Opts}, result := Result, regs_after := RegsAfter}) ->
        ResultStr = case Result of
            ok -> "ok";
            break -> "BREAK";
            {verdict, V} -> io_lib:format("VERDICT:~p", [V])
        end,
        DataRegs = maps:get(data, RegsAfter),
        RegStr = maps:fold(fun(K, V, Acc) ->
            [io_lib:format(" reg~p=~s", [K, bin_to_hex(V)]) | Acc]
        end, [], DataRegs),
        io:format("  [ ~-12s ~-40s ] ~-16s~s~n", [
            atom_to_list(Type),
            format_opts(Type, Opts),
            ResultStr,
            lists:flatten(lists:reverse(RegStr))
        ])
    end, Trace),
    io:format("=== end trace ===~n~n", []).

%% --- Register Management ---

-doc "Create a fresh register file with all registers zeroed.".
-spec new_regs() -> regs().
new_regs() ->
    #{verdict => continue, data => #{}}.

%% --- Internal Functions ---

-spec reg_store(non_neg_integer(), binary(), regs()) -> regs().
reg_store(Reg, Val, #{data := Data} = Regs) ->
    Regs#{data := Data#{Reg => Val}}.

-spec reg_load(non_neg_integer(), regs()) -> binary().
reg_load(Reg, #{data := Data}) ->
    maps:get(Reg, Data, <<0:32>>).

%% Compare two binaries as unsigned big-endian integers
-spec compare(binary(), binary()) -> equal | less | greater.
compare(A, B) ->
    %% Pad to same length for fair comparison
    MaxLen = max(byte_size(A), byte_size(B)),
    PA = pad_left(A, MaxLen),
    PB = pad_left(B, MaxLen),
    if
        PA =:= PB -> equal;
        PA < PB   -> less;
        true      -> greater
    end.

-spec pad_left(binary(), non_neg_integer()) -> binary().
pad_left(Bin, Len) when byte_size(Bin) >= Len -> Bin;
pad_left(Bin, Len) ->
    Pad = Len - byte_size(Bin),
    <<0:(Pad * 8), Bin/binary>>.

-spec pad_to(binary(), non_neg_integer()) -> binary().
pad_to(Bin, Len) when byte_size(Bin) >= Len ->
    binary:part(Bin, 0, Len);
pad_to(Bin, Len) ->
    Pad = Len - byte_size(Bin),
    <<Bin/binary, 0:(Pad * 8)>>.

-spec bin_and(binary(), binary()) -> binary().
bin_and(A, B) ->
    list_to_binary([X band Y || {X, Y} <- lists:zip(
        binary_to_list(A), binary_to_list(B))]).

-spec bin_xor(binary(), binary()) -> binary().
bin_xor(A, B) ->
    list_to_binary([X bxor Y || {X, Y} <- lists:zip(
        binary_to_list(A), binary_to_list(B))]).

%% --- Chain / Rule Evaluation ---

eval_rules([], _Pkt, DefaultPolicy, AllTrace) ->
    {DefaultPolicy, lists:reverse(AllTrace)};
eval_rules([Rule | Rest], Pkt, DefaultPolicy, AllTrace) ->
    {Verdict, _Regs, RuleTrace} = eval_rule(Rule, Pkt, new_regs()),
    NewTrace = lists:reverse(RuleTrace) ++ AllTrace,
    case Verdict of
        break    -> eval_rules(Rest, Pkt, DefaultPolicy, NewTrace);
        continue -> eval_rules(Rest, Pkt, DefaultPolicy, NewTrace);
        accept   -> {accept, lists:reverse(NewTrace)};
        drop     -> {drop, lists:reverse(NewTrace)};
        {jump, _Chain} -> {Verdict, lists:reverse(NewTrace)};
        {goto, _Chain} -> {Verdict, lists:reverse(NewTrace)};
        return   -> {return, lists:reverse(NewTrace)}
    end.

eval_exprs([], _Pkt, Regs, Trace) ->
    {maps:get(verdict, Regs), Regs, lists:reverse(Trace)};
eval_exprs([Expr | Rest], Pkt, Regs, Trace) ->
    {Result, NewRegs} = eval_expr(Expr, Pkt, Regs),
    Entry = #{expr => Expr, regs_before => Regs, regs_after => NewRegs, result => Result},
    case Result of
        ok ->
            eval_exprs(Rest, Pkt, NewRegs, [Entry | Trace]);
        break ->
            {break, NewRegs, lists:reverse([Entry | Trace])};
        {verdict, _V} ->
            {maps:get(verdict, NewRegs), NewRegs, lists:reverse([Entry | Trace])}
    end.

%% --- Formatting helpers ---

format_opts(payload, #{base := B, offset := O, len := L, dreg := D}) ->
    io_lib:format("load ~pb @ ~p + ~p => reg ~p", [L, B, O, D]);
format_opts(meta, #{key := K, dreg := D}) ->
    io_lib:format("load ~p => reg ~p", [K, D]);
format_opts(ct, #{key := K, dreg := D}) ->
    io_lib:format("load ~p => reg ~p", [K, D]);
format_opts(cmp, #{sreg := S, op := Op, data := Data}) ->
    io_lib:format("~p reg ~p ~s", [Op, S, bin_to_hex(Data)]);
format_opts(bitwise, #{sreg := S, dreg := D}) ->
    io_lib:format("reg ~p = (reg ~p & mask) ^ xor", [D, S]);
format_opts(lookup, #{sreg := S, set := Set}) ->
    io_lib:format("reg ~p in set ~s", [S, Set]);
format_opts(immediate, #{verdict := V}) ->
    io_lib:format("=> ~p", [V]);
format_opts(immediate, #{dreg := D, data := Data}) ->
    io_lib:format("reg ~p = ~s", [D, bin_to_hex(Data)]);
format_opts(counter, _) -> "pkts/bytes";
format_opts(objref, #{name := N}) -> io_lib:format("counter ~s", [N]);
format_opts(objref, _) -> "objref";
format_opts(log, #{prefix := P}) -> io_lib:format("prefix ~s", [P]);
format_opts(log, _) -> "log";
format_opts(limit, #{rate := R}) -> io_lib:format("rate ~p", [R]);
format_opts(reject, _) -> "=> reject";
format_opts(range, #{sreg := S}) -> io_lib:format("reg ~p in range", [S]);
format_opts(_, Opts) -> io_lib:format("~p", [Opts]).

-spec bin_to_hex(binary()) -> string().
bin_to_hex(Bin) ->
    lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B>> <= Bin]).
