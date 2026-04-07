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

-module(nft_encode).
-moduledoc """
Encode nf_tables semantic terms into Netlink binary messages.

Translates the intermediate representation from nft_expr_ir into
the Netlink attribute bytes that the kernel expects. All domain
knowledge (symbolic constants, verdict encoding, key mappings)
lives here. The _gen modules handle raw attribute encoding.

Usage:
    Rule = nft_rules:tcp_accept(22),
    Msg = nft_encode:rule(inet, <<"fw">>, <<"input">>, Rule, Seq),
    MsgFun = nft_encode:rule_fun(inet, <<"fw">>, <<"input">>, Rule).
""".

-export([expr/1, exprs/1, rule/5, rule_fun/4]).

-export_type([family/0]).

%% --- Types ---

-doc "Address family atom or integer.".
-type family() :: inet | ip | ip6 | arp | bridge | netdev | non_neg_integer().

-include("nft_constants.hrl").

%% --- Public API ---

-doc """
Encode a single expression term to its Netlink binary representation.
""".
-spec expr(nft_expr_ir:expr()) -> binary().

%% === payload ===
expr({payload, #{base := Base, offset := Offset, len := Len, dreg := DReg}}) ->
    nft_expr_payload_gen:encode(#{
        dreg => DReg,
        base => payload_base(Base),
        offset => Offset,
        len => Len
    });
%% === meta ===
expr({meta, #{key := Key, dreg := DReg}}) ->
    nft_expr_meta_gen:encode(#{
        key => meta_key(Key),
        dreg => DReg
    });
%% === ct (read: load into register) ===
expr({ct, #{key := Key, dreg := DReg}}) ->
    nft_expr_ct_gen:encode(#{
        key => ct_key(Key),
        dreg => DReg
    });
%% === ct (write: set from register) ===
expr({ct, #{key := Key, sreg := SReg}}) ->
    nft_expr_ct_gen:encode(#{
        key => ct_key(Key),
        sreg => SReg
    });
%% === cmp ===
expr({cmp, #{sreg := SReg, op := Op, data := Data}}) ->
    nft_expr_cmp_gen:encode(#{
        sreg => SReg,
        op => cmp_op(Op),
        data => nft_data_value(Data)
    });
%% === bitwise ===
expr({bitwise, #{sreg := SReg, dreg := DReg, mask := Mask, xor_val := Xor}}) ->
    nft_expr_bitwise_gen:encode(#{
        sreg => SReg,
        dreg => DReg,
        len => byte_size(Mask),
        mask => nft_data_value(Mask),
        'xor' => nft_data_value(Xor)
    });
%% === range ===
expr({range, #{sreg := SReg, op := Op, from_data := From, to_data := To}}) ->
    nft_expr_range_gen:encode(#{
        sreg => SReg,
        op => range_op(Op),
        from_data => nft_data_value(From),
        to_data => nft_data_value(To)
    });
%% === lookup (verdict map: dreg=0 means verdict register) ===
expr({lookup, #{sreg := SReg, set := SetName, dreg := 0} = Opts}) ->
    nft_expr_lookup_gen:encode(#{
        set => SetName,
        sreg => SReg,
        dreg => ?NFT_REG_VERDICT,
        set_id => maps:get(set_id, Opts, 0)
    });
%% === lookup (inverted) ===
expr({lookup, #{sreg := SReg, set := SetName, flags := 1} = Opts}) ->
    nft_expr_lookup_gen:encode(#{
        set => SetName,
        sreg => SReg,
        set_id => maps:get(set_id, Opts, 0),
        flags => ?NFT_LOOKUP_F_INV
    });
%% === lookup (data map: has dreg for result storage) ===
expr({lookup, #{sreg := SReg, set := SetName, dreg := DReg} = Opts}) when DReg > 0 ->
    nft_expr_lookup_gen:encode(#{
        set => SetName,
        sreg => SReg,
        dreg => DReg,
        set_id => maps:get(set_id, Opts, 0)
    });
%% === lookup (normal set membership, no data returned) ===
expr({lookup, #{sreg := SReg, set := SetName} = Opts}) ->
    nft_expr_lookup_gen:encode(#{
        set => SetName,
        sreg => SReg,
        set_id => maps:get(set_id, Opts, 0)
    });
%% === counter ===
expr({counter, #{packets := Pkts, bytes := Bytes}}) ->
    nft_expr_counter_gen:encode(#{bytes => Bytes, packets => Pkts});
expr({counter, _}) ->
    nft_expr_counter_gen:encode(#{bytes => 0, packets => 0});
%% === objref (counter) ===
expr({objref, #{type := counter, name := Name}}) ->
    nft_expr_objref_gen:encode(#{
        imm_type => ?NFT_OBJECT_COUNTER,
        imm_name => Name
    });
%% === objref (quota) ===
expr({objref, #{type := quota, name := Name}}) ->
    nft_expr_objref_gen:encode(#{
        imm_type => ?NFT_OBJECT_QUOTA,
        imm_name => Name
    });
%% === objref (limit) ===
expr({objref, #{type := limit, name := Name}}) ->
    nft_expr_objref_gen:encode(#{
        imm_type => ?NFT_OBJECT_LIMIT,
        imm_name => Name
    });
%% === log ===
expr({log, Opts}) ->
    nft_expr_log_gen:encode(Opts);
%% === limit ===
expr(
    {limit, #{
        rate := Rate,
        unit := Unit,
        burst := Burst,
        type := Type,
        flags := Flags
    }}
) ->
    nft_expr_limit_gen:encode(#{
        rate => Rate,
        unit => Unit,
        burst => Burst,
        type => limit_type(Type),
        flags => Flags
    });
%% === immediate (data into register) ===
expr({immediate, #{dreg := DReg, data := Data}}) when is_binary(Data) ->
    nft_expr_immediate_gen:encode(#{
        dreg => DReg,
        data => nft_data_value(Data)
    });
%% === immediate (verdict) ===
expr({immediate, #{verdict := Verdict}}) ->
    encode_verdict(Verdict);
%% === reject ===
expr({reject, #{type := Type, icmp_code := Code}}) ->
    nft_expr_reject_gen:encode(#{type => Type, icmp_code => Code});
expr({reject, _}) ->
    nft_expr_reject_gen:encode(#{type => 0, icmp_code => 3});
%% === nat (SNAT / DNAT) ===
expr({nat, #{type := Type} = Opts}) ->
    nft_expr_nat_gen:encode(Opts#{type := nat_type(Type)});
%% === masq (masquerade / dynamic SNAT) ===
expr({masq, Opts}) ->
    nft_expr_masq_gen:encode(Opts);
%% === quota ===
expr({quota, Opts}) ->
    nft_expr_quota_gen:encode(Opts);
%% === hash ===
expr({hash, Opts}) ->
    nft_expr_hash_gen:encode(Opts);
%% === queue (NFQUEUE to userspace) ===
expr({queue, Opts}) ->
    nft_expr_queue_gen:encode(Opts);
%% === redir (port redirect) ===
expr({redir, Opts}) ->
    nft_expr_redir_gen:encode(Opts);
%% === notrack (conntrack bypass — name only, no attributes) ===
expr({notrack, #{}}) ->
    %% NFTA_EXPR_NAME = 1
    nfnl_attr:encode_str(1, <<"notrack">>);
%% === dynset with single nested expression (meter) ===
expr({dynset, #{exprs := [SingleExpr]} = Opts}) ->
    %% For a single expression, use NFTA_DYNSET_EXPR (7) directly,
    %% matching libnftnl's behavior (nftnl_expr_dynset_build).
    EncodedExpr = expr(SingleExpr),
    nft_expr_dynset_gen:encode(
        maps:remove(exprs, Opts#{expr => EncodedExpr})
    );
%% === dynset with multiple nested expressions ===
expr({dynset, #{exprs := Exprs} = Opts}) ->
    %% For multiple expressions, use NFTA_DYNSET_EXPRESSIONS (10)
    %% with NFTA_LIST_ELEM wrapping.
    EncodedExprs = iolist_to_binary([nfnl_attr:encode_nested(1, expr(E)) || E <- Exprs]),
    nft_expr_dynset_gen:encode(
        maps:remove(exprs, Opts#{expressions => EncodedExprs})
    );
%% === socket (with symbolic key translation) ===
expr({socket, #{key := Key} = Opts}) when is_atom(Key) ->
    nft_expr_socket_gen:encode(Opts#{key := socket_key(Key)});
%% === catch-all: delegate directly to _gen module ===
%% Any expression {ExprName, Opts} where ExprName is an atom and
%% nft_expr_<ExprName>_gen:encode/1 exists will be dispatched here.
%% This covers: byteorder, connlimit, dup, dynset, exthdr, fib, fwd,
%% inner, last, ng, offload, osf, rt, secmark, socket, synproxy,
%% tproxy, tunnel, xfrm — and any future generated modules.
expr({ExprName, Opts}) when is_atom(ExprName), is_map(Opts) ->
    Mod = list_to_existing_atom(
        "nft_expr_" ++ atom_to_list(ExprName) ++ "_gen"
    ),
    Mod:encode(Opts).

-doc "Encode a list of expression terms to a list of Netlink binaries.".
-spec exprs([nft_expr_ir:expr()]) -> [binary()].
exprs(Terms) ->
    [expr(T) || T <- Terms].

-doc "Build a complete NEWRULE Netlink message from semantic terms.".
-spec rule(family(), binary(), binary(), [nft_expr_ir:expr()], non_neg_integer()) ->
    nfnl_msg:nl_msg().
rule(Family, Table, Chain, ExprTerms, Seq) ->
    Bins = exprs(ExprTerms),
    nft_rule:add(family_val(Family), Table, Chain, Bins, Seq).

-doc "Wrap a rule as a msg_fun for nfnl_server:apply_msgs/2.".
-spec rule_fun(family(), binary(), binary(), [nft_expr_ir:expr()]) ->
    fun((non_neg_integer()) -> nfnl_msg:nl_msg()).
rule_fun(Family, Table, Chain, ExprTerms) ->
    fun(Seq) -> rule(Family, Table, Chain, ExprTerms, Seq) end.

%% ===================================================================
%% Internal: Verdict encoding
%% ===================================================================

encode_verdict(accept) ->
    encode_simple_verdict(?NF_ACCEPT);
encode_verdict(drop) ->
    encode_simple_verdict(?NF_DROP);
encode_verdict(return) ->
    encode_simple_verdict(?NFT_RETURN);
encode_verdict({jump, Chain}) ->
    encode_chain_verdict(?NFT_JUMP, Chain);
encode_verdict({goto, Chain}) ->
    encode_chain_verdict(?NFT_GOTO, Chain).

encode_simple_verdict(Code) ->
    VerdictNest = nfnl_attr:encode_nested(
        ?NFTA_DATA_VERDICT,
        nfnl_attr:encode_u32(?NFTA_VERDICT_CODE, Code)
    ),
    build_immediate_verdict(VerdictNest).

encode_chain_verdict(Code, Chain) ->
    VerdictNest = nfnl_attr:encode_nested(
        ?NFTA_DATA_VERDICT,
        iolist_to_binary([
            nfnl_attr:encode_u32(?NFTA_VERDICT_CODE, Code),
            nfnl_attr:encode_str(?NFTA_VERDICT_CHAIN, Chain)
        ])
    ),
    build_immediate_verdict(VerdictNest).

build_immediate_verdict(VerdictNest) ->
    DataNest = nfnl_attr:encode_nested(?NFTA_IMMEDIATE_DATA, VerdictNest),
    Attrs = iolist_to_binary([
        %% NFTA_IMMEDIATE_DREG
        nfnl_attr:encode_u32(1, ?NFT_REG_VERDICT),
        DataNest
    ]),
    nft_expr:build(<<"immediate">>, Attrs).

%% ===================================================================
%% Internal: Data wrapping
%% ===================================================================

%% Wrap raw binary data in NFTA_DATA_VALUE attribute
nft_data_value(Bin) when is_binary(Bin) ->
    %% NFTA_DATA_VALUE = 1 (plain, not nested)
    nfnl_attr:encode(1, Bin).

%% ===================================================================
%% Internal: Symbolic constant translation
%% ===================================================================

family_val(inet) -> ?NFPROTO_INET;
family_val(ip) -> ?NFPROTO_IPV4;
family_val(ip6) -> ?NFPROTO_IPV6;
family_val(arp) -> 3;
family_val(bridge) -> 7;
family_val(netdev) -> 5;
family_val(N) when is_integer(N) -> N.

payload_base(link) -> ?NFT_PAYLOAD_LL_HEADER;
payload_base(network) -> ?NFT_PAYLOAD_NETWORK_HEADER;
payload_base(transport) -> ?NFT_PAYLOAD_TRANSPORT_HEADER;
payload_base(N) when is_integer(N) -> N.

meta_key(len) -> ?NFT_META_LEN;
meta_key(protocol) -> ?NFT_META_PROTOCOL;
meta_key(nfproto) -> ?NFT_META_NFPROTO;
meta_key(l4proto) -> ?NFT_META_L4PROTO;
meta_key(iif) -> ?NFT_META_IIF;
meta_key(oif) -> ?NFT_META_OIF;
meta_key(iifname) -> ?NFT_META_IIFNAME;
meta_key(oifname) -> ?NFT_META_OIFNAME;
meta_key(mark) -> ?NFT_META_MARK;
meta_key(N) when is_integer(N) -> N.

ct_key(state) -> ?NFT_CT_STATE;
ct_key(dir) -> ?NFT_CT_DIRECTION;
ct_key(status) -> ?NFT_CT_STATUS;
ct_key(mark) -> ?NFT_CT_MARK;
ct_key(l3proto) -> ?NFT_CT_L3PROTOCOL;
ct_key(N) when is_integer(N) -> N.

cmp_op(eq) -> ?NFT_CMP_EQ;
cmp_op(neq) -> ?NFT_CMP_NEQ;
cmp_op(lt) -> ?NFT_CMP_LT;
cmp_op(lte) -> ?NFT_CMP_LTE;
cmp_op(gt) -> ?NFT_CMP_GT;
cmp_op(gte) -> ?NFT_CMP_GTE;
cmp_op(N) when is_integer(N) -> N.

range_op(eq) -> ?NFT_RANGE_EQ;
range_op(neq) -> ?NFT_RANGE_NEQ;
range_op(N) when is_integer(N) -> N.

limit_type(0) -> ?NFT_LIMIT_PKTS;
limit_type(1) -> ?NFT_LIMIT_PKT_BYTES;
limit_type(pkts) -> ?NFT_LIMIT_PKTS;
limit_type(bytes) -> ?NFT_LIMIT_PKT_BYTES.

nat_type(snat) -> 0;
nat_type(dnat) -> 1;
nat_type(N) when is_integer(N) -> N.

socket_key(transparent) -> 0;
socket_key(mark) -> 1;
socket_key(wildcard) -> 2;
socket_key(cgroupv2) -> 3.
