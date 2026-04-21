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

-module(nft_decode).
-moduledoc """
Decode nf_tables rule expressions into human-readable descriptions.

Parses the raw netlink attributes returned by the kernel for each
rule and produces a text description like:
    "tcp dport 22 counter packets 42 bytes 3360 accept"

This is the inverse of what nft_expr_* modules do: instead of
building binary expressions, we read them back.
""".

-export([rule_description/1]).
%% Exposed for fuzzing — pure parsers of nft-internal exprs.
-export([decode_expr/2, decode_expr_attrs/1, decode_list_elem/1]).

-include("nft_constants.hrl").

%% --- Public API ---

-doc """
Decode a list of NFTA_LIST_ELEM expressions into a human-readable string.

Input is the decoded attribute list from NFTA_RULE_EXPRESSIONS.
""".
-spec rule_description(binary() | [tuple()]) -> binary().
rule_description(ExprBin) when is_binary(ExprBin) ->
    %% nfnl_attr:decode raises on malformed input (short header, bad
    %% Len field).  Swallow that here — this function is purely
    %% human-output, its callers route the return to logs/dumps.
    %% Crashing takes down the nft query gen_server on any malformed
    %% kernel response.
    try nfnl_attr:decode(ExprBin) of
        Decoded -> rule_description(Decoded)
    catch
        error:{invalid_nla, _, _} -> <<"<invalid nla>">>;
        _:_ -> <<"<unparseable>">>
    end;
rule_description(ExprList) when is_list(ExprList) ->
    Exprs = lists:map(fun decode_list_elem/1, ExprList),
    Parts = build_description(Exprs, []),
    iolist_to_binary(lists:join(<<" ">>, Parts)).

%% --- Internal: decode each expression ---

-spec decode_list_elem(tuple()) -> map().
decode_list_elem({_, nested, Attrs}) ->
    decode_expr_attrs(Attrs);
decode_list_elem({_, Bin}) when is_binary(Bin) ->
    %% Catch malformed-NLA inside an expression element — same
    %% Glasbox as the top-level rule_description wrap.
    try nfnl_attr:decode(Bin) of
        Attrs -> decode_expr_attrs(Attrs)
    catch
        _:_ -> #{type => unknown}
    end;
decode_list_elem(_) ->
    #{type => unknown}.

-spec decode_expr_attrs([tuple()]) -> map().
decode_expr_attrs(Attrs) ->
    Name =
        case lists:keyfind(?NFTA_EXPR_NAME, 1, Attrs) of
            {_, N} -> strip_null(N);
            false -> <<"unknown">>
        end,
    Data =
        case lists:keyfind(?NFTA_EXPR_DATA, 1, Attrs) of
            {_, nested, D} -> D;
            {_, D} when is_binary(D) ->
                try nfnl_attr:decode(D) of
                    Ds -> Ds
                catch _:_ -> [] end;
            false -> []
        end,
    decode_expr(Name, Data).

-spec decode_expr(binary(), [tuple()]) -> map().
decode_expr(Name, Data) ->
    try decode_expr_inner(Name, Data)
    catch _:_ -> #{type => Name, decode_error => true}
    end.

-spec decode_expr_inner(binary(), [tuple()]) -> map().
decode_expr_inner(<<"meta">>, Data) ->
    Key =
        case lists:keyfind(2, 1, Data) of
            {2, <<K:32/big>>} -> meta_key_name(K);
            _ -> <<"?">>
        end,
    #{type => meta, key => Key};
decode_expr_inner(<<"cmp">>, Data) ->
    Op =
        case lists:keyfind(2, 1, Data) of
            {2, <<O:32/big>>} -> cmp_op_name(O);
            _ -> <<"?">>
        end,
    Value =
        case lists:keyfind(3, 1, Data) of
            {3, nested, VAttrs} ->
                case lists:keyfind(1, 1, VAttrs) of
                    {1, V} -> V;
                    _ -> <<>>
                end;
            {3, VBin} when is_binary(VBin) ->
                InnerAttrs = nfnl_attr:decode(VBin),
                case lists:keyfind(1, 1, InnerAttrs) of
                    {1, V} -> V;
                    _ -> <<>>
                end;
            _ ->
                <<>>
        end,
    #{type => cmp, op => Op, value => Value};
decode_expr_inner(<<"payload">>, Data) ->
    Base =
        case lists:keyfind(2, 1, Data) of
            {2, <<B:32/big>>} -> B;
            _ -> -1
        end,
    Offset =
        case lists:keyfind(3, 1, Data) of
            {3, <<O:32/big>>} -> O;
            _ -> -1
        end,
    Len =
        case lists:keyfind(4, 1, Data) of
            {4, <<L:32/big>>} -> L;
            _ -> 0
        end,
    #{type => payload, base => Base, offset => Offset, len => Len};
decode_expr_inner(<<"immediate">>, Data) ->
    %% Same Glasbox as rule_description: nfnl_attr:decode + the
    %% verdict decoder can both raise on malformed inputs.  Swallow
    %% tagged errors instead of propagating to the caller (nft_query).
    try
        case lists:keyfind(2, 1, Data) of
            {2, nested, VerdictOuter} ->
                decode_verdict(VerdictOuter);
            {2, VBin} when is_binary(VBin) ->
                decode_verdict(nfnl_attr:decode(VBin));
            _ ->
                #{type => immediate, verdict => <<"?">>}
        end
    catch _:_ ->
        #{type => immediate, verdict => <<"?">>}
    end;
decode_expr_inner(<<"counter">>, Data) ->
    Bytes =
        case lists:keyfind(1, 1, Data) of
            {1, <<B:64/big>>} -> B;
            _ -> 0
        end,
    Pkts =
        case lists:keyfind(2, 1, Data) of
            {2, <<P:64/big>>} -> P;
            _ -> 0
        end,
    #{type => counter, packets => Pkts, bytes => Bytes};
decode_expr_inner(<<"ct">>, Data) ->
    Key =
        case lists:keyfind(2, 1, Data) of
            {2, <<K:32/big>>} -> ct_key_name(K);
            _ -> <<"?">>
        end,
    #{type => ct, key => Key};
decode_expr_inner(<<"bitwise">>, _Data) ->
    #{type => bitwise};
decode_expr_inner(<<"lookup">>, Data) ->
    Set =
        case lists:keyfind(1, 1, Data) of
            {1, S} -> strip_null(S);
            _ -> <<"?">>
        end,
    #{type => lookup, set => Set};
decode_expr_inner(<<"log">>, Data) ->
    Prefix =
        case lists:keyfind(2, 1, Data) of
            {2, P} -> strip_null(P);
            _ -> <<>>
        end,
    #{type => log, prefix => Prefix};
decode_expr_inner(Name, _Data) ->
    #{type => unknown, name => Name}.

-spec decode_verdict([tuple()]) -> map().
decode_verdict(Attrs) ->
    VerdictData =
        case lists:keyfind(2, 1, Attrs) of
            {2, nested, VD} -> VD;
            {2, VBin} when is_binary(VBin) -> nfnl_attr:decode(VBin);
            _ -> []
        end,
    Code =
        case lists:keyfind(1, 1, VerdictData) of
            {1, <<C:32/big>>} -> C;
            _ -> -1
        end,
    #{type => immediate, verdict => verdict_name(Code)}.

%% --- Internal: build description from decoded expressions ---

-spec build_description([map()], [iodata()]) -> [iodata()].
build_description([], Acc) ->
    lists:reverse(Acc);
%% ct state established,related (ct + bitwise + cmp pattern)
build_description(
    [
        #{type := ct, key := <<"state">>},
        #{type := bitwise},
        #{type := cmp}
        | Rest
    ],
    Acc
) ->
    build_description(Rest, [<<"ct state established,related">> | Acc]);
%% meta l4proto + cmp → protocol match
build_description(
    [
        #{type := meta, key := <<"l4proto">>},
        #{type := cmp, value := Value}
        | Rest
    ],
    Acc
) ->
    Proto =
        case Value of
            <<6>> -> <<"tcp">>;
            <<17>> -> <<"udp">>;
            <<1>> -> <<"icmp">>;
            <<58>> -> <<"icmpv6">>;
            <<N>> -> <<"proto ", (integer_to_binary(N))/binary>>;
            _ -> <<"proto ?">>
        end,
    build_description(Rest, [Proto | Acc]);
%% meta nfproto + cmp (ip family match, skip in output)
build_description(
    [
        #{type := meta, key := <<"nfproto">>},
        #{type := cmp}
        | Rest
    ],
    Acc
) ->
    build_description(Rest, Acc);
%% meta iif + cmp → interface match
build_description(
    [
        #{type := meta, key := <<"iif">>},
        #{type := cmp, value := <<1:32/native>>}
        | Rest
    ],
    Acc
) ->
    build_description(Rest, [<<"iif lo">> | Acc]);
build_description(
    [
        #{type := meta, key := <<"iif">>},
        #{type := cmp}
        | Rest
    ],
    Acc
) ->
    build_description(Rest, [<<"iif ?">> | Acc]);
%% payload + cmp → port/addr match
build_description(
    [
        #{type := payload, base := 2, offset := 2, len := 2},
        #{type := cmp, value := <<Port:16/big>>}
        | Rest
    ],
    Acc
) ->
    build_description(Rest, [<<"dport ", (integer_to_binary(Port))/binary>> | Acc]);
build_description(
    [
        #{type := payload, base := 2, offset := 0, len := 2},
        #{type := cmp, value := <<Port:16/big>>}
        | Rest
    ],
    Acc
) ->
    build_description(Rest, [<<"sport ", (integer_to_binary(Port))/binary>> | Acc]);
build_description(
    [
        #{type := payload, base := 1, offset := 12, len := 4},
        #{type := cmp, value := <<A, B, C, D>>}
        | Rest
    ],
    Acc
) ->
    IP = iolist_to_binary(io_lib:format("~B.~B.~B.~B", [A, B, C, D])),
    build_description(Rest, [<<"ip saddr ", IP/binary>> | Acc]);
%% lookup
build_description([#{type := lookup, set := Set} | Rest], Acc) ->
    build_description(Rest, [<<"@", Set/binary>> | Acc]);
%% counter
build_description([#{type := counter, packets := P, bytes := B} | Rest], Acc) ->
    Txt = iolist_to_binary(io_lib:format("counter packets ~B bytes ~B", [P, B])),
    build_description(Rest, [Txt | Acc]);
%% log
build_description([#{type := log, prefix := <<>>} | Rest], Acc) ->
    build_description(Rest, [<<"log">> | Acc]);
build_description([#{type := log, prefix := Prefix} | Rest], Acc) ->
    build_description(Rest, [<<"log \"", Prefix/binary, "\"">> | Acc]);
%% verdict
build_description([#{type := immediate, verdict := V} | Rest], Acc) ->
    build_description(Rest, [V | Acc]);
%% skip unknowns
build_description([_ | Rest], Acc) ->
    build_description(Rest, Acc).

%% --- Name lookups ---

-spec meta_key_name(non_neg_integer()) -> binary().
meta_key_name(?NFT_META_LEN) -> <<"len">>;
meta_key_name(?NFT_META_PROTOCOL) -> <<"protocol">>;
meta_key_name(?NFT_META_MARK) -> <<"mark">>;
meta_key_name(?NFT_META_IIF) -> <<"iif">>;
meta_key_name(?NFT_META_OIF) -> <<"oif">>;
meta_key_name(?NFT_META_IIFNAME) -> <<"iifname">>;
meta_key_name(?NFT_META_OIFNAME) -> <<"oifname">>;
meta_key_name(?NFT_META_NFPROTO) -> <<"nfproto">>;
meta_key_name(?NFT_META_L4PROTO) -> <<"l4proto">>;
meta_key_name(N) -> integer_to_binary(N).

-spec ct_key_name(non_neg_integer()) -> binary().
ct_key_name(?NFT_CT_STATE) -> <<"state">>;
ct_key_name(?NFT_CT_DIRECTION) -> <<"direction">>;
ct_key_name(?NFT_CT_STATUS) -> <<"status">>;
ct_key_name(?NFT_CT_MARK) -> <<"mark">>;
ct_key_name(N) -> integer_to_binary(N).

-spec cmp_op_name(non_neg_integer()) -> nonempty_binary().
cmp_op_name(?NFT_CMP_EQ) -> <<"eq">>;
cmp_op_name(?NFT_CMP_NEQ) -> <<"neq">>;
cmp_op_name(?NFT_CMP_LT) -> <<"lt">>;
cmp_op_name(?NFT_CMP_LTE) -> <<"lte">>;
cmp_op_name(?NFT_CMP_GT) -> <<"gt">>;
cmp_op_name(?NFT_CMP_GTE) -> <<"gte">>;
cmp_op_name(_) -> <<"?">>.

-spec verdict_name(non_neg_integer()) -> binary().
verdict_name(?NF_DROP) -> <<"drop">>;
verdict_name(?NF_ACCEPT) -> <<"accept">>;
verdict_name(?NFT_RETURN) -> <<"return">>;
verdict_name(?NFT_GOTO) -> <<"goto">>;
verdict_name(?NFT_JUMP) -> <<"jump">>;
verdict_name(_) -> <<"?">>.

-spec strip_null(binary()) -> binary().
strip_null(Bin) ->
    case binary:split(Bin, <<0>>) of
        [Name, _] -> Name;
        [Name] -> Name
    end.
