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

-module(nft_query).
-moduledoc """
nf_tables query operations.

Sends NFT_MSG_GET* messages to the kernel and parses the responses.
Unlike create/delete operations which return simple ACKs, get
operations return the full object data as netlink attributes.

The kernel responds with one message per object, followed by
NLMSG_DONE. For dump operations (NLM_F_DUMP), all objects of the
requested type are returned.

This module works directly with nfnl_socket for send/recv since
get responses contain data, not just ACK/error codes.
""".

-export([list_tables/2,
         list_chains/3,
         list_rules/3,
         get_ruleset/2,
         list_set_elems/4]).

%% --- Constants ---

-define(NFT_MSG_GETTABLE, 1).
-define(NFT_MSG_GETCHAIN, 4).
-define(NFT_MSG_GETRULE,  7).

-define(NFTA_TABLE_NAME,  1).

-define(NFTA_CHAIN_TABLE, 1).
-define(NFTA_CHAIN_NAME,  3).
-define(NFTA_CHAIN_POLICY, 5).
-define(NFTA_CHAIN_TYPE,  7).

-define(NFTA_RULE_TABLE,       1).
-define(NFTA_RULE_CHAIN,       2).
-define(NFTA_RULE_HANDLE,      3).
-define(NFTA_RULE_EXPRESSIONS, 4).

-define(NLM_F_REQUEST, 16#0001).
-define(NLM_F_DUMP,    16#0300).

-define(NLMSG_DONE, 3).

-define(NFNL_SUBSYS_NFTABLES, 10).

%% --- Public API ---

-doc """
List all tables for the given family.

Returns a list of table names.

Example:
    {ok, Sock} = nfnl_socket:open(),
    {ok, Tables} = nft_query:list_tables(Sock, 1),
    %% Tables = [<<"fw">>, <<"nat">>]
""".
-spec list_tables(socket:socket(), 0..255) ->
    {ok, [binary()]} | {error, term()}.
list_tables(Sock, Family) ->
    Msg = nfnl_msg:build_hdr(?NFT_MSG_GETTABLE, Family,
        ?NLM_F_REQUEST bor ?NLM_F_DUMP, seq(), <<>>),
    case send_and_collect(Sock, Msg) of
        {ok, Responses} ->
            Tables = lists:filtermap(fun(Attrs) ->
                case lists:keyfind(?NFTA_TABLE_NAME, 1, Attrs) of
                    {_, NameBin} -> {true, strip_null(NameBin)};
                    false -> false
                end
            end, Responses),
            {ok, Tables};
        {error, _} = Err ->
            Err
    end.

-doc """
List all chains in a table.

Returns a list of maps with chain properties.

Example:
    {ok, Chains} = nft_query:list_chains(Sock, 1, <<"fw">>),
    %% Chains = [#{name => <<"input">>, policy => 1, ...}]
""".
-spec list_chains(socket:socket(), 0..255, binary()) ->
    {ok, [map()]} | {error, term()}.
list_chains(Sock, Family, Table) ->
    FilterAttrs = nfnl_attr:encode_str(?NFTA_CHAIN_TABLE, Table),
    Msg = nfnl_msg:build_hdr(?NFT_MSG_GETCHAIN, Family,
        ?NLM_F_REQUEST bor ?NLM_F_DUMP, seq(), FilterAttrs),
    case send_and_collect(Sock, Msg) of
        {ok, Responses} ->
            Chains = [parse_chain_attrs(A) || A <- Responses,
                      table_matches(A, Table)],
            {ok, Chains};
        {error, _} = Err ->
            Err
    end.

-doc """
List all rules in a table with their handles and counter values.

Returns a list of maps containing rule handle, chain, and
any counter values found.

Example:
    {ok, Rules} = nft_query:list_rules(Sock, 1, <<"fw">>),
    %% Rules = [#{handle => 5, chain => <<"input">>,
    %%            counters => [{packets, 42}, {bytes, 3360}]}]
""".
-spec list_rules(socket:socket(), 0..255, binary()) ->
    {ok, [map()]} | {error, term()}.
list_rules(Sock, Family, Table) ->
    FilterAttrs = nfnl_attr:encode_str(?NFTA_RULE_TABLE, Table),
    Msg = nfnl_msg:build_hdr(?NFT_MSG_GETRULE, Family,
        ?NLM_F_REQUEST bor ?NLM_F_DUMP, seq(), FilterAttrs),
    case send_and_collect(Sock, Msg) of
        {ok, Responses} ->
            Rules = [parse_rule_attrs(A) || A <- Responses,
                     table_matches(A, Table)],
            {ok, Rules};
        {error, _} = Err ->
            Err
    end.

-doc """
Get the full ruleset for a family: tables, chains, and rules.

Convenience function that calls list_tables, list_chains, and
list_rules for each table.
""".
-spec get_ruleset(socket:socket(), 0..255) ->
    {ok, [map()]} | {error, term()}.
get_ruleset(Sock, Family) ->
    case list_tables(Sock, Family) of
        {ok, Tables} ->
            Result = lists:map(fun(TableName) ->
                {ok, Chains} = list_chains(Sock, Family, TableName),
                {ok, Rules} = list_rules(Sock, Family, TableName),
                #{table => TableName, chains => Chains, rules => Rules}
            end, Tables),
            {ok, Result};
        {error, _} = Err ->
            Err
    end.

%% --- Internal: send/recv ---

-spec send_and_collect(socket:socket(), binary()) ->
    {ok, [[nfnl_attr:nla()]]} | {error, term()}.
send_and_collect(Sock, Msg) ->
    case nfnl_socket:send(Sock, Msg) of
        ok -> collect_dump(Sock, []);
        {error, _} = Err -> Err
    end.

-spec collect_dump(socket:socket(), [[nfnl_attr:nla()]]) ->
    {ok, [[nfnl_attr:nla()]]} | {error, term()}.
collect_dump(Sock, Acc) ->
    case nfnl_socket:recv(Sock) of
        {ok, Data} ->
            case parse_dump(Data, Acc) of
                {more, NewAcc} -> collect_dump(Sock, NewAcc);
                {done, NewAcc} -> {ok, lists:reverse(NewAcc)}
            end;
        {error, timeout} ->
            {ok, lists:reverse(Acc)};
        {error, _} = Err ->
            Err
    end.

-spec parse_dump(binary(), [[nfnl_attr:nla()]]) ->
    {more | done, [[nfnl_attr:nla()]]}.
parse_dump(<<>>, Acc) ->
    {more, Acc};
parse_dump(<<Len:32/little, ?NLMSG_DONE:16/little, _/binary>>, Acc)
  when Len >= 16 ->
    {done, Acc};
parse_dump(<<Len:32/little, Type:16/little, _Flags:16/little,
             _Seq:32/little, _Pid:32/little, Rest/binary>>, Acc)
  when Len >= 20 ->
    Subsys = Type bsr 8,
    PayloadLen = Len - 16,
    <<Payload:PayloadLen/binary, Tail/binary>> = Rest,
    case Subsys of
        ?NFNL_SUBSYS_NFTABLES ->
            <<_NfGenMsg:4/binary, AttrBin/binary>> = Payload,
            Attrs = nfnl_attr:decode(AttrBin),
            parse_dump(Tail, [Attrs | Acc]);
        _ ->
            parse_dump(Tail, Acc)
    end;
parse_dump(<<Len:32/little, _/binary>> = Bin, Acc) when Len >= 16 ->
    <<_:Len/binary, Tail/binary>> = Bin,
    parse_dump(Tail, Acc);
parse_dump(_, Acc) ->
    {more, Acc}.

%% --- Internal: attribute parsing ---

-spec table_matches([nfnl_attr:nla()], binary()) -> boolean().
table_matches(Attrs, Table) ->
    case lists:keyfind(1, 1, Attrs) of
        {1, Bin} when is_binary(Bin) -> strip_null(Bin) =:= Table;
        _ -> false
    end.

-spec parse_chain_attrs([nfnl_attr:nla()]) -> map().
parse_chain_attrs(Attrs) ->
    M = #{},
    M1 = case lists:keyfind(?NFTA_CHAIN_NAME, 1, Attrs) of
        {_, N} when is_binary(N) -> M#{name => strip_null(N)};
        _ -> M
    end,
    M2 = case lists:keyfind(?NFTA_CHAIN_POLICY, 1, Attrs) of
        {_, <<P:32/big>>} -> M1#{policy => P};
        _ -> M1
    end,
    M3 = case lists:keyfind(?NFTA_CHAIN_TYPE, 1, Attrs) of
        {_, T} when is_binary(T) -> M2#{type => strip_null(T)};
        _ -> M2
    end,
    M3.

-spec parse_rule_attrs([nfnl_attr:nla()]) -> map().
parse_rule_attrs(Attrs) ->
    M = #{},
    M1 = case lists:keyfind(?NFTA_RULE_CHAIN, 1, Attrs) of
        {_, C} when is_binary(C) -> M#{chain => strip_null(C)};
        _ -> M
    end,
    M2 = case lists:keyfind(?NFTA_RULE_HANDLE, 1, Attrs) of
        {_, <<H:64/big>>} -> M1#{handle => H};
        _ -> M1
    end,
    %% NFTA_RULE_EXPRESSIONS may come without NLA_F_NESTED from kernel
    ExprList = case lists:keyfind(?NFTA_RULE_EXPRESSIONS, 1, Attrs) of
        {?NFTA_RULE_EXPRESSIONS, nested, EL} -> EL;
        {?NFTA_RULE_EXPRESSIONS, ExprBin} when is_binary(ExprBin) ->
            nfnl_attr:decode(ExprBin);
        _ -> []
    end,
    M3 = add_counters(M2, ExprList),
    M4 = case ExprList of
        [] -> M3;
        _ -> M3#{description => nft_decode:rule_description(ExprList)}
    end,
    M4.



-spec add_counters(map(), [nfnl_attr:nla()]) -> map().
add_counters(M, ExprList) ->
    Counters = extract_counters(ExprList),
    case Counters of
        [] -> M;
        _ -> M#{counters => Counters}
    end.

-spec extract_counters([nfnl_attr:nla()]) -> [{atom(), non_neg_integer()}].
extract_counters(ExprList) ->
    lists:foldl(fun(Elem, Acc) ->
        ExprAttrs = case Elem of
            {_, nested, A} -> A;
            {_, Bin} when is_binary(Bin) -> nfnl_attr:decode(Bin);
            _ -> []
        end,
        case lists:keyfind(1, 1, ExprAttrs) of
            {1, <<"counter", 0>>} ->
                CtrData = case lists:keyfind(2, 1, ExprAttrs) of
                    {2, nested, D} -> D;
                    {2, D} when is_binary(D) -> nfnl_attr:decode(D);
                    _ -> []
                end,
                Bytes = case lists:keyfind(1, 1, CtrData) of
                    {1, <<B:64/big>>} -> B;
                    _ -> 0
                end,
                Pkts = case lists:keyfind(2, 1, CtrData) of
                    {2, <<P:64/big>>} -> P;
                    _ -> 0
                end,
                [{packets, Pkts}, {bytes, Bytes} | Acc];
            _ -> Acc
        end
    end, [], ExprList).

-spec strip_null(binary()) -> binary().
strip_null(Bin) ->
    case binary:split(Bin, <<0>>) of
        [Name, _] -> Name;
        [Name] -> Name
    end.

-spec seq() -> non_neg_integer().
seq() ->
    erlang:system_time(second) band 16#FFFFFFFF.

%% --- Set Element Query ---

-define(NFT_MSG_GETSETELEM, 13).
-define(NFTA_SET_ELEM_LIST_TABLE, 1).
-define(NFTA_SET_ELEM_LIST_SET, 2).
-define(NFTA_SET_ELEM_LIST_ELEMENTS, 3).
-define(NFTA_SET_ELEM_KEY, 1).
-define(NFTA_DATA_VALUE, 1).

-doc """
List all elements in a named set.

Returns IPs as formatted strings for ipv4_addr sets.

Example:
    {ok, Sock} = nfnl_socket:open(),
    {ok, IPs} = nft_query:list_set_elems(Sock, 1, <<"fw">>, <<"blocklist">>),
    %% IPs = [<<"10.0.0.5">>, <<"192.168.1.100">>]
""".
-spec list_set_elems(socket:socket(), 0..255, binary(), binary()) ->
    {ok, [binary()]} | {error, term()}.
list_set_elems(Sock, Family, Table, SetName) ->
    FilterAttrs = iolist_to_binary([
        nfnl_attr:encode_str(?NFTA_SET_ELEM_LIST_TABLE, Table),
        nfnl_attr:encode_str(?NFTA_SET_ELEM_LIST_SET, SetName)
    ]),
    Msg = nfnl_msg:build_hdr(?NFT_MSG_GETSETELEM, Family,
        ?NLM_F_REQUEST bor ?NLM_F_DUMP, seq(), FilterAttrs),
    case send_and_collect(Sock, Msg) of
        {ok, Responses} ->
            Elems = lists:flatmap(fun extract_set_elems/1, Responses),
            {ok, Elems};
        {error, _} = Err ->
            Err
    end.

-spec extract_set_elems([tuple()]) -> [binary()].
extract_set_elems(Attrs) ->
    case lists:keyfind(?NFTA_SET_ELEM_LIST_ELEMENTS, 1, Attrs) of
        {_, nested, ElemList} ->
            lists:filtermap(fun extract_one_elem/1, ElemList);
        {_, ElemBin} when is_binary(ElemBin) ->
            lists:filtermap(fun extract_one_elem/1, nfnl_attr:decode(ElemBin));
        _ ->
            []
    end.

-spec extract_one_elem(tuple()) -> {true, binary()} | false.
extract_one_elem({_, nested, ElemAttrs}) ->
    extract_key(ElemAttrs);
extract_one_elem({_, Bin}) when is_binary(Bin) ->
    extract_key(nfnl_attr:decode(Bin));
extract_one_elem(_) ->
    false.

-spec extract_key([tuple()]) -> {true, binary()} | false.
extract_key(ElemAttrs) ->
    case lists:keyfind(?NFTA_SET_ELEM_KEY, 1, ElemAttrs) of
        {_, nested, KeyAttrs} ->
            case lists:keyfind(?NFTA_DATA_VALUE, 1, KeyAttrs) of
                {_, Val} -> {true, format_set_val(Val)};
                _ -> false
            end;
        {_, KeyBin} when is_binary(KeyBin) ->
            Inner = nfnl_attr:decode(KeyBin),
            case lists:keyfind(?NFTA_DATA_VALUE, 1, Inner) of
                {_, Val} -> {true, format_set_val(Val)};
                _ -> false
            end;
        _ -> false
    end.

-spec format_set_val(binary()) -> binary().
format_set_val(<<A, B, C, D>>) ->
    iolist_to_binary(erlk_ip:format(<<A, B, C, D>>));
format_set_val(<<_:16/binary>> = V6) ->
    iolist_to_binary(erlk_ip:format(V6));
format_set_val(Val) ->
    Val.
