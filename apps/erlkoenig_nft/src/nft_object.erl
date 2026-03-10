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

-module(nft_object).
-moduledoc """
nf_tables stateful object operations.

Creates, queries, and deletes named stateful objects. Currently
supports counter objects. Named counters are independent of rules
and can be referenced by multiple rules simultaneously.

A named counter persists across rule reloads and can be queried
or reset atomically — perfect for rate monitoring.

Usage:
    %% Create a named counter
    nft_object:add_counter(1, <<"fw">>, <<"ssh_pkts">>, Seq)

    %% Read counter values (non-destructive)
    nft_object:get_counter(Sock, 1, <<"fw">>, <<"ssh_pkts">>)

    %% Read AND atomically reset to zero (ideal for rate calculation)
    nft_object:get_counter_reset(Sock, 1, <<"fw">>, <<"ssh_pkts">>)
""".

-export([add_counter/4,
         delete/4,
         get_counter/4,
         get_counter_reset/4,
         get_all_counters/3]).

%% --- Constants ---

-define(NFT_MSG_NEWOBJ,       18).
-define(NFT_MSG_GETOBJ,       19).
-define(NFT_MSG_DELOBJ,       20).
-define(NFT_MSG_GETOBJ_RESET, 21).

-define(NFT_OBJECT_COUNTER, 1).

-define(NFTA_OBJ_TABLE,  1).
-define(NFTA_OBJ_NAME,   2).
-define(NFTA_OBJ_TYPE,   3).
-define(NFTA_OBJ_DATA,   4).

-define(NFTA_COUNTER_BYTES,   1).
-define(NFTA_COUNTER_PACKETS, 2).

-define(NLM_F_REQUEST, 16#0001).
-define(NLM_F_ACK,     16#0004).
-define(NLM_F_CREATE,  16#0400).
-define(NLM_F_DUMP,    16#0300).

-define(NLMSG_DONE, 3).
-define(NFNL_SUBSYS_NFTABLES, 10).

%% --- Public API: Create/Delete ---

-doc """
Create a named counter object with zero initial values.

Example:
    Msg = nft_object:add_counter(1, <<"fw">>, <<"ssh_pkts">>, Seq)
""".
-spec add_counter(0..255, binary(), binary(), non_neg_integer()) ->
    nfnl_msg:nl_msg().
add_counter(Family, Table, Name, Seq) ->
    CounterData = iolist_to_binary([
        nfnl_attr:encode_u64(?NFTA_COUNTER_BYTES, 0),
        nfnl_attr:encode_u64(?NFTA_COUNTER_PACKETS, 0)
    ]),
    Attrs = iolist_to_binary([
        nfnl_attr:encode_str(?NFTA_OBJ_TABLE, Table),
        nfnl_attr:encode_str(?NFTA_OBJ_NAME, Name),
        nfnl_attr:encode_u32(?NFTA_OBJ_TYPE, ?NFT_OBJECT_COUNTER),
        nfnl_attr:encode_nested(?NFTA_OBJ_DATA, CounterData)
    ]),
    Flags = ?NLM_F_REQUEST bor ?NLM_F_ACK bor ?NLM_F_CREATE,
    nfnl_msg:build_hdr(?NFT_MSG_NEWOBJ, Family, Flags, Seq, Attrs).

-doc "Delete a named object.".
-spec delete(0..255, binary(), binary(), non_neg_integer()) ->
    nfnl_msg:nl_msg().
delete(Family, Table, Name, Seq) ->
    Attrs = iolist_to_binary([
        nfnl_attr:encode_str(?NFTA_OBJ_TABLE, Table),
        nfnl_attr:encode_str(?NFTA_OBJ_NAME, Name),
        nfnl_attr:encode_u32(?NFTA_OBJ_TYPE, ?NFT_OBJECT_COUNTER)
    ]),
    Flags = ?NLM_F_REQUEST bor ?NLM_F_ACK,
    nfnl_msg:build_hdr(?NFT_MSG_DELOBJ, Family, Flags, Seq, Attrs).

%% --- Public API: Query ---

-doc """
Read a named counter's current values without resetting.

Returns {ok, #{packets => N, bytes => N}} or {error, Reason}.
""".
-spec get_counter(socket:socket(), 0..255, binary(), binary()) ->
    {ok, map()} | {error, term()}.
get_counter(Sock, Family, Table, Name) ->
    query_counter(Sock, ?NFT_MSG_GETOBJ, Family, Table, Name).

-doc """
Read a named counter and atomically reset it to zero.

This is the ideal primitive for rate calculation: you get the
exact count since the last reset, with no race conditions.
""".
-spec get_counter_reset(socket:socket(), 0..255, binary(), binary()) ->
    {ok, map()} | {error, term()}.
get_counter_reset(Sock, Family, Table, Name) ->
    query_counter(Sock, ?NFT_MSG_GETOBJ_RESET, Family, Table, Name).

-doc """
Get all named counters in a table.

Returns {ok, [#{name => Name, packets => N, bytes => N}]}.
""".
-spec get_all_counters(socket:socket(), 0..255, binary()) ->
    {ok, [map()]} | {error, term()}.
get_all_counters(Sock, Family, Table) ->
    FilterAttrs = iolist_to_binary([
        nfnl_attr:encode_str(?NFTA_OBJ_TABLE, Table),
        nfnl_attr:encode_u32(?NFTA_OBJ_TYPE, ?NFT_OBJECT_COUNTER)
    ]),
    Msg = nfnl_msg:build_hdr(?NFT_MSG_GETOBJ, Family,
        ?NLM_F_REQUEST bor ?NLM_F_DUMP, seq(), FilterAttrs),
    case send_and_collect(Sock, Msg) of
        {ok, Responses} ->
            Counters = lists:filtermap(fun(Attrs) ->
                case parse_counter_response(Attrs) of
                    #{name := _} = C -> {true, C};
                    _ -> false
                end
            end, [A || A <- Responses, table_matches(A, Table)]),
            {ok, Counters};
        {error, _} = Err ->
            Err
    end.

%% --- Internal ---
-spec query_counter(socket:socket(), 0..255, 0..255, binary(), binary()) ->
    {ok, map()} | {error, term()}.
query_counter(Sock, MsgType, Family, Table, Name) ->
    Attrs = iolist_to_binary([
        nfnl_attr:encode_str(?NFTA_OBJ_TABLE, Table),
        nfnl_attr:encode_str(?NFTA_OBJ_NAME, Name),
        nfnl_attr:encode_u32(?NFTA_OBJ_TYPE, ?NFT_OBJECT_COUNTER)
    ]),
    Msg = nfnl_msg:build_hdr(MsgType, Family,
        ?NLM_F_REQUEST bor ?NLM_F_ACK, seq(), Attrs),
    case nfnl_socket:send(Sock, Msg) of
        ok ->
            %% First response: the object data
            case nfnl_socket:recv(Sock) of
                {ok, Data} ->
                    Result = parse_obj_response(Data),
                    %% Second response: the ACK — drain it
                    _ = nfnl_socket:recv(Sock),
                    Result;
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.


-spec parse_obj_response(binary()) -> {ok, map()} | {error, term()}.
parse_obj_response(<<Len:32/little, Type:16/little, _Flags:16/little,
                     _Seq:32/little, _Pid:32/little, Rest/binary>>)
  when Len >= 20 ->
    Subsys = Type bsr 8,
    case Subsys of
        ?NFNL_SUBSYS_NFTABLES ->
            PayloadLen = Len - 16,
            <<Payload:PayloadLen/binary, _/binary>> = Rest,
            <<_NfGenMsg:4/binary, AttrBin/binary>> = Payload,
            Attrs = nfnl_attr:decode(AttrBin),
            {ok, parse_counter_response(Attrs)};
        _ ->
            {error, unexpected_subsystem}
    end;
parse_obj_response(_) ->
    {error, invalid_response}.

-spec parse_counter_response([tuple()]) -> map().
parse_counter_response(Attrs) ->
    M = #{},
    M1 = case lists:keyfind(?NFTA_OBJ_NAME, 1, Attrs) of
        {_, N} when is_binary(N) -> M#{name => strip_null(N)};
        _ -> M
    end,
    M2 = case lists:keyfind(?NFTA_OBJ_DATA, 1, Attrs) of
        {_, nested, Data} -> parse_counter_data(M1, Data);
        {_, Bin} when is_binary(Bin) -> parse_counter_data(M1, nfnl_attr:decode(Bin));
        _ -> M1
    end,
    M2.

-spec parse_counter_data(map(), [tuple()]) -> map().
parse_counter_data(M, Data) ->
    M1 = case lists:keyfind(?NFTA_COUNTER_BYTES, 1, Data) of
        {_, <<B:64/big>>} -> M#{bytes => B};
        _ -> M#{bytes => 0}
    end,
    case lists:keyfind(?NFTA_COUNTER_PACKETS, 1, Data) of
        {_, <<P:64/big>>} -> M1#{packets => P};
        _ -> M1#{packets => 0}
    end.

-spec table_matches([tuple()], binary()) -> boolean().
table_matches(Attrs, Table) ->
    case lists:keyfind(1, 1, Attrs) of
        {1, Bin} when is_binary(Bin) -> strip_null(Bin) =:= Table;
        _ -> false
    end.

-spec send_and_collect(socket:socket(), binary()) ->
    {ok, [[tuple()]]} | {error, term()}.
send_and_collect(Sock, Msg) ->
    case nfnl_socket:send(Sock, Msg) of
        ok -> collect_dump(Sock, []);
        {error, _} = Err -> Err
    end.

-spec collect_dump(socket:socket(), [[tuple()]]) ->
    {ok, [[tuple()]]} | {error, term()}.
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

-spec parse_dump(binary(), [[tuple()]]) -> {more | done, [[tuple()]]}.
parse_dump(<<>>, Acc) ->
    {more, Acc};
parse_dump(<<Len:32/little, ?NLMSG_DONE:16/little, _/binary>>, Acc)
  when Len >= 16 ->
    {done, Acc};
parse_dump(<<Len:32/little, Type:16/little, _:16/little,
             _:32/little, _:32/little, Rest/binary>>, Acc)
  when Len >= 20 ->
    Subsys = Type bsr 8,
    PayloadLen = Len - 16,
    <<Payload:PayloadLen/binary, Tail/binary>> = Rest,
    case Subsys of
        ?NFNL_SUBSYS_NFTABLES ->
            <<_:4/binary, AttrBin/binary>> = Payload,
            parse_dump(Tail, [nfnl_attr:decode(AttrBin) | Acc]);
        _ ->
            parse_dump(Tail, Acc)
    end;
parse_dump(<<Len:32/little, _/binary>> = Bin, Acc) when Len >= 16 ->
    <<_:Len/binary, Tail/binary>> = Bin,
    parse_dump(Tail, Acc);
parse_dump(_, Acc) ->
    {more, Acc}.

-spec strip_null(binary()) -> binary().
strip_null(Bin) ->
    case binary:split(Bin, <<0>>) of
        [Name, _] -> Name;
        [Name] -> Name
    end.

-spec seq() -> non_neg_integer().
seq() ->
    erlang:system_time(second) band 16#FFFFFFFF.
