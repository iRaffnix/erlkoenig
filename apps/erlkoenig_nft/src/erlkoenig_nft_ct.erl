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

-module(erlkoenig_nft_ct).
-moduledoc """
Conntrack event receiver - tracks network connections in real time.

Opens a dedicated AF_NETLINK socket subscribed to conntrack multicast
groups (NEW, DESTROY). Maintains an ETS table of active connections
with automatic fallback to per-source-IP aggregation when the table
exceeds a configurable limit.

Two modes:

  1. Full tracking (default): Each connection is an ETS entry keyed by
     {Proto, SrcIP, SrcPort, DstIP, DstPort}. Provides complete
     connection visibility.

  2. Aggregation mode: When full tracking exceeds max_entries, switches
     to per-source-IP counters. Uses ~100x less memory under DDoS.

Events are broadcast via pg group `ct_events`:
    {ct_new, #{proto => tcp, src => <<...>>, ...}}
    {ct_destroy, #{proto => tcp, src => <<...>>, ...}}
    {ct_alert, {mode_switch, aggregate}}

Public API:
    erlkoenig_nft_ct:count()                  - total active connections
    erlkoenig_nft_ct:count_by_src(IP)         - connections from a source IP
    erlkoenig_nft_ct:top_sources(N)           - top N source IPs by connection count
    erlkoenig_nft_ct:connections()            - list all tracked connections (full mode)
    erlkoenig_nft_ct:mode()                   - current mode: full | aggregate
    erlkoenig_nft_ct:stats()                  - operational statistics
    erlkoenig_nft_ct:kill_by_src(IP)          - request kernel to kill connections from IP
""".

-behaviour(gen_server).

-export([start_link/0, start_link/1, stop/1]).
-export([count/0, count_by_src/1, top_sources/1,
         connections/0, mode/0, stats/0, kill_by_src/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).
-export_type([ct_key/0, ct_event/0]).

%% --- Constants: Netlink ---

-define(AF_NETLINK, 16).
-define(NETLINK_NETFILTER, 12).

-define(NLM_F_REQUEST, 16#0001).
-define(NLM_F_ACK,     16#0004).

%% Conntrack multicast groups (for nl_mgrp bitmask)
-define(NFNLGRP_CONNTRACK_NEW,     1).
-define(NFNLGRP_CONNTRACK_UPDATE,  2).
-define(NFNLGRP_CONNTRACK_DESTROY, 3).

%% Subsystem + message types
-define(NFNL_SUBSYS_CTNETLINK, 1).
-define(IPCTNL_MSG_CT_NEW,     0).
-define(IPCTNL_MSG_CT_GET,     1).
-define(IPCTNL_MSG_CT_DELETE,  2).

%% Top-level conntrack attributes
-define(CTA_TUPLE_ORIG,    1).
-define(CTA_TUPLE_REPLY,   2).
-define(CTA_STATUS,        3).
-define(CTA_PROTOINFO,     4).
-define(CTA_TIMEOUT,       7).
-define(CTA_MARK,          8).
-define(CTA_ID,           12).
-define(CTA_ZONE,         18).
-define(CTA_TIMESTAMP,    20).

%% Tuple attributes
-define(CTA_TUPLE_IP,      1).
-define(CTA_TUPLE_PROTO,   2).

%% IP attributes
-define(CTA_IP_V4_SRC, 1).
-define(CTA_IP_V4_DST, 2).
-define(CTA_IP_V6_SRC, 3).
-define(CTA_IP_V6_DST, 4).

%% Proto attributes
-define(CTA_PROTO_NUM,      1).
-define(CTA_PROTO_SRC_PORT, 2).
-define(CTA_PROTO_DST_PORT, 3).
-define(CTA_PROTO_ICMP_ID,  4).
-define(CTA_PROTO_ICMP_TYPE, 5).
-define(CTA_PROTO_ICMP_CODE, 6).

%% Protocol numbers
-define(IPPROTO_TCP,  6).
-define(IPPROTO_UDP,  17).
-define(IPPROTO_ICMP, 1).

%% Default config
-define(DEFAULT_MAX_ENTRIES, 100000).

%% ETS table names
-define(CT_TAB, erlkoenig_nft_ct_conns).
-define(CT_AGG, erlkoenig_nft_ct_agg).

%% --- Types ---

-type ct_key() :: {Proto :: non_neg_integer(),
                   SrcIP :: binary(),
                   SrcPort :: non_neg_integer(),
                   DstIP :: binary(),
                   DstPort :: non_neg_integer()}.

-type ct_event() :: #{
    proto     => non_neg_integer(),
    proto_name => binary(),
    src       => binary(),
    dst       => binary(),
    sport     => non_neg_integer(),
    dport     => non_neg_integer()
}.

%% --- Public API ---

-doc "Start with default options.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    start_link(#{}).

-doc "Start with options: max_entries (default 100000).".
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Opts) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Opts, []).

-doc "Stop the conntrack receiver.".
-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_server:stop(Pid).

-doc "Total number of tracked connections.".
-spec count() -> non_neg_integer().
count() ->
    ets:info(?CT_TAB, size).

-doc "Number of connections from a specific source IP binary.".
-spec count_by_src(binary()) -> non_neg_integer().
count_by_src(SrcIP) when is_binary(SrcIP) ->
    case ets:info(?CT_AGG, size) of
        undefined -> 0;
        _ ->
            case ets:lookup(?CT_AGG, SrcIP) of
                [{_, Count, _, _}] -> Count;
                [] -> 0
            end
    end.

-doc "Top N source IPs by active connection count.".
-spec top_sources(pos_integer()) -> [{binary(), non_neg_integer()}].
top_sources(N) when is_integer(N), N > 0 ->
    All = ets:tab2list(?CT_AGG),
    Sorted = lists:sort(fun({_, C1, _, _}, {_, C2, _, _}) -> C1 > C2 end, All),
    [{IP, Count} || {IP, Count, _, _} <- lists:sublist(Sorted, N)].

-doc "List all tracked connections (only in full mode).".
-spec connections() -> [map()].
connections() ->
    ets:foldl(fun
        ({Key, State, Ts, Timeout}, Acc) when is_tuple(Key) ->
            {Proto, Src, SPort, Dst, DPort} = Key,
            [#{proto => Proto, src => Src, sport => SPort,
               dst => Dst, dport => DPort,
               state => State, timestamp => Ts,
               timeout => Timeout} | Acc];
        (_, Acc) -> Acc
    end, [], ?CT_TAB).

-doc "Current tracking mode: full or aggregate.".
-spec mode() -> full | aggregate.
mode() ->
    gen_server:call(?MODULE, mode).

-doc "Operational statistics.".
-spec stats() -> map().
stats() ->
    gen_server:call(?MODULE, stats).

-doc "Request kernel to kill all connections from a source IP (4 or 16 byte binary).".
-spec kill_by_src(binary()) -> ok | {error, term()}.
kill_by_src(SrcIP) when is_binary(SrcIP),
                         (byte_size(SrcIP) =:= 4 orelse byte_size(SrcIP) =:= 16) ->
    gen_server:call(?MODULE, {kill_by_src, SrcIP}).

%% --- gen_server callbacks ---

init(Opts) ->
    MaxEntries = maps:get(max_entries, Opts, ?DEFAULT_MAX_ENTRIES),

    %% Create ETS tables
    %% Full tracking: {Key, State, Timestamp, Timeout}
    ets:new(?CT_TAB, [named_table, set, public, {read_concurrency, true}]),
    %% Aggregation: {SrcIP, Count, FirstSeen, LastSeen}
    ets:new(?CT_AGG, [named_table, set, public, {read_concurrency, true}]),

    case open_ct_socket() of
        {ok, Sock} ->
            request_recv(Sock),
            {ok, #{
                socket      => Sock,
                mode        => full,
                max_entries => MaxEntries,
                ct_new      => 0,
                ct_destroy  => 0,
                ct_dropped  => 0,
                mode_switches => 0
            }};
        {error, Reason} ->
            {stop, {ct_socket_failed, Reason}}
    end.

handle_call(mode, _From, #{mode := Mode} = State) ->
    {reply, Mode, State};

handle_call(stats, _From, State) ->
    #{ct_new := New, ct_destroy := Destroy, ct_dropped := Dropped,
      mode := Mode, mode_switches := Switches, max_entries := Max} = State,
    Stats = #{
        mode => Mode,
        connections => ets:info(?CT_TAB, size),
        sources => ets:info(?CT_AGG, size),
        events_new => New,
        events_destroy => Destroy,
        events_dropped => Dropped,
        mode_switches => Switches,
        max_entries => Max
    },
    {reply, Stats, State};

handle_call({kill_by_src, SrcIP}, _From, #{socket := Sock} = State) ->
    %% Find matching connections and send delete for each
    Result = kill_connections(Sock, SrcIP),
    {reply, Result, State};

handle_call(_Req, _From, State) ->
    {reply, {error, unknown}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'$socket', Sock, select, _Ref}, #{socket := Sock} = State) ->
    State2 = recv_loop(Sock, State),
    request_recv(Sock),
    {noreply, State2};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #{socket := Sock}) ->
    _ = socket:close(Sock),
    _ = ets:delete(?CT_TAB),
    _ = ets:delete(?CT_AGG),
    ok.

%% --- Internal: Socket ---

open_ct_socket() ->
    case socket:open(?AF_NETLINK, raw, ?NETLINK_NETFILTER) of
        {ok, Sock} ->
            %% Build multicast group bitmask:
            %% bit N subscribes to group N+1
            Groups = (1 bsl (?NFNLGRP_CONNTRACK_NEW - 1)) bor
                     (1 bsl (?NFNLGRP_CONNTRACK_DESTROY - 1)),
            SaData = <<0:16, 0:32/native, Groups:32/native, 0:32/native>>,
            Addr = #{family => ?AF_NETLINK, addr => SaData},
            case socket:bind(Sock, Addr) of
                ok    -> {ok, Sock};
                Err   -> _ = socket:close(Sock), Err
            end;
        Err -> Err
    end.

request_recv(Sock) ->
    case socket:recv(Sock, 0, nowait) of
        {ok, Data} ->
            self() ! {ct_data, Data},
            request_recv(Sock);
        {select, _SelectInfo} ->
            ok;
        {error, _} ->
            ok
    end.

recv_loop(Sock, State) ->
    case socket:recv(Sock, 0, nowait) of
        {ok, Data} ->
            State2 = process_messages(Data, State),
            recv_loop(Sock, State2);
        {select, _} ->
            State;
        {error, _} ->
            State
    end.

%% --- Internal: Message Processing ---

process_messages(<<>>, State) -> State;
process_messages(<<Len:32/little, Type:16/little, _Flags:16/little,
                   _Seq:32/little, _Pid:32/little, Rest/binary>>, State)
  when Len >= 20 ->
    Subsys = Type bsr 8,
    MsgType = Type band 16#FF,
    PayloadLen = Len - 16,
    case byte_size(Rest) >= PayloadLen of
        true ->
            <<Payload:PayloadLen/binary, Tail/binary>> = Rest,
            State2 = case Subsys of
                ?NFNL_SUBSYS_CTNETLINK ->
                    handle_ct_msg(MsgType, Payload, State);
                _ ->
                    State
            end,
            process_messages(Tail, State2);
        false ->
            State
    end;
process_messages(_, State) -> State.

handle_ct_msg(MsgType, Payload, State) when byte_size(Payload) >= 4 ->
    <<_NfGenMsg:4/binary, AttrBin/binary>> = Payload,
    Attrs = nfnl_attr:decode(AttrBin),
    Event = parse_ct_event(Attrs),
    case MsgType of
        ?IPCTNL_MSG_CT_NEW ->
            handle_new(Event, State);
        ?IPCTNL_MSG_CT_DELETE ->
            handle_destroy(Event, State);
        _ ->
            State
    end;
handle_ct_msg(_, _, State) -> State.

%% --- Internal: Event Handling ---

handle_new(#{src := _} = Event, #{mode := Mode, max_entries := Max,
                    ct_new := N} = State) ->
    broadcast({ct_new, Event}),
    State2 = State#{ct_new := N + 1},

    %% Always update aggregation table
    update_agg(Event, 1),

    case Mode of
        full ->
            Size = ets:info(?CT_TAB, size),
            case Size >= Max of
                true ->
                    %% Switch to aggregate mode
                    ets:delete_all_objects(?CT_TAB),
                    broadcast({ct_alert, {mode_switch, aggregate}}),
                    Switches = maps:get(mode_switches, State2, 0),
                    State2#{mode := aggregate, mode_switches := Switches + 1};
                false ->
                    Key = event_key(Event),
                    Timeout = maps:get(timeout, Event, 0),
                    ets:insert(?CT_TAB, {Key, established,
                                         erlang:system_time(second), Timeout}),
                    State2
            end;
        aggregate ->
            State2#{ct_dropped := maps:get(ct_dropped, State2, 0) + 1}
    end;
handle_new(_EventNoSrc, State) ->
    %% Skip events we couldn't fully parse
    State.

handle_destroy(#{src := _} = Event, #{ct_destroy := N, mode := Mode} = State) ->
    broadcast({ct_destroy, Event}),
    State2 = State#{ct_destroy := N + 1},

    %% Update aggregation table
    update_agg(Event, -1),

    case Mode of
        full ->
            Key = event_key(Event),
            ets:delete(?CT_TAB, Key),
            State2;
        aggregate ->
            State2
    end;
handle_destroy(_EventNoSrc, State) ->
    State.

event_key(#{proto := Proto, src := Src, sport := SPort,
            dst := Dst, dport := DPort}) ->
    {Proto, Src, SPort, Dst, DPort};
event_key(#{proto := Proto, src := Src, dst := Dst}) ->
    {Proto, Src, 0, Dst, 0};
event_key(_Incomplete) ->
    undefined.

update_agg(#{src := SrcIP}, Delta) ->
    Now = erlang:system_time(second),
    case ets:lookup(?CT_AGG, SrcIP) of
        [{_, Count, First, _Last}] ->
            NewCount = max(0, Count + Delta),
            case NewCount of
                0 -> ets:delete(?CT_AGG, SrcIP);
                _ -> ets:insert(?CT_AGG, {SrcIP, NewCount, First, Now})
            end;
        [] when Delta > 0 ->
            ets:insert(?CT_AGG, {SrcIP, 1, Now, Now});
        [] ->
            ok
    end.

%% --- Internal: Kill Connections ---

kill_connections(Sock, SrcIP) ->
    %% Find all connections from this source
    Conns = ets:match_object(?CT_TAB, {{'_', SrcIP, '_', '_', '_'}, '_', '_', '_'}),
    lists:foreach(fun({Key, _, _, _}) ->
        send_ct_delete(Sock, Key)
    end, Conns),
    %% Also clean ETS
    lists:foreach(fun({Key, _, _, _}) ->
        ets:delete(?CT_TAB, Key)
    end, Conns),
    ok.

send_ct_delete(Sock, {Proto, SrcIP, SrcPort, DstIP, DstPort}) ->
    %% Build CTA_TUPLE_ORIG with nested IP + Proto
    {SrcAttrType, DstAttrType, AF} = case byte_size(SrcIP) of
        4  -> {?CTA_IP_V4_SRC, ?CTA_IP_V4_DST, 2};   %% AF_INET
        16 -> {?CTA_IP_V6_SRC, ?CTA_IP_V6_DST, 10}   %% AF_INET6
    end,
    IpAttrs = iolist_to_binary([
        nfnl_attr:encode(SrcAttrType, SrcIP),
        nfnl_attr:encode(DstAttrType, DstIP)
    ]),
    ProtoAttrs = iolist_to_binary([
        nfnl_attr:encode(?CTA_PROTO_NUM, <<Proto:8>>),
        case Proto of
            P when P =:= ?IPPROTO_TCP; P =:= ?IPPROTO_UDP ->
                iolist_to_binary([
                    nfnl_attr:encode(?CTA_PROTO_SRC_PORT, <<SrcPort:16/big>>),
                    nfnl_attr:encode(?CTA_PROTO_DST_PORT, <<DstPort:16/big>>)
                ]);
            _ -> <<>>
        end
    ]),
    TupleAttrs = iolist_to_binary([
        nfnl_attr:encode_nested(?CTA_TUPLE_IP, IpAttrs),
        nfnl_attr:encode_nested(?CTA_TUPLE_PROTO, ProtoAttrs)
    ]),
    TupleOrig = nfnl_attr:encode_nested(?CTA_TUPLE_ORIG, TupleAttrs),

    %% Frame as IPCTNL_MSG_CT_DELETE
    NfGenMsg = <<AF:8, 0:8, 0:16>>,  %% AF_INET or AF_INET6, version 0, res_id 0
    Payload = <<NfGenMsg/binary, TupleOrig/binary>>,
    MsgType = (?NFNL_SUBSYS_CTNETLINK bsl 8) bor ?IPCTNL_MSG_CT_DELETE,
    Flags = ?NLM_F_REQUEST bor ?NLM_F_ACK,
    Seq = erlang:unique_integer([positive]) band 16#FFFFFFFF,
    Len = 16 + byte_size(Payload),
    Msg = <<Len:32/little, MsgType:16/little, Flags:16/little,
            Seq:32/little, 0:32/little, Payload/binary>>,
    case socket:send(Sock, Msg) of
        ok ->
            %% Drain ACK
            _ = socket:recv(Sock, 0, 500),
            ok;
        Err -> Err
    end.

%% --- Internal: CT Event Parsing ---

%% Find a nested attribute by type. Handles both formats:
%% - {Type, nested, Children}  (NLA_F_NESTED flag was set)
%% - {Type, BinaryBlob}        (no nested flag, parse manually)
find_nested(Type, Attrs) ->
    case lists:keyfind(Type, 1, Attrs) of
        {_, nested, Children} ->
            {ok, Children};
        {_, Bin} when is_binary(Bin), byte_size(Bin) >= 4 ->
            %% Kernel sent without NLA_F_NESTED, decode the blob
            {ok, nfnl_attr:decode(Bin)};
        _ ->
            error
    end.

parse_ct_event(Attrs) ->
    M = #{},
    M1 = case find_nested(?CTA_TUPLE_ORIG, Attrs) of
        {ok, TupleAttrs} -> parse_tuple(M, TupleAttrs);
        error -> M
    end,
    M2 = case lists:keyfind(?CTA_TIMEOUT, 1, Attrs) of
        {_, <<Timeout:32/big>>} -> M1#{timeout => Timeout};
        _ -> M1
    end,
    M3 = case lists:keyfind(?CTA_STATUS, 1, Attrs) of
        {_, <<Status:32/big>>} -> M2#{status => Status};
        _ -> M2
    end,
    M4 = case lists:keyfind(?CTA_MARK, 1, Attrs) of
        {_, <<Mark:32/big>>} -> M3#{mark => Mark};
        _ -> M3
    end,
    M4.

parse_tuple(M, TupleAttrs) ->
    M1 = case find_nested(?CTA_TUPLE_IP, TupleAttrs) of
        {ok, IpAttrs} -> parse_ip(M, IpAttrs);
        error -> M
    end,
    case find_nested(?CTA_TUPLE_PROTO, TupleAttrs) of
        {ok, ProtoAttrs} -> parse_proto(M1, ProtoAttrs);
        error -> M1
    end.

parse_ip(M, IpAttrs) ->
    M1 = case lists:keyfind(?CTA_IP_V4_SRC, 1, IpAttrs) of
        {_, <<A, B, C, D>>} -> M#{src => <<A, B, C, D>>};
        _ ->
            case lists:keyfind(?CTA_IP_V6_SRC, 1, IpAttrs) of
                {_, <<Src:16/binary>>} -> M#{src => Src};
                _ -> M
            end
    end,
    case lists:keyfind(?CTA_IP_V4_DST, 1, IpAttrs) of
        {_, <<A2, B2, C2, D2>>} -> M1#{dst => <<A2, B2, C2, D2>>};
        _ ->
            case lists:keyfind(?CTA_IP_V6_DST, 1, IpAttrs) of
                {_, <<Dst:16/binary>>} -> M1#{dst => Dst};
                _ -> M1
            end
    end.

parse_proto(M, ProtoAttrs) ->
    M1 = case lists:keyfind(?CTA_PROTO_NUM, 1, ProtoAttrs) of
        {_, <<Proto:8>>} -> M#{proto => Proto, proto_name => proto_name(Proto)};
        _ -> M
    end,
    M2 = case lists:keyfind(?CTA_PROTO_SRC_PORT, 1, ProtoAttrs) of
        {_, <<SPort:16/big>>} -> M1#{sport => SPort};
        _ -> M1
    end,
    case lists:keyfind(?CTA_PROTO_DST_PORT, 1, ProtoAttrs) of
        {_, <<DPort:16/big>>} -> M2#{dport => DPort};
        _ -> M2
    end.

proto_name(?IPPROTO_TCP)  -> <<"tcp">>;
proto_name(?IPPROTO_UDP)  -> <<"udp">>;
proto_name(?IPPROTO_ICMP) -> <<"icmp">>;
proto_name(N) -> integer_to_binary(N).

%% --- Internal: Broadcast ---

broadcast(Msg) ->
    try
        Members = pg:get_members(erlkoenig_nft, ct_events),
        _ = [Pid ! Msg || Pid <- Members],
        ok
    catch
        _:_ -> ok
    end.
