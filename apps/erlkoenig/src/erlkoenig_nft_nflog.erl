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

-module(erlkoenig_nft_nflog).
-moduledoc """
NFLOG receiver - receives firewall log messages directly from the kernel
via a NETLINK_NETFILTER socket. No dmesg, no file parsing.

Events are broadcast via pg group `nflog_events`:
    {nflog_event, #{
        prefix => <<"ERLKOENIG: ">>,
        src    => <<"10.0.0.5">>,
        dst    => <<"192.168.1.1">>,
        proto  => <<"tcp">>,
        sport  => 54321,
        dport  => 80,
        len    => 60
    }}
""".

-behaviour(gen_server).

-export([start_link/1, ensure_started/1, stop/1, name_for/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).
%% Exposed for fuzzing / property tests.  Pure functions — no side
%% effects.  Do not call from production code; use the gen_server
%% interface instead.
-export([parse_packet/1, parse_ip_packet/2, process_messages/1, process_messages/2]).

-include("nft_constants.hrl").

-define(IPPROTO_TCP, 6).
-define(IPPROTO_UDP, 17).
-define(IPPROTO_ICMP, 1).

%% --- Public API ---

-spec start_link(non_neg_integer()) -> {ok, pid()} | {error, term()}.
start_link(Group) ->
    gen_server:start_link(?MODULE, Group, []).

-doc """
Ensure exactly one nflog receiver is running for the given group.

Returns the existing pid if a receiver is already registered for
this group; otherwise starts a new one under the deterministic
local name returned by `name_for/1'. Idempotent under concurrent
callers — the registration is atomic and a lost race resolves to
`{ok, ExistingPid}'.

The returned pid is linked to the caller (same as `start_link/1');
callers that should not own the lifecycle of the receiver must
unlink afterwards.
""".
-spec ensure_started(non_neg_integer()) -> {ok, pid()} | {error, term()}.
ensure_started(Group) when is_integer(Group), Group >= 0 ->
    Name = name_for(Group),
    case whereis(Name) of
        Pid when is_pid(Pid) ->
            link(Pid),
            {ok, Pid};
        undefined ->
            case gen_server:start_link({local, Name}, ?MODULE, Group, []) of
                {ok, Pid} ->
                    {ok, Pid};
                {error, {already_started, Pid}} ->
                    link(Pid),
                    {ok, Pid};
                {error, _} = Err ->
                    Err
            end
    end.

-doc "Deterministic local registration name for a given nflog group.".
-spec name_for(non_neg_integer()) -> atom().
name_for(Group) when is_integer(Group), Group >= 0 ->
    list_to_atom("erlkoenig_nft_nflog_" ++ integer_to_list(Group)).

-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_server:stop(Pid).

%% --- gen_server callbacks ---

init(Group) ->
    proc_lib:set_label(erlkoenig_nft_nflog),
    case open_nflog_socket(Group) of
        {ok, Sock} ->
            %% Start async recv loop
            request_recv(Sock, Group),
            {ok, #{socket => Sock, group => Group}};
        {error, Reason} ->
            {stop, {nflog_open_failed, Reason}}
    end.

handle_call(_Req, _From, State) ->
    {reply, {error, unknown}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'$socket', Sock, select, _Ref}, #{socket := Sock, group := Group} = State) ->
    recv_loop(Sock, Group),
    request_recv(Sock, Group),
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #{socket := Sock}) ->
    socket:close(Sock).

%% --- Internal: recv ---

-spec request_recv(socket:socket(), non_neg_integer()) -> ok.
request_recv(Sock, Group) ->
    case socket:recv(Sock, 0, nowait) of
        {ok, Data} ->
            process_messages(Data, Group),
            request_recv(Sock, Group);
        {select, _SelectInfo} ->
            ok;
        {error, Reason} ->
            logger:warning("[erlkoenig_nft_nflog] recv failed: ~p", [Reason]),
            ok
    end.

-spec recv_loop(socket:socket(), non_neg_integer()) -> ok.
recv_loop(Sock, Group) ->
    case socket:recv(Sock, 0, nowait) of
        {ok, Data} ->
            process_messages(Data, Group),
            recv_loop(Sock, Group);
        {select, _} ->
            ok;
        {error, Reason} ->
            logger:warning("[erlkoenig_nft_nflog] recv_loop failed: ~p", [Reason]),
            ok
    end.

%% --- Internal: Socket setup ---

-spec open_nflog_socket(non_neg_integer()) -> {ok, socket:socket()} | {error, term()}.
open_nflog_socket(Group) ->
    nfnl_nflog:open(Group).

%% --- Internal: Message processing ---

-spec process_messages(binary()) -> ok.
process_messages(Bin) ->
    process_messages(Bin, unknown).

-spec process_messages(binary(), non_neg_integer() | unknown) -> ok.
process_messages(<<>>, _Group) ->
    ok;
process_messages(Bin, Group) ->
    process_messages_loop(Bin, Group).

process_messages_loop(<<>>, _Group) ->
    ok;
process_messages_loop(
    <<Len:32/little, Type:16/little, _Flags:16/little, _Seq:32/little, _Pid:32/little, Rest/binary>>,
    Group
) when
    Len >= 20
->
    Subsys = Type bsr 8,
    MsgType = Type band 16#FF,
    PayloadLen = Len - 16,
    AlignedPayloadLen = align4(Len) - 16,
    case byte_size(Rest) >= PayloadLen of
        true ->
            {Payload, Tail} = split_payload(Rest, PayloadLen, AlignedPayloadLen),
            case {Subsys, MsgType} of
                {?NFNL_SUBSYS_ULOG, ?NFULNL_MSG_PACKET} ->
                    process_nflog_packet(Group, Payload);
                _ ->
                    ok
            end,
            process_messages_loop(Tail, Group);
        false ->
            ok
    end;
process_messages_loop(_, _Group) ->
    ok.

split_payload(Rest, PayloadLen, AlignedPayloadLen)
  when byte_size(Rest) >= AlignedPayloadLen ->
    PadLen = AlignedPayloadLen - PayloadLen,
    <<Payload:PayloadLen/binary, _Pad:PadLen/binary, Tail/binary>> = Rest,
    {Payload, Tail};
split_payload(Rest, PayloadLen, _AlignedPayloadLen) ->
    <<Payload:PayloadLen/binary, Tail/binary>> = Rest,
    {Payload, Tail}.

align4(N) ->
    (N + 3) band bnot 3.

process_nflog_packet(Group, Payload) when byte_size(Payload) >= 4 ->
    <<_:4/binary, AttrBin/binary>> = Payload,
    %% nfnl_attr:decode may raise on malformed NLA. Skip the
    %% individual message and keep draining the kernel socket.
    try
        Attrs = nfnl_attr:decode(AttrBin),
        Event0 = parse_packet(Attrs),
        Event = enrich_group_metadata(Group, Event0),
        erlkoenig_nft_events:notify_nflog({nflog_event, Event})
    catch _:_ -> ok
    end;
process_nflog_packet(_Group, _Payload) ->
    ok.

enrich_group_metadata(Group, Event) ->
    case erlkoenig_nft_nflog_registry:lookup(Group) of
        {ok, Meta} ->
            maps:merge(Event, Meta);
        error ->
            Event
    end.

-spec parse_packet([{char(), binary()} | {char(), nested, [any()]}]) ->
    #{
        dport => char(),
        dst => binary(),
        iface => non_neg_integer(),
        len => non_neg_integer(),
        prefix => binary(),
        proto => binary(),
        sport => char(),
        src => binary()
    }.
parse_packet(Attrs) ->
    M = #{},
    M1 =
        case lists:keyfind(?NFULA_PREFIX, 1, Attrs) of
            {_, PBin} -> M#{prefix => strip_null(PBin)};
            _ -> M
        end,
    M2 =
        case lists:keyfind(?NFULA_IFINDEX_INDEV, 1, Attrs) of
            {_, <<Idx:32/big>>} -> M1#{iface => Idx};
            _ -> M1
        end,
    case lists:keyfind(?NFULA_PAYLOAD, 1, Attrs) of
        {_, PayloadBin} -> parse_ip_packet(M2, PayloadBin);
        _ -> M2
    end.

-spec parse_ip_packet(#{iface => non_neg_integer(), prefix => binary()}, binary()) ->
    #{
        dport => char(),
        dst => binary(),
        iface => non_neg_integer(),
        len => non_neg_integer(),
        prefix => binary(),
        proto => binary(),
        sport => char(),
        src => binary()
    }.
parse_ip_packet(
    M,
    <<4:4, IHL:4, _TOS:8, TotalLen:16/big, _ID:16, _FragOff:16, _TTL:8, Proto:8, _Checksum:16,
        SrcA:8, SrcB:8, SrcC:8, SrcD:8, DstA:8, DstB:8, DstC:8, DstD:8, Rest/binary>>
) when IHL >= 5 ->
    SrcRaw = <<SrcA, SrcB, SrcC, SrcD>>,
    DstRaw = <<DstA, DstB, DstC, DstD>>,
    Src = iolist_to_binary(erlkoenig_nft_ip:format(<<SrcA, SrcB, SrcC, SrcD>>)),
    Dst = iolist_to_binary(erlkoenig_nft_ip:format(<<DstA, DstB, DstC, DstD>>)),
    M1 = M#{src => Src, dst => Dst,
            src_raw => SrcRaw, dst_raw => DstRaw,
            len => TotalLen, proto => proto_name(Proto)},
    HeaderLen = IHL * 4,
    Skip = HeaderLen - 20,
    case {Proto, Rest} of
        {P, <<_:Skip/binary, SPort:16/big, DPort:16/big, _/binary>>} when
            P =:= ?IPPROTO_TCP; P =:= ?IPPROTO_UDP
        ->
            M1#{sport => SPort, dport => DPort};
        _ ->
            M1
    end;
parse_ip_packet(
    M,
    <<6:4, _TC:8, _FL:20, PayloadLen:16/big, NextHeader:8, _HopLimit:8, Src:16/binary,
        Dst:16/binary, Rest/binary>>
) ->
    SrcStr = iolist_to_binary(erlkoenig_nft_ip:format(Src)),
    DstStr = iolist_to_binary(erlkoenig_nft_ip:format(Dst)),
    M1 = M#{
        src => SrcStr,
        dst => DstStr,
        src_raw => Src,
        dst_raw => Dst,
        len => 40 + PayloadLen,
        proto => proto_name(NextHeader)
    },
    case {NextHeader, Rest} of
        {P, <<SPort:16/big, DPort:16/big, _/binary>>} when
            P =:= ?IPPROTO_TCP; P =:= ?IPPROTO_UDP
        ->
            M1#{sport => SPort, dport => DPort};
        _ ->
            M1
    end;
parse_ip_packet(M, _) ->
    M.

-spec proto_name(byte()) -> binary().
proto_name(?IPPROTO_TCP) -> <<"tcp">>;
proto_name(?IPPROTO_UDP) -> <<"udp">>;
proto_name(?IPPROTO_ICMP) -> <<"icmp">>;
proto_name(58) -> <<"icmpv6">>;
proto_name(N) -> integer_to_binary(N).

-spec strip_null(binary()) -> binary().
strip_null(Bin) ->
    case binary:split(Bin, <<0>>) of
        [Name, _] -> Name;
        [Name] -> Name
    end.
