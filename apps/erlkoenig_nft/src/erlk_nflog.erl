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

-module(erlk_nflog).
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

-export([start_link/1, stop/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

%% --- Constants ---

-define(NFNL_SUBSYS_ULOG, 4).
-define(NFULNL_MSG_PACKET, 0).

-define(NFULA_PACKET_HDR, 1).
-define(NFULA_PREFIX, 10).
-define(NFULA_PAYLOAD, 9).
-define(NFULA_IFINDEX_INDEV, 4).

-define(IPPROTO_TCP, 6).
-define(IPPROTO_UDP, 17).
-define(IPPROTO_ICMP, 1).

%% --- Public API ---

-spec start_link(non_neg_integer()) -> {ok, pid()} | {error, term()}.
start_link(Group) ->
    gen_server:start_link(?MODULE, Group, []).

-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_server:stop(Pid).

%% --- gen_server callbacks ---

init(Group) ->
    case open_nflog_socket(Group) of
        {ok, Sock} ->
            %% Start async recv loop
            request_recv(Sock),
            {ok, #{socket => Sock, group => Group}};
        {error, Reason} ->
            {stop, {nflog_open_failed, Reason}}
    end.

handle_call(_Req, _From, State) ->
    {reply, {error, unknown}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'$socket', Sock, select, _Ref}, #{socket := Sock} = State) ->
    recv_loop(Sock),
    request_recv(Sock),
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #{socket := Sock}) ->
    socket:close(Sock).

%% --- Internal: recv ---

-spec request_recv(socket:socket()) -> ok.
request_recv(Sock) ->
    case socket:recv(Sock, 0, nowait) of
        {ok, Data} ->
            process_messages(Data),
            request_recv(Sock);
        {select, _SelectInfo} ->
            ok;
        {error, _} ->
            ok
    end.

-spec recv_loop(socket:socket()) -> ok.
recv_loop(Sock) ->
    case socket:recv(Sock, 0, nowait) of
        {ok, Data} ->
            process_messages(Data),
            recv_loop(Sock);
        {select, _} ->
            ok;
        {error, _} ->
            ok
    end.

%% --- Internal: Socket setup ---

-spec open_nflog_socket(non_neg_integer()) -> {ok, socket:socket()} | {error, term()}.
open_nflog_socket(Group) ->
    nfnl_nflog:open(Group).

%% --- Internal: Message processing ---

-spec process_messages(binary()) -> ok.
process_messages(<<>>) -> ok;
process_messages(<<Len:32/little, Type:16/little, _Flags:16/little,
                   _Seq:32/little, _Pid:32/little, Rest/binary>>)
  when Len >= 20 ->
    Subsys = Type bsr 8,
    MsgType = Type band 16#FF,
    PayloadLen = Len - 16,
    case byte_size(Rest) >= PayloadLen of
        true ->
            <<Payload:PayloadLen/binary, Tail/binary>> = Rest,
            case {Subsys, MsgType} of
                {?NFNL_SUBSYS_ULOG, ?NFULNL_MSG_PACKET} ->
                    <<_:4/binary, AttrBin/binary>> = Payload,
                    Attrs = nfnl_attr:decode(AttrBin),
                    Event = parse_packet(Attrs),
                    broadcast({nflog_event, Event});
                _ ->
                    ok
            end,
            process_messages(Tail);
        false ->
            ok
    end;
process_messages(_) -> ok.

-spec parse_packet([tuple()]) -> map().
parse_packet(Attrs) ->
    M = #{},
    M1 = case lists:keyfind(?NFULA_PREFIX, 1, Attrs) of
        {_, PBin} -> M#{prefix => strip_null(PBin)};
        _ -> M
    end,
    M2 = case lists:keyfind(?NFULA_IFINDEX_INDEV, 1, Attrs) of
        {_, <<Idx:32/big>>} -> M1#{iface => Idx};
        _ -> M1
    end,
    case lists:keyfind(?NFULA_PAYLOAD, 1, Attrs) of
        {_, PayloadBin} -> parse_ip_packet(M2, PayloadBin);
        _ -> M2
    end.

-spec parse_ip_packet(map(), binary()) -> map().
parse_ip_packet(M, <<4:4, IHL:4, _TOS:8, TotalLen:16/big,
                      _ID:16, _FragOff:16, _TTL:8, Proto:8, _Checksum:16,
                      SrcA:8, SrcB:8, SrcC:8, SrcD:8,
                      DstA:8, DstB:8, DstC:8, DstD:8,
                      Rest/binary>>) ->
    Src = iolist_to_binary(erlk_ip:format(<<SrcA, SrcB, SrcC, SrcD>>)),
    Dst = iolist_to_binary(erlk_ip:format(<<DstA, DstB, DstC, DstD>>)),
    M1 = M#{src => Src, dst => Dst, len => TotalLen, proto => proto_name(Proto)},
    HeaderLen = IHL * 4,
    Skip = HeaderLen - 20,
    case {Proto, Rest} of
        {P, <<_:Skip/binary, SPort:16/big, DPort:16/big, _/binary>>}
          when P =:= ?IPPROTO_TCP; P =:= ?IPPROTO_UDP ->
            M1#{sport => SPort, dport => DPort};
        _ ->
            M1
    end;
parse_ip_packet(M, <<6:4, _TC:8, _FL:20, PayloadLen:16/big, NextHeader:8,
                      _HopLimit:8, Src:16/binary, Dst:16/binary,
                      Rest/binary>>) ->
    SrcStr = iolist_to_binary(erlk_ip:format(Src)),
    DstStr = iolist_to_binary(erlk_ip:format(Dst)),
    M1 = M#{src => SrcStr, dst => DstStr, len => 40 + PayloadLen,
             proto => proto_name(NextHeader)},
    case {NextHeader, Rest} of
        {P, <<SPort:16/big, DPort:16/big, _/binary>>}
          when P =:= ?IPPROTO_TCP; P =:= ?IPPROTO_UDP ->
            M1#{sport => SPort, dport => DPort};
        _ ->
            M1
    end;
parse_ip_packet(M, _) -> M.

-spec proto_name(non_neg_integer()) -> binary().
proto_name(?IPPROTO_TCP)  -> <<"tcp">>;
proto_name(?IPPROTO_UDP)  -> <<"udp">>;
proto_name(?IPPROTO_ICMP) -> <<"icmp">>;
proto_name(58) -> <<"icmpv6">>;
proto_name(N) -> integer_to_binary(N).

-spec broadcast(term()) -> ok.
broadcast(Msg) ->
    try
        Members = pg:get_members(erlkoenig_nft, nflog_events),
        _ = [Pid ! Msg || Pid <- Members],
        ok
    catch
        _:_ -> ok
    end.

-spec strip_null(binary()) -> binary().
strip_null(Bin) ->
    case binary:split(Bin, <<0>>) of
        [Name, _] -> Name;
        [Name] -> Name
    end.
