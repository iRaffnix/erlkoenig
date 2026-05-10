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

-module(erlkoenig_nft_nflog_tests).

-include_lib("eunit/include/eunit.hrl").
-include("nft_constants.hrl").

%% ============================================================
%% Phase 6.0c: ensure_started/1 receiver pooling
%% ============================================================
%%
%% The actual gen_server cannot be started in non-root eunit
%% (NFLOG socket open requires CAP_NET_ADMIN). What we test is the
%% pooling guarantee: when a process is already registered under
%% `name_for(Group)', `ensure_started/1' returns that pid instead
%% of trying to spawn a new gen_server.

name_for_test_() ->
    [
        ?_assertEqual(erlkoenig_nft_nflog_100,
                      erlkoenig_nft_nflog:name_for(100)),
        ?_assertEqual(erlkoenig_nft_nflog_0,
                      erlkoenig_nft_nflog:name_for(0)),
        ?_assertEqual(erlkoenig_nft_nflog_42,
                      erlkoenig_nft_nflog:name_for(42))
    ].

parse_ipv4_tcp_packet_preserves_raw_addresses_test() ->
    Packet = <<4:4, 5:4,
               0:8, 40:16/big, 0:16, 0:16,
               64:8, 6:8, 0:16,
               203, 0, 113, 44,
               10, 0, 0, 1,
               49152:16/big, 22:16/big,
               0:32, 0:32, 0:16>>,
    Event = erlkoenig_nft_nflog:parse_ip_packet(#{prefix => <<"ssh_drop">>}, Packet),
    ?assertEqual(<<"203.0.113.44">>, maps:get(src, Event)),
    ?assertEqual(<<"10.0.0.1">>, maps:get(dst, Event)),
    ?assertEqual(<<203,0,113,44>>, maps:get(src_raw, Event)),
    ?assertEqual(<<10,0,0,1>>, maps:get(dst_raw, Event)),
    ?assertEqual(<<"tcp">>, maps:get(proto, Event)),
    ?assertEqual(49152, maps:get(sport, Event)),
    ?assertEqual(22, maps:get(dport, Event)).

parse_ipv6_udp_packet_preserves_raw_addresses_test() ->
    Src = <<16#2001:16, 16#0db8:16, 0:16, 0:16, 0:16, 0:16, 0:16, 1:16>>,
    Dst = <<16#2001:16, 16#0db8:16, 0:16, 0:16, 0:16, 0:16, 0:16, 2:16>>,
    Packet = <<6:4, 0:8, 0:20,
               8:16/big, 17:8, 64:8,
               Src/binary, Dst/binary,
               5353:16/big, 53:16/big, 8:16/big, 0:16>>,
    Event = erlkoenig_nft_nflog:parse_ip_packet(#{}, Packet),
    ?assertEqual(Src, maps:get(src_raw, Event)),
    ?assertEqual(Dst, maps:get(dst_raw, Event)),
    ?assertEqual(<<"udp">>, maps:get(proto, Event)),
    ?assertEqual(5353, maps:get(sport, Event)),
    ?assertEqual(53, maps:get(dport, Event)).

parse_ipv4_small_ihl_is_ignored_test() ->
    Packet = <<4:4, 4:4,
               0:8, 40:16/big, 0:16, 0:16,
               64:8, 6:8, 0:16,
               10, 0, 0, 1,
               10, 0, 0, 2,
               1234:16/big, 80:16/big>>,
    ?assertEqual(#{}, erlkoenig_nft_nflog:parse_ip_packet(#{}, Packet)).

process_messages_short_nflog_payload_is_ignored_test() ->
    Len = 16 + 3,
    Type = (?NFNL_SUBSYS_ULOG bsl 8) bor ?NFULNL_MSG_PACKET,
    Msg = <<Len:32/little, Type:16/little, 0:16/little,
            1:32/little, 0:32/little, 1, 2, 3>>,
    ?assertEqual(ok, erlkoenig_nft_nflog:process_messages(Msg)).

process_messages_consumes_netlink_alignment_padding_test() ->
    ensure_pg(),
    ok = pg:join(erlkoenig_nft, nflog_events, self()),
    Packet1 = ipv4_tcp_packet(<<203,0,113,44>>, <<10,0,0,1>>, 49152, 22),
    Packet2 = ipv4_tcp_packet(<<198,51,100,9>>, <<10,0,0,1>>, 49153, 443),
    Msg1 = nflog_msg(Packet1, 1),
    Msg2 = nflog_msg(Packet2, 2),
    ?assertEqual(ok, erlkoenig_nft_nflog:process_messages(<<Msg1/binary, Msg2/binary>>)),
    Events = collect_nflog_events(2, []),
    Srcs = [maps:get(src, E) || {nflog_event, E} <- Events],
    ?assert(lists:member(<<"203.0.113.44">>, Srcs)),
    ?assert(lists:member(<<"198.51.100.9">>, Srcs)),
    pg:leave(erlkoenig_nft, nflog_events, self()).

process_messages_enriches_host_group_metadata_test() ->
    erlkoenig_nft_nflog_registry:clear(),
    ok = erlkoenig_nft_nflog_registry:register_group(1, <<"erlkoenig_host">>, host),
    ensure_pg(),
    ok = pg:join(erlkoenig_nft, nflog_events, self()),
    Packet = ipv4_tcp_packet(<<203,0,113,44>>, <<10,0,0,1>>, 49152, 22),
    Msg = nflog_msg(Packet, 1),
    ?assertEqual(ok, erlkoenig_nft_nflog:process_messages(Msg, 1)),
    [{nflog_event, Event}] = collect_nflog_events(1, []),
    ?assertEqual(<<"erlkoenig_host">>, maps:get(table, Event)),
    ?assertEqual(host, maps:get(table_owner, Event)),
    ?assertEqual(<<"203.0.113.44">>, maps:get(src, Event)),
    erlkoenig_nft_nflog_registry:clear(),
    pg:leave(erlkoenig_nft, nflog_events, self()).

nflog_registry_registers_explicit_table_groups_test() ->
    erlkoenig_nft_nflog_registry:clear(),
    Table = #{
        name => <<"erlkoenig_zone">>,
        owner => zone,
        nflog_groups => [#{group => 42, name => <<"zone_alpha">>}]
    },
    ?assertEqual(ok, erlkoenig_nft_nflog_registry:register_table(Table)),
    ?assertEqual(
        {ok, #{table => <<"erlkoenig_zone">>, table_owner => zone}},
        erlkoenig_nft_nflog_registry:lookup(42)),
    ?assertEqual(error, erlkoenig_nft_nflog_registry:lookup(43)),
    erlkoenig_nft_nflog_registry:clear().

ensure_started_returns_existing_pid_test() ->
    Group = 9999,
    Name = erlkoenig_nft_nflog:name_for(Group),
    %% Spawn a placeholder that holds the registered name, simulating
    %% an already-running receiver. The placeholder responds to no
    %% messages — `ensure_started/1' must return its pid based on
    %% `whereis/1' alone, not by sending probes.
    DummyPid = spawn(fun loop_until_killed/0),
    true = register(Name, DummyPid),
    try
        ?assertEqual({ok, DummyPid},
                     erlkoenig_nft_nflog:ensure_started(Group)),
        ?assert(lists:member(DummyPid, linked_processes()))
    after
        unlink(DummyPid),
        case whereis(Name) of
            DummyPid -> unregister(Name);
            _ -> ok
        end,
        exit(DummyPid, kill)
    end.

linked_processes() ->
    {links, Links} = process_info(self(), links),
    Links.

loop_until_killed() ->
    receive _ -> loop_until_killed() end.

ensure_pg() ->
    case pg:start_link(erlkoenig_nft) of
        {ok, _Pid} -> ok;
        {error, {already_started, _Pid}} -> ok
    end.

nflog_msg(Packet, Seq) ->
    Attrs = nfnl_attr:encode(?NFULA_PAYLOAD, Packet),
    Payload = <<0, 0, 0, 0, Attrs/binary>>,
    Len = 16 + byte_size(Payload),
    Type = (?NFNL_SUBSYS_ULOG bsl 8) bor ?NFULNL_MSG_PACKET,
    Msg = <<Len:32/little, Type:16/little, 0:16/little,
            Seq:32/little, 0:32/little, Payload/binary>>,
    PadLen = align4(Len) - Len,
    <<Msg/binary, 0:PadLen/unit:8>>.

ipv4_tcp_packet(<<SrcA, SrcB, SrcC, SrcD>>, <<DstA, DstB, DstC, DstD>>, Sport, Dport) ->
    <<4:4, 5:4,
      0:8, 40:16/big, 0:16, 0:16,
      64:8, 6:8, 0:16,
      SrcA, SrcB, SrcC, SrcD,
      DstA, DstB, DstC, DstD,
      Sport:16/big, Dport:16/big,
      0:32, 0:32, 0:16>>.

align4(N) ->
    (N + 3) band bnot 3.

collect_nflog_events(0, Acc) ->
    lists:reverse(Acc);
collect_nflog_events(N, Acc) ->
    receive
        {nflog_event, _} = Event ->
            collect_nflog_events(N - 1, [Event | Acc])
    after 1000 ->
        erlang:error({missing_nflog_events, N, lists:reverse(Acc)})
    end.
