%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_firewall_events_tests).

-include_lib("eunit/include/eunit.hrl").

event_bus_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [
      fun stores_normalized_nflog_events/0,
      fun receives_nflog_events_from_pg_group/0,
      fun since_returns_only_events_after_cursor/0,
      fun skips_zero_counter_events/0
     ]}.

setup() ->
    ensure_pg(),
    case whereis(erlkoenig_firewall_events) of
        undefined -> ok;
        ExistingPid ->
            catch unlink(ExistingPid),
            exit(ExistingPid, kill),
            timer:sleep(20)
    end,
    {ok, Pid} = erlkoenig_firewall_events:start_link(),
    unlink(Pid),
    Pid.

cleanup(Pid) ->
    case is_process_alive(Pid) of
        true ->
            catch unlink(Pid),
            exit(Pid, shutdown);
        false -> ok
    end.

stores_normalized_nflog_events() ->
    ok = erlkoenig_firewall_events:ingest(
        {nflog_event, #{chain => <<"input">>,
                        src => {203,0,113,44},
                        dst => {10,0,0,1},
                        proto => tcp,
                        dport => 22}}),
    {ok, [Event]} = wait_recent(1),
    ?assertEqual(1, maps:get(seq, Event)),
    ?assertEqual(firewall_packet, maps:get(kind, Event)),
    ?assertEqual(nflog, maps:get(source, Event)),
    ?assertEqual({203,0,113,44}, maps:get(src_ip, Event)),
    ?assertEqual(22, maps:get(dst_port, Event)).

receives_nflog_events_from_pg_group() ->
    {ok, Cursor0, _} = erlkoenig_firewall_events:since(0, 0, 100),
    ok = erlkoenig_nft_events:notify_nflog(
        {nflog_event, #{chain => <<"ssh">>,
                        src => {198,51,100,9},
                        dst => {10,0,0,1},
                        proto => tcp,
                        dport => 22}}),
    {ok, _Cursor1, [Event]} = wait_since(Cursor0, 1),
    ?assertEqual(firewall_packet, maps:get(kind, Event)),
    ?assertEqual(<<"ssh">>, maps:get(chain, Event)),
    ?assertEqual({198,51,100,9}, maps:get(src_ip, Event)).

since_returns_only_events_after_cursor() ->
    {ok, Cursor0, _} = erlkoenig_firewall_events:since(0, 0, 10),
    ok = erlkoenig_firewall_events:ingest(
        {firewall_event, #{kind => scan_suspect,
                           source => threat_actor,
                           src_ip => <<"10.0.0.8">>,
                           reason => distinct_ports_seen}}),
    {ok, _Cursor1, [Event]} = wait_since(Cursor0, 1),
    ?assert(maps:get(seq, Event) > Cursor0),
    ?assertEqual(scan_suspect, maps:get(kind, Event)),
    {ok, _, []} = erlkoenig_firewall_events:since(maps:get(seq, Event), 0, 10).

skips_zero_counter_events() ->
    {ok, Cursor0, _} = erlkoenig_firewall_events:since(0, 0, 10),
    ok = erlkoenig_firewall_events:ingest(
        {counter_event, <<"input_drop">>, #{packets => 0, bytes => 0}}),
    {ok, Cursor1, []} = erlkoenig_firewall_events:since(Cursor0, 0, 10),
    ?assertEqual(Cursor0, Cursor1).

wait_recent(Limit) ->
    wait_recent(Limit, 20).

wait_recent(_Limit, 0) ->
    erlang:error(timeout);
wait_recent(Limit, Tries) ->
    case erlkoenig_firewall_events:recent(Limit) of
        {ok, []} ->
            timer:sleep(10),
            wait_recent(Limit, Tries - 1);
        Other ->
            Other
    end.

wait_since(Cursor, Limit) ->
    wait_since(Cursor, Limit, 20).

wait_since(_Cursor, _Limit, 0) ->
    erlang:error(timeout);
wait_since(Cursor, Limit, Tries) ->
    case erlkoenig_firewall_events:since(Cursor, 0, Limit) of
        {ok, _, []} ->
            timer:sleep(10),
            wait_since(Cursor, Limit, Tries - 1);
        Other ->
            Other
    end.

ensure_pg() ->
    case pg:start_link(erlkoenig_nft) of
        {ok, _Pid} -> ok;
        {error, {already_started, _Pid}} -> ok
    end.
