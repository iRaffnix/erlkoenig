%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_denial_log_tests).

-include_lib("eunit/include/eunit.hrl").

denial_log_test_() ->
    {foreach,
     fun setup/0,
     fun teardown/1,
     [fun t_lookup_empty/1,
      fun t_round_trip/1,
      fun t_lookup_returns_latest_for_id/1,
      fun t_list_for_returns_all_newest_first/1,
      fun t_all_returns_all_newest_first/1,
      fun t_ts_added_when_absent/1,
      fun t_ts_preserved_when_present/1,
      fun t_eviction_keeps_newest/1,
      fun t_clear_empties_ring/1,
      fun t_size_reflects_inserts/1]}.

setup() ->
    %% Tight ring so eviction is exercisable in tests.
    application:set_env(erlkoenig, denial_log_max_entries, 5),
    {ok, Pid} = erlkoenig_denial_log:start_link(),
    %% Cast-based writes — flush via a sync call.
    sync(),
    Pid.

teardown(Pid) ->
    application:unset_env(erlkoenig, denial_log_max_entries),
    catch gen_server:stop(Pid),
    ok.

%% Force any pending casts through the gen_server before reading ETS.
%% sys:get_state/1 is a synchronous OTP system message that queues
%% behind everything already in the mailbox, including the casts
%% from record_denial/1.
sync() -> _ = sys:get_state(erlkoenig_denial_log), ok.

flush() ->
    _ = erlkoenig_denial_log:clear(),
    ok.

denial(Id) ->
    denial(Id, #{}).

denial(Id, Extra) ->
    Base = #{container_id => Id,
             zone => zone_a,
             reason => #{reason => insufficient_memory,
                         kind => memory,
                         ceiling => 1000, allocated => 800,
                         committed => 100},
             limits => #{memory => 200, pids => 10}},
    maps:merge(Base, Extra).

t_lookup_empty(_) ->
    ?_test(begin
        ?assertEqual({error, not_found},
                     erlkoenig_denial_log:lookup(<<"nope">>))
    end).

t_round_trip(_) ->
    ?_test(begin
        ok = erlkoenig_denial_log:record_denial(denial(<<"c1">>)),
        sync(),
        {ok, Got} = erlkoenig_denial_log:lookup(<<"c1">>),
        ?assertEqual(<<"c1">>, maps:get(container_id, Got)),
        ?assert(is_integer(maps:get(ts_ms, Got))),
        ?assertEqual(zone_a, maps:get(zone, Got))
    end).

t_lookup_returns_latest_for_id(_) ->
    ?_test(begin
        ok = erlkoenig_denial_log:record_denial(
               denial(<<"c1">>, #{ts_ms => 100, zone => zone_old})),
        ok = erlkoenig_denial_log:record_denial(
               denial(<<"c1">>, #{ts_ms => 200, zone => zone_new})),
        sync(),
        {ok, Got} = erlkoenig_denial_log:lookup(<<"c1">>),
        ?assertEqual(zone_new, maps:get(zone, Got)),
        ?assertEqual(200, maps:get(ts_ms, Got))
    end).

t_list_for_returns_all_newest_first(_) ->
    ?_test(begin
        ok = erlkoenig_denial_log:record_denial(
               denial(<<"c1">>, #{ts_ms => 100})),
        ok = erlkoenig_denial_log:record_denial(
               denial(<<"c2">>, #{ts_ms => 150})),
        ok = erlkoenig_denial_log:record_denial(
               denial(<<"c1">>, #{ts_ms => 200})),
        sync(),
        Got = erlkoenig_denial_log:list_for(<<"c1">>),
        ?assertEqual(2, length(Got)),
        ?assertEqual([200, 100],
                     [maps:get(ts_ms, D) || D <- Got])
    end).

t_all_returns_all_newest_first(_) ->
    ?_test(begin
        ok = erlkoenig_denial_log:record_denial(
               denial(<<"c1">>, #{ts_ms => 100})),
        ok = erlkoenig_denial_log:record_denial(
               denial(<<"c2">>, #{ts_ms => 200})),
        sync(),
        Got = erlkoenig_denial_log:all(),
        ?assertEqual([<<"c2">>, <<"c1">>],
                     [maps:get(container_id, D) || D <- Got])
    end).

t_ts_added_when_absent(_) ->
    ?_test(begin
        Before = erlang:system_time(millisecond),
        ok = erlkoenig_denial_log:record_denial(denial(<<"c1">>)),
        sync(),
        {ok, Got} = erlkoenig_denial_log:lookup(<<"c1">>),
        After = erlang:system_time(millisecond),
        Ts = maps:get(ts_ms, Got),
        ?assert(Ts >= Before andalso Ts =< After)
    end).

t_ts_preserved_when_present(_) ->
    ?_test(begin
        ok = erlkoenig_denial_log:record_denial(
               denial(<<"c1">>, #{ts_ms => 42})),
        sync(),
        {ok, Got} = erlkoenig_denial_log:lookup(<<"c1">>),
        ?assertEqual(42, maps:get(ts_ms, Got))
    end).

t_eviction_keeps_newest(_) ->
    ?_test(begin
        flush(),
        %% Max is 5 (set in setup). Insert 8, expect oldest 3 evicted.
        [ok = erlkoenig_denial_log:record_denial(
                denial(list_to_binary("c" ++ integer_to_list(N)),
                       #{ts_ms => N}))
         || N <- lists:seq(1, 8)],
        sync(),
        ?assertEqual(5, erlkoenig_denial_log:size()),
        Got = erlkoenig_denial_log:all(),
        ?assertEqual([8, 7, 6, 5, 4],
                     [maps:get(ts_ms, D) || D <- Got])
    end).

t_clear_empties_ring(_) ->
    ?_test(begin
        ok = erlkoenig_denial_log:record_denial(denial(<<"c1">>)),
        sync(),
        ?assertEqual(1, erlkoenig_denial_log:size()),
        ok = erlkoenig_denial_log:clear(),
        ?assertEqual(0, erlkoenig_denial_log:size()),
        ?assertEqual({error, not_found},
                     erlkoenig_denial_log:lookup(<<"c1">>))
    end).

t_size_reflects_inserts(_) ->
    ?_test(begin
        flush(),
        ?assertEqual(0, erlkoenig_denial_log:size()),
        ok = erlkoenig_denial_log:record_denial(denial(<<"c1">>)),
        ok = erlkoenig_denial_log:record_denial(denial(<<"c2">>)),
        sync(),
        ?assertEqual(2, erlkoenig_denial_log:size())
    end).
