%%%-------------------------------------------------------------------
%%% @doc Unit tests for erlkoenig_quarantine.
%%%
%%% Exercises: the crashloop threshold, manual quarantine/unquarantine,
%%% the pre-spawn `check/1` gate, and the hash-based keying.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_quarantine_tests).

-include_lib("eunit/include/eunit.hrl").

quarantine_test_() ->
    {foreach, fun setup/0, fun cleanup/1,
     [fun t_enabled_by_default/1,
      fun t_crash_under_threshold_clears/1,
      fun t_crash_over_threshold_quarantines/1,
      fun t_window_expires_old_crashes/1,
      fun t_manual_quarantine/1,
      fun t_unquarantine/1,
      fun t_check_gate_on_quarantined/1,
      fun t_check_gate_passes_when_clean/1,
      fun t_list_snapshot/1,
      fun t_disabled_never_quarantines/1]}.

%%--------------------------------------------------------------------
%% Fixture
%%--------------------------------------------------------------------

setup() ->
    %% Low threshold + short window so tests are fast and deterministic.
    ok = application:set_env(erlkoenig, quarantine_enabled, true),
    ok = application:set_env(erlkoenig, quarantine_threshold, 3),
    ok = application:set_env(erlkoenig, quarantine_window_ms, 500),
    %% Fresh binary per test so hashes don't bleed across tests.
    BinPath = iolist_to_binary(
        ["/tmp/eunit_ek_qtn_",
         integer_to_list(erlang:system_time(nanosecond)), ".bin"]),
    ok = file:write_file(binary_to_list(BinPath),
                         crypto:strong_rand_bytes(128)),
    {ok, _} = erlkoenig_quarantine:start_link(),
    #{bin => BinPath}.

cleanup(#{bin := BinPath}) ->
    case whereis(erlkoenig_quarantine) of
        undefined -> ok;
        Pid -> gen_server:stop(Pid, normal, 5_000)
    end,
    _ = file:delete(binary_to_list(BinPath)),
    _ = application:unset_env(erlkoenig, quarantine_enabled),
    _ = application:unset_env(erlkoenig, quarantine_threshold),
    _ = application:unset_env(erlkoenig, quarantine_window_ms),
    ok.

%%--------------------------------------------------------------------
%% Tests
%%--------------------------------------------------------------------

t_enabled_by_default(_) ->
    ?_test(?assertEqual([], erlkoenig_quarantine:list())).

t_crash_under_threshold_clears(#{bin := Bin}) ->
    ?_test(begin
        ok = erlkoenig_quarantine:record_crash(Bin),
        ok = erlkoenig_quarantine:record_crash(Bin),
        sync(),
        %% threshold is 3 — two crashes should not trigger.
        ?assertEqual([], erlkoenig_quarantine:list())
    end).

t_crash_over_threshold_quarantines(#{bin := Bin}) ->
    ?_test(begin
        lists:foreach(
            fun(_) -> erlkoenig_quarantine:record_crash(Bin) end,
            lists:seq(1, 3)),
        sync(),
        {ok, Hash} = erlkoenig_sig:hash_file(Bin),
        ?assertMatch({true, _Since},
                     erlkoenig_quarantine:is_quarantined(Hash))
    end).

t_window_expires_old_crashes(#{bin := Bin}) ->
    ?_test(begin
        %% Two crashes now, wait past the 500 ms window, two more —
        %% at most 2 in any 500 ms window → no quarantine.
        erlkoenig_quarantine:record_crash(Bin),
        erlkoenig_quarantine:record_crash(Bin),
        sync(),
        timer:sleep(600),
        erlkoenig_quarantine:record_crash(Bin),
        erlkoenig_quarantine:record_crash(Bin),
        sync(),
        ?assertEqual([], erlkoenig_quarantine:list())
    end).

t_manual_quarantine(#{bin := Bin}) ->
    ?_test(begin
        {ok, Hash} = erlkoenig_sig:hash_file(Bin),
        ok = erlkoenig_quarantine:quarantine(Hash, operator_ban),
        ?assertMatch({true, _}, erlkoenig_quarantine:is_quarantined(Hash))
    end).

t_unquarantine(#{bin := Bin}) ->
    ?_test(begin
        {ok, Hash} = erlkoenig_sig:hash_file(Bin),
        ok = erlkoenig_quarantine:quarantine(Hash, test),
        ok = erlkoenig_quarantine:unquarantine(Hash),
        ?assertEqual(false, erlkoenig_quarantine:is_quarantined(Hash))
    end).

t_check_gate_on_quarantined(#{bin := Bin}) ->
    ?_test(begin
        {ok, Hash} = erlkoenig_sig:hash_file(Bin),
        ok = erlkoenig_quarantine:quarantine(Hash, test),
        ?assertMatch({error, {quarantined, Hash, _Since}},
                     erlkoenig_quarantine:check(Bin))
    end).

t_check_gate_passes_when_clean(#{bin := Bin}) ->
    ?_test(?assertEqual(ok, erlkoenig_quarantine:check(Bin))).

t_list_snapshot(#{bin := Bin}) ->
    ?_test(begin
        {ok, Hash} = erlkoenig_sig:hash_file(Bin),
        ok = erlkoenig_quarantine:quarantine(Hash, operator_ban),
        [{Hash, Meta}] = erlkoenig_quarantine:list(),
        ?assertEqual(operator_ban, maps:get(reason, Meta)),
        ?assert(is_integer(maps:get(since, Meta)))
    end).

t_disabled_never_quarantines(#{bin := Bin}) ->
    ?_test(begin
        ok = application:set_env(erlkoenig, quarantine_enabled, false),
        %% Restart to pick up env change.
        _ = gen_server:stop(erlkoenig_quarantine, normal, 5_000),
        {ok, _} = erlkoenig_quarantine:start_link(),
        lists:foreach(
            fun(_) -> erlkoenig_quarantine:record_crash(Bin) end,
            lists:seq(1, 10)),
        sync(),
        ?assertEqual([], erlkoenig_quarantine:list())
    end).

%%--------------------------------------------------------------------
%% Helper — wait for async casts to settle.
%%--------------------------------------------------------------------

sync() ->
    %% A synchronous call after casts guarantees earlier casts have
    %% been processed (gen_server mailbox FIFO).
    _ = erlkoenig_quarantine:list(),
    ok.
