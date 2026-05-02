#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 52: SIGKILL a member of every pod strategy and verify
%% clean respawn.  Before the IP-pool cooldown fix, `:one_for_all`
%% and `:rest_for_one` would hit `EADDRINUSE (-98)` on respawn
%% because the dying container's ipvlan slave still held the IP
%% when the replacement tried `ip addr add`.  After the fix the
%% cooldown bridges the asynchronous kernel teardown window.
-mode(compile).

-define(PARENT, <<"ek_t52">>).
-define(GW_CIDR, "10.99.52.1/24").

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 52: SIGKILL across all 3 pod strategies ===~n~n"),
    require_root(),

    test_helper:boot(),
    logger:set_primary_config(level, error),
    application:set_env(erlkoenig, quarantine_enabled, false),

    Root     = test_helper:project_root(),
    Example  = filename:join(Root, "examples/stacks/pod_strategies.exs"),
    TermFile = "/tmp/erlkoenig_test52.term",
    DemoBin  = test_helper:demo("echo_server"),

    tutorial_helper:cleanup_all(),
    tutorial_helper:cleanup_dummy(?PARENT),
    tutorial_helper:ensure_dummy(?PARENT, ?GW_CIDR),

    test_helper:step("compile pod_strategies.exs", fun() ->
        tutorial_helper:compile_dsl(Root, Example, TermFile)
    end),

    test_helper:step("patch term", fun() ->
        tutorial_helper:patch_term(TermFile,
            #{binary => DemoBin,
              parents => #{<<"ek_strat">> => ?PARENT}})
    end),

    test_helper:step("load + 9 containers reach running", fun() ->
        tutorial_helper:load_and_wait(TermFile, 9, 30_000)
    end),

    AllNames = [<<"ofo-0-a">>, <<"ofo-0-b">>, <<"ofo-0-c">>,
                <<"ofa-0-a">>, <<"ofa-0-b">>, <<"ofa-0-c">>,
                <<"rfo-0-a">>, <<"rfo-0-b">>, <<"rfo-0-c">>],

    Before = snapshot(AllNames),

    test_helper:step("SIGKILL ofa-0-b (one_for_all member)", fun() ->
        {ok, OsPid} = maps:get(<<"ofa-0-b">>, Before),
        os:cmd("kill -9 " ++ integer_to_list(OsPid)),
        ok
    end),
    timer:sleep(3000),

    test_helper:step("wait for all 3 ofa members back in running", fun() ->
        wait_names_running([<<"ofa-0-a">>, <<"ofa-0-b">>, <<"ofa-0-c">>],
                            45_000)
    end),

    OfaAfter = snapshot([<<"ofa-0-a">>, <<"ofa-0-b">>, <<"ofa-0-c">>]),

    test_helper:step(":one_for_all: ALL three have NEW os_pids "
                     "(no EADDRINUSE)",
      fun() ->
        lists:foreach(fun(N) ->
            {ok, Old} = maps:get(N, Before),
            {ok, New} = maps:get(N, OfaAfter),
            case New =/= Old of
                true  -> ok;
                false -> error({no_churn, N, Old, New})
            end
        end, [<<"ofa-0-a">>, <<"ofa-0-b">>, <<"ofa-0-c">>]),
        ok
    end),

    Before2 = snapshot(AllNames),

    test_helper:step("SIGKILL rfo-0-b (rest_for_one member)", fun() ->
        {ok, OsPid} = maps:get(<<"rfo-0-b">>, Before2),
        os:cmd("kill -9 " ++ integer_to_list(OsPid)),
        ok
    end),
    timer:sleep(3000),

    test_helper:step("wait for rfo-0-b + rfo-0-c back in running", fun() ->
        wait_names_running([<<"rfo-0-b">>, <<"rfo-0-c">>], 20_000)
    end),

    RfoAfter = snapshot([<<"rfo-0-a">>, <<"rfo-0-b">>, <<"rfo-0-c">>]),

    test_helper:step(":rest_for_one: b+c churned, a stable", fun() ->
        {ok, A0} = maps:get(<<"rfo-0-a">>, Before2),
        {ok, AN} = maps:get(<<"rfo-0-a">>, RfoAfter),
        {ok, B0} = maps:get(<<"rfo-0-b">>, Before2),
        {ok, BN} = maps:get(<<"rfo-0-b">>, RfoAfter),
        {ok, C0} = maps:get(<<"rfo-0-c">>, Before2),
        {ok, CN} = maps:get(<<"rfo-0-c">>, RfoAfter),
        true = A0 =:= AN,
        true = B0 =/= BN,
        true = C0 =/= CN,
        ok
    end),

    test_helper:step("cleanup", fun() ->
        tutorial_helper:cleanup_all(),
        tutorial_helper:cleanup_dummy(?PARENT),
        file:delete(TermFile),
        ok
    end),

    io:format("~n=== Test 52 passed — IP-pool cooldown beats the "
              "EADDRINUSE race ===~n~n"),
    halt(0).

require_root() ->
    case string:trim(os:cmd("id -u")) of
        "0" -> ok;
        _   -> io:format("ERROR: must run as root~n"), halt(1)
    end.

snapshot(Names) ->
    maps:from_list([{N, get_os_pid(N)} || N <- Names]).

get_os_pid(Name) ->
    case tutorial_helper:find_pid(Name) of
        {ok, Pid} ->
            try erlkoenig:inspect(Pid) of
                #{os_pid := OsPid} -> {ok, OsPid};
                _ -> not_running
            catch _:_ -> crashed
            end;
        not_found -> not_found
    end.

wait_names_running(Names, TimeoutMs) ->
    Dl = erlang:system_time(millisecond) + TimeoutMs,
    wait_names_running_loop(Names, Dl).

wait_names_running_loop(Names, Dl) ->
    Running = [N || N <- Names, running(N)],
    AllUp = lists:sort(Running) =:= lists:sort(Names),
    case AllUp of
        true -> ok;
        false ->
            case erlang:system_time(millisecond) > Dl of
                true -> {error, {timeout, missing, Names -- Running}};
                false -> timer:sleep(300),
                         wait_names_running_loop(Names, Dl)
            end
    end.

running(Name) ->
    case tutorial_helper:find_pid(Name) of
        {ok, Pid} ->
            try erlkoenig:inspect(Pid) of
                #{state := running} -> true;
                _ -> false
            catch _:_ -> false end;
        _ -> false
    end.
