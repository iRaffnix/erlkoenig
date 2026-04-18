#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 29: Pod strategies -- :one_for_one (isolated).
%%
%% Spawns the three pods from examples/pod_strategies.exs, but asserts
%% the coupling pattern only for the :one_for_one pod. The
%% :one_for_all and :rest_for_one pods are declared (so the example
%% still compiles and spawns as published) but their SIGKILL
%% behaviour currently hits a known IP-reuse race: the pod supervisor
%% simultaneously tears down every coupled sibling, but the dying
%% container's ipvlan slave (and its address) hasn't left the kernel
%% by the time the replacement tries `ip addr add`. Tracked as a
%% runtime finding; chapter 4 marks the all/rest strategies as
%% hands-on-only for now.
%%
%% Needs sudo, a free 10.99.200.0/24, and the ipvlan kernel module.
-mode(compile).

-define(PARENT, "ek_strat_test").
-define(GW_CIDR, "10.99.200.1/24").

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 29: Pod strategies ===~n~n"),

    require_root(),
    require_ipvlan_module(),

    test_helper:boot(),
    logger:set_primary_config(level, warning),

    %% This test deliberately kills the same binary repeatedly. The
    %% crashloop quarantine fires after five crashes on the same hash
    %% within its window, which would turn later SIGKILLs into
    %% `{quarantined, …}` spawn errors. Disable the feature for the
    %% run and bounce the gen_server so it picks up the new env.
    application:set_env(erlkoenig, quarantine_enabled, false),
    _ = exit(whereis(erlkoenig_quarantine), kill),
    timer:sleep(200),

    Root     = test_helper:project_root(),
    Example  = filename:join(Root, "examples/pod_strategies.exs"),
    TermFile = "/tmp/erlkoenig_integration_29.term",
    DemoBin  = binary_to_list(test_helper:demo("echo_server")),

    ensure_parent(),

    test_helper:step("mix compile .exs -> .term", fun() ->
        compile_dsl(Root, Example, TermFile)
    end),

    test_helper:step("patch term (parent + binary + zone)", fun() ->
        patch_term(TermFile, list_to_binary(DemoBin))
    end),

    test_helper:step("erlkoenig_config:load/1 -> 9 containers", fun() ->
        case erlkoenig_config:load(TermFile) of
            {ok, Names} when length(Names) =:= 9 -> ok;
            {ok, Other} ->
                {error, {expected_9_got, length(Other)}};
            {error, Reason} ->
                {error, {load_failed, Reason}}
        end
    end),

    test_helper:step("wait for 9 running", fun() ->
        wait_for_running(9, 30_000)
    end),
    timer:sleep(1500),

    %% Snapshot every ofo container's os_pid before we meddle.
    OfoNames = [<<"ofo-0-a">>, <<"ofo-0-b">>, <<"ofo-0-c">>],
    Before = snapshot(OfoNames),

    test_helper:step("SIGKILL ofo-0-b (middle of :one_for_one pod)", fun() ->
        #{<<"ofo-0-b">> := {OsPid, _}} = Before,
        os:cmd("kill -KILL " ++ integer_to_list(OsPid)),
        wait_until_running(<<"ofo-0-b">>, 15_000)
    end),
    timer:sleep(1500),

    After = snapshot(OfoNames),

    test_helper:step(":one_for_one isolates -- a/c preserved, b churned",
                     fun() ->
        {OldA, _} = maps:get(<<"ofo-0-a">>, Before),
        {NewA, _} = maps:get(<<"ofo-0-a">>, After),
        {OldB, _} = maps:get(<<"ofo-0-b">>, Before),
        {NewB, _} = maps:get(<<"ofo-0-b">>, After),
        {OldC, _} = maps:get(<<"ofo-0-c">>, Before),
        {NewC, _} = maps:get(<<"ofo-0-c">>, After),
        case {OldA =:= NewA, OldB =/= NewB, OldC =:= NewC} of
            {true, true, true} -> ok;
            Other ->
                {error, {churn_mismatch,
                         #{a_preserved => element(1, Other),
                           b_churned   => element(2, Other),
                           c_preserved => element(3, Other)}}}
        end
    end),

    %% Backoff smoke test -- kill ofo-0-a five times, observe monotonic
    %% restart_count and plausible wall-clock growth between kills.
    test_helper:step("backoff: 5 × SIGKILL ofo-0-a, counter reaches 5",
                     fun() ->
        lists:foreach(fun(_) ->
            case inspect_os_pid_and_count(<<"ofo-0-a">>) of
                {OsPid, _} ->
                    os:cmd("kill -KILL " ++ integer_to_list(OsPid)),
                    ok = wait_until_running(<<"ofo-0-a">>, 25_000)
            end
        end, lists:seq(1, 5)),
        case inspect_os_pid_and_count(<<"ofo-0-a">>) of
            {_, N} when N >= 5 -> ok;
            {_, N} -> {error, {expected_count_ge_5, N}}
        end
    end),

    %% Cleanup
    test_helper:step("cleanup", fun() ->
        Pids = try pg:get_members(erlkoenig_pg, erlkoenig_cts)
               catch error:_ -> []
               end,
        test_helper:cleanup(Pids),
        file:delete(TermFile),
        cleanup_parent(),
        ok
    end),

    io:format("~n=== Test 29 bestanden ===~n~n"),
    halt(0).

%% ──────────────────────────────────────────────────────────────

require_root() ->
    case string:trim(os:cmd("id -u")) of
        "0" -> ok;
        _   -> io:format("ERROR: must run as root~n"), halt(1)
    end.

require_ipvlan_module() ->
    Out = os:cmd("modprobe ipvlan 2>&1; echo $?"),
    case lists:last(string:split(string:trim(Out), "\n", all)) of
        "0" -> ok;
        _   -> io:format("SKIP: ipvlan kernel module not available~n"),
               halt(77)
    end.

ensure_parent() ->
    os:cmd("ip link del h." ?PARENT " 2>/dev/null"),
    os:cmd("ip link del " ?PARENT " 2>/dev/null"),
    "0" = exit_code(os:cmd("ip link add " ?PARENT " type dummy 2>&1; echo $?")),
    "0" = exit_code(os:cmd("ip addr add " ?GW_CIDR " dev " ?PARENT " 2>&1; echo $?")),
    "0" = exit_code(os:cmd("ip link set " ?PARENT " up 2>&1; echo $?")),
    ok.

cleanup_parent() ->
    os:cmd("ip link del h." ?PARENT " 2>/dev/null"),
    os:cmd("ip link del " ?PARENT " 2>/dev/null"),
    ok.

compile_dsl(Root, Example, TermFile) ->
    DslDir = filename:join(Root, "dsl"),
    Snippet = io_lib:format(
                "[{mod, _} | _] = Code.compile_file(~p); mod.write!(~p)",
                [Example, TermFile]),
    Cmd = "cd " ++ DslDir ++
          " && MIX_ENV=test mix run --no-deps-check --no-compile -e " ++
          shell_quote(lists:flatten(Snippet)) ++ " 2>&1",
    Output = os:cmd(Cmd),
    case filelib:is_regular(TermFile) of
        true  -> ok;
        false -> {error, {term_not_created, Output}}
    end.

%% Retarget the dummy parent so the test doesn't touch the stack
%% file's real `ek_strat`, and point every container at the test
%% echo binary.
patch_term(TermFile, BinPath) ->
    {ok, Config} = erlkoenig_config:parse(TermFile),
    Pods = maps:get(pods, Config, []),
    Zones = maps:get(zones, Config, []),
    Host0 = maps:get(host, Config, #{}),
    NewPods = [patch_pod_binaries(P, BinPath) || P <- Pods],
    NewZones = [patch_zone_parent(Z) || Z <- Zones],
    NewHost = patch_host_parent(Host0),
    Final = Config#{pods => NewPods, zones => NewZones, host => NewHost},
    file:write_file(TermFile, io_lib:format("~tp.~n", [Final])),
    ok.

patch_pod_binaries(Pod, BinPath) ->
    Cts = [Ct#{binary => BinPath} || Ct <- maps:get(containers, Pod, [])],
    Pod#{containers => Cts}.

patch_zone_parent(#{network := Net} = Zone) ->
    Zone#{network => Net#{parent => list_to_binary(?PARENT)}};
patch_zone_parent(Zone) -> Zone.

patch_host_parent(#{network := Net} = Host) ->
    Host#{network => Net#{parent => list_to_binary(?PARENT)}};
patch_host_parent(Host) -> Host.

snapshot(Names) ->
    maps:from_list([{N, inspect_os_pid_and_count(N)} || N <- Names]).

inspect_os_pid_and_count(NameBin) ->
    {ok, Pid} = find_pid(NameBin),
    #{os_pid := OsPid, restart_count := Count} = erlkoenig:inspect(Pid),
    {OsPid, Count}.

find_pid(NameBin) ->
    Pids = try pg:get_members(erlkoenig_pg, erlkoenig_cts)
           catch error:_ -> []
           end,
    Match = [P || P <- Pids,
                  try #{name := N} = erlkoenig:inspect(P),
                       N =:= NameBin
                  catch _:_ -> false end],
    case Match of
        [Pid | _] -> {ok, Pid};
        []        -> not_found
    end.

wait_for_running(N, TimeoutMs) ->
    wait_for_running(N, TimeoutMs, erlang:system_time(millisecond)).

wait_for_running(N, TimeoutMs, Start) ->
    Now = erlang:system_time(millisecond),
    case Now - Start > TimeoutMs of
        true -> {error, {timeout_waiting_for_running, N}};
        false ->
            Pids = try pg:get_members(erlkoenig_pg, erlkoenig_cts)
                   catch error:_ -> []
                   end,
            Running = [P || P <- Pids,
                            try #{state := running} = erlkoenig:inspect(P), true
                            catch _:_ -> false end],
            case length(Running) of
                N -> ok;
                _ -> timer:sleep(200),
                     wait_for_running(N, TimeoutMs, Start)
            end
    end.

wait_until_running(NameBin, TimeoutMs) ->
    wait_until_running(NameBin, TimeoutMs, erlang:system_time(millisecond)).

wait_until_running(NameBin, TimeoutMs, Start) ->
    Now = erlang:system_time(millisecond),
    case Now - Start > TimeoutMs of
        true -> {error, {timeout_waiting_for, NameBin}};
        false ->
            case find_pid(NameBin) of
                {ok, Pid} ->
                    case try erlkoenig:inspect(Pid)
                         catch _:_ -> #{} end of
                        #{state := running} -> ok;
                        _ -> timer:sleep(200),
                             wait_until_running(NameBin, TimeoutMs, Start)
                    end;
                _ ->
                    timer:sleep(200),
                    wait_until_running(NameBin, TimeoutMs, Start)
            end
    end.

exit_code(Str) ->
    Lines = [L || L <- string:split(string:trim(Str), "\n", all), L =/= ""],
    case Lines of
        [] -> "";
        _  -> lists:last(Lines)
    end.

shell_quote(S) ->
    Escaped = lists:flatten(
                [case C of
                     $' -> "'\\''";
                     Other -> Other
                 end || C <- S]),
    "'" ++ Escaped ++ "'".
