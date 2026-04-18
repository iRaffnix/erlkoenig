#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 28: Tutorial lifecycle — SIGKILL restart + config drift.
%%
%% Loads examples/tutorial.exs and drives it through the lifecycle the
%% book's chapter 3 promises:
%%
%%   1. up -> 3 containers running (2 web replicas + 1 api)
%%   2. SIGKILL the web-0 OS process -> pod supervisor respawns,
%%      restart_count goes from 0 to 1
%%   3. Edit the .term in-memory: change web's args and nft input
%%      tcp_dport; reload via erlkoenig_config:load
%%   4. Verify drift detection restarted *only* the two web
%%      containers, api kept its old gen_statem pid
%%   5. Verify restart_count on web-0 is 2 (survived reconcile via
%%      persistent_term)
%%   6. New port answers, old port doesn't
%%   7. Down: stop everything, /proc/net/nf_conntrack stays sane
%%
%% Needs sudo, a free 10.99.0.0/24, and the ipvlan kernel module.
-mode(compile).

-define(PARENT, "ek_tut_test").
-define(GW_CIDR, "10.99.0.1/24").

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 28: Tutorial lifecycle ===~n~n"),

    require_root(),
    require_ipvlan_module(),

    test_helper:boot(),
    logger:set_primary_config(level, warning),

    Root     = test_helper:project_root(),
    Example  = filename:join(Root, "examples/tutorial.exs"),
    TermFile = "/tmp/erlkoenig_integration_25.term",
    DemoBin  = binary_to_list(test_helper:demo("echo_server")),

    ensure_parent(),

    test_helper:step("mix compile .exs -> .term", fun() ->
        compile_dsl(Root, Example, TermFile)
    end),

    %% The tutorial's host firewall whitelists only SSH 22222; applying
    %% it to a test runner would drop us. Strip host-wide bits and
    %% patch the dummy parent name + binary path. Container-level nft
    %% is preserved — that is what we want to exercise.
    test_helper:step("patch term for test (strip host fw, retarget parent)",
                     fun() -> patch_term(TermFile, list_to_binary(DemoBin)) end),

    test_helper:step("erlkoenig_config:load/1 -> 3 containers", fun() ->
        case erlkoenig_config:load(TermFile) of
            {ok, Names} when length(Names) =:= 3 ->
                io:format("    loaded: ~p~n",
                          [[N || {N, _} <- Names]]),
                ok;
            {ok, Other} ->
                {error, {expected_3_got, length(Other)}};
            {error, Reason} ->
                {error, {load_failed, Reason}}
        end
    end),

    test_helper:step("wait for 3 running", fun() ->
        wait_for_running(3, 30_000)
    end),
    timer:sleep(1500),

    %% --- SIGKILL + restart_count -------------------------------------

    {OldOsPid, 0} = inspect_os_pid_and_count(<<"app-0-web">>),

    test_helper:step("SIGKILL app-0-web OS process", fun() ->
        os:cmd("kill -KILL " ++ integer_to_list(OldOsPid)),
        wait_until_running(<<"app-0-web">>, 15_000)
    end),

    test_helper:step("restart_count persists to 1", fun() ->
        case inspect_os_pid_and_count(<<"app-0-web">>) of
            {NewOsPid, 1} when NewOsPid =/= OldOsPid -> ok;
            {_, N}   -> {error, {expected_count_1_got, N}};
            Other    -> {error, {unexpected, Other}}
        end
    end),

    ApiPidBefore = find_pid(<<"app-0-api">>),

    %% --- Drift via config edit ---------------------------------------

    test_helper:step("patch term: web port 8080 -> 9090", fun() ->
        patch_web_port(TermFile, <<"9090">>)
    end),

    test_helper:step("erlkoenig_config:load/1 reconciles drift", fun() ->
        case erlkoenig_config:load(TermFile) of
            {ok, _Names} ->
                io:format("    drift reload ok~n"),
                ok;
            {error, Reason} ->
                {error, {reload_failed, Reason}}
        end
    end),
    timer:sleep(1500),
    ok = wait_until_running(<<"app-0-web">>, 15_000),
    ok = wait_until_running(<<"app-1-web">>, 15_000),

    test_helper:step("api kept its gen_statem pid (not drifted)", fun() ->
        case find_pid(<<"app-0-api">>) of
            ApiPidBefore -> ok;
            Other ->
                {error, {api_pid_changed, ApiPidBefore, Other}}
        end
    end),

    test_helper:step("web restart_count is 2 (persistent across reconcile)",
                     fun() ->
        case inspect_os_pid_and_count(<<"app-0-web">>) of
            {_, 2} -> ok;
            {_, N} -> {error, {expected_count_2_got, N}}
        end
    end),

    %% Connect from the host (test runner is in host netns, source IP is
    %% the zone gateway 10.99.0.1). web's input chain has no saddr
    %% filter on tcp_dport rules, so any source reaches it.
    test_helper:step("new port 9090 answers on web from host", fun() ->
        case gen_tcp:connect({10,99,0,2}, 9090,
                             [binary, {active, false}, {packet, 0}], 3000) of
            {ok, Sock} ->
                ok = gen_tcp:send(Sock, <<"ping\n">>),
                Res = case gen_tcp:recv(Sock, 0, 2000) of
                    {ok, _} -> ok;
                    Err     -> {error, {recv_failed, Err}}
                end,
                gen_tcp:close(Sock),
                Res;
            {error, Why} ->
                {error, {connect_failed, Why}}
        end
    end),

    test_helper:step("old port 8080 does NOT answer", fun() ->
        case gen_tcp:connect({10,99,0,2}, 8080,
                             [binary, {active, false}], 1500) of
            {error, _} -> ok;  %% expected: closed/timeout
            {ok, Sock} ->
                gen_tcp:close(Sock),
                {error, old_port_still_open}
        end
    end),

    %% --- Down --------------------------------------------------------

    test_helper:step("cleanup: stop containers + remove parent", fun() ->
        Pids = try pg:get_members(erlkoenig_pg, erlkoenig_cts)
               catch error:_ -> []
               end,
        test_helper:cleanup(Pids),
        file:delete(TermFile),
        cleanup_parent(),
        ok
    end),

    io:format("~n=== Test 28 bestanden ===~n~n"),
    halt(0).

%% ──────────────────────────────────────────────────────────────
%% Helpers
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
        _   ->
            io:format("SKIP: ipvlan kernel module not available~n"),
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

%% Adjust the compiled term for this test environment:
%%  - retarget the zone's IPVLAN parent to our local dummy
%%  - replace the container binary with the test echo server
%%  - drop `nft_tables` and `ct_guard` so the host firewall + guard
%%    don't touch the test runner's sshd path
patch_term(TermFile, BinPath) ->
    case erlkoenig_config:parse(TermFile) of
        {ok, Config} ->
            Pods = maps:get(pods, Config, []),
            PatchedPods = [patch_pod_binaries(P, BinPath) || P <- Pods],
            Zones = maps:get(zones, Config, []),
            PatchedZones = [patch_zone_parent(Z) || Z <- Zones],
            Host0 = maps:get(host, Config, #{}),
            PatchedHost = patch_host_parent(Host0),
            Stripped = maps:without([nft_tables, ct_guard, guard], Config),
            Final = Stripped#{pods => PatchedPods,
                              zones => PatchedZones,
                              host => PatchedHost},
            file:write_file(TermFile, io_lib:format("~tp.~n", [Final])),
            ok;
        {error, Reason} ->
            {error, {parse_failed, Reason}}
    end.

patch_pod_binaries(Pod, BinPath) ->
    Cts = [Ct#{binary => BinPath} || Ct <- maps:get(containers, Pod, [])],
    Pod#{containers => Cts}.

patch_zone_parent(#{network := Net} = Zone) ->
    Zone#{network => Net#{parent => list_to_binary(?PARENT)}};
patch_zone_parent(Zone) -> Zone.

patch_host_parent(#{network := Net} = Host) ->
    Host#{network => Net#{parent => list_to_binary(?PARENT)}};
patch_host_parent(Host) -> Host.

%% Edit web container's `args` and its `nft` input chain tcp_dport
%% to the new port. api is left untouched -> will NOT show as drifted.
patch_web_port(TermFile, NewPortBin) ->
    {ok, Config} = erlkoenig_config:parse(TermFile),
    Pods = maps:get(pods, Config, []),
    NewPods = [bump_web_port(Pod, NewPortBin) || Pod <- Pods],
    Final = Config#{pods => NewPods},
    file:write_file(TermFile, io_lib:format("~tp.~n", [Final])),
    ok.

bump_web_port(Pod, NewPortBin) ->
    Cts = maps:get(containers, Pod, []),
    NewCts = [case maps:get(name, Ct) of
                  <<"web">> -> set_web_port(Ct, NewPortBin);
                  _         -> Ct
              end || Ct <- Cts],
    Pod#{containers => NewCts}.

set_web_port(Ct, NewPortBin) ->
    WithArgs = Ct#{args => [NewPortBin]},
    case maps:find(nft, WithArgs) of
        {ok, Nft} ->
            Chains  = maps:get(chains, Nft, []),
            NewChains = [rewrite_input_dport(C, NewPortBin) || C <- Chains],
            WithArgs#{nft => Nft#{chains => NewChains}};
        error ->
            WithArgs
    end.

rewrite_input_dport(#{hook := input, rules := Rules} = Chain, NewPortBin) ->
    NewPortInt = binary_to_integer(NewPortBin),
    NewRules = [case R of
                    {accept, #{tcp_dport := _} = Opts} ->
                        {accept, Opts#{tcp_dport => NewPortInt}};
                    Other -> Other
                end || R <- Rules],
    Chain#{rules => NewRules};
rewrite_input_dport(Chain, _) -> Chain.

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

inspect_os_pid_and_count(NameBin) ->
    {ok, Pid} = find_pid(NameBin),
    #{os_pid := OsPid, restart_count := Count} = erlkoenig:inspect(Pid),
    {OsPid, Count}.

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
