#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 24: Tier-Isolation via per-container nft in netns.
%%
%% Nimmt examples/three_tier_ipvlan.exs, patched die binary-Pfade,
%% lädt den Stack und prüft die Konnektivitätsmatrix:
%%
%%   ALLOWED            BLOCKED
%%   ─────────────      ───────────────────────
%%   nginx → api:4000   nginx → pg:5432
%%   api   → pg:5432    nginx → api:8443 (falscher Port)
%%   any   → gw ICMP    api   → nginx:8443
%%                      pg    → api:4000
%%                      pg    → nginx:8443
%%
%% Prüft damit dass das DSL-Example genau das tut was seine Doku sagt.
%% Braucht sudo, ein freies /24-Subnet und `ipvlan` kernel-Modul.
-mode(compile).

-define(PARENT, "ek_ct0").
-define(SUBNET, "10.50.100.0/24").
-define(GW_IP, "10.50.100.1").
-define(SUBNET_GW, ?GW_IP "/24").

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 24: Tier-Isolation ===~n~n"),

    require_root(),
    require_ipvlan_module(),

    test_helper:boot(),
    logger:set_primary_config(level, warning),

    Root     = test_helper:project_root(),
    Example  = filename:join(Root, "examples/three_tier_ipvlan.exs"),
    TermFile = "/tmp/erlkoenig_integration_24.term",
    DemoBin  = binary_to_list(test_helper:demo("echo_server")),

    ensure_parent(),

    test_helper:step("mix compile .exs -> .term", fun() ->
        compile_dsl(Root, Example, TermFile)
    end),

    test_helper:step("parse + patch binary paths", fun() ->
        patch_term(TermFile, list_to_binary(DemoBin))
    end),

    test_helper:step("erlkoenig_config:load/1", fun() ->
        case erlkoenig_config:load(TermFile) of
            {ok, Pids} when length(Pids) >= 5 ->
                io:format("    spawned ~p container(s)~n", [length(Pids)]),
                ok;
            {ok, Other} ->
                {error, {expected_5_got, length(Other)}};
            {error, Reason} ->
                {error, {load_failed, Reason}}
        end
    end),

    %% Wait for all containers to reach running state.
    test_helper:step("wait for 5 running", fun() ->
        wait_for_containers(5, 30_000)
    end),

    %% The container names in the pod.strategy=one_for_one setup:
    %%   replicas=3 nginx: three_tier-0-nginx, three_tier-1-nginx, three_tier-2-nginx
    %%   replicas=1 api:   three_tier-0-api
    %%   replicas=1 pg:    three_tier-0-postgres
    Nginx0 = <<"three_tier-0-nginx">>,
    Api    = <<"three_tier-0-api">>,
    Pg     = <<"three_tier-0-postgres">>,

    %% Give the per-container nft batches a moment to settle in netns.
    timer:sleep(1500),

    %% ── Erlaubte Pfade ─────────────────────────────────────────
    test_helper:step("ALLOW nginx -> api:4000", fun() ->
        expect_reachable(Nginx0, "10.50.100.5", 4000)
    end),
    test_helper:step("ALLOW api -> pg:5432", fun() ->
        expect_reachable(Api, "10.50.100.6", 5432)
    end),
    test_helper:step("ALLOW any -> gateway icmp", fun() ->
        expect_pingable(Nginx0, ?GW_IP)
    end),

    %% ── Verbotene Pfade ─────────────────────────────────────────
    test_helper:step("BLOCK nginx -> pg:5432", fun() ->
        expect_blocked(Nginx0, "10.50.100.6", 5432)
    end),
    test_helper:step("BLOCK nginx -> nginx1:8443 (web-to-web)", fun() ->
        expect_blocked(Nginx0, "10.50.100.3", 8443)
    end),
    test_helper:step("BLOCK api -> nginx:8443 (reverse)", fun() ->
        expect_blocked(Api, "10.50.100.2", 8443)
    end),
    test_helper:step("BLOCK pg -> api:4000 (reverse)", fun() ->
        expect_blocked(Pg, "10.50.100.5", 4000)
    end),
    test_helper:step("BLOCK pg -> nginx:8443 (reverse)", fun() ->
        expect_blocked(Pg, "10.50.100.2", 8443)
    end),

    %% Ensure the wrong-port case uses the normal TCP RST path, not
    %% our nft drop — otherwise this test proves nothing.
    test_helper:step("BLOCK nginx -> api:9999 (no listener, nft drops)", fun() ->
        expect_blocked(Nginx0, "10.50.100.5", 9999)
    end),

    test_helper:step("cleanup", fun() ->
        Pids = try pg:get_members(erlkoenig_pg, erlkoenig_cts)
               catch error:_ -> []
               end,
        test_helper:cleanup(Pids),
        file:delete(TermFile),
        cleanup_parent(),
        ok
    end),

    io:format("~n=== Test 24 bestanden ===~n~n"),
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
    %% Clean up any leftover state from a previous run, then create fresh.
    %% ek_ct0 is the IPVLAN parent; h.ek_ct0 is the host-side slave that
    %% erlkoenig_zone_link_ipvlan creates on first attach — wipe both so
    %% zone_link doesn't hit "File exists" on this run's attach.
    os:cmd("ip link del h." ?PARENT " 2>/dev/null"),
    os:cmd("ip link del " ?PARENT " 2>/dev/null"),
    "0" = exit_code(os:cmd("ip link add " ?PARENT " type dummy 2>&1; echo $?")),
    "0" = exit_code(os:cmd("ip addr add " ?SUBNET_GW " dev " ?PARENT " 2>&1; echo $?")),
    "0" = exit_code(os:cmd("ip link set " ?PARENT " up 2>&1; echo $?")),
    ok.

cleanup_parent() ->
    os:cmd("ip link del h." ?PARENT " 2>/dev/null"),
    os:cmd("ip link del " ?PARENT " 2>/dev/null"),
    ok.

compile_dsl(Root, Example, TermFile) ->
    DslDir = filename:join(Root, "dsl"),
    Snippet = io_lib:format(
                "[{mod, _} | _] = Code.compile_file(~p); "
                "mod.write!(~p)",
                [Example, TermFile]),
    Cmd = "cd " ++ DslDir ++
          " && MIX_ENV=test mix run --no-deps-check --no-compile -e " ++
          shell_quote(lists:flatten(Snippet)) ++ " 2>&1",
    Output = os:cmd(Cmd),
    case filelib:is_regular(TermFile) of
        true -> ok;
        false -> {error, {term_not_created, Output}}
    end.

patch_term(TermFile, BinPath) ->
    case erlkoenig_config:parse(TermFile) of
        {ok, Config} ->
            Pods = maps:get(pods, Config, []),
            PatchedPods = [begin
                Cts = [Ct#{binary => BinPath} || Ct <- maps:get(containers, P, [])],
                P#{containers => Cts}
            end || P <- Pods],
            %% Drop host-level firewall + guard from the test config.
            %% This test verifies PER-CONTAINER nft in their own netns;
            %% applying the example's host `nft_tables` (policy: drop on
            %% input with only 22222 accepted) would race with the SSH
            %% session that launched the test and lock out the operator.
            %% The test owns `ek_ct0` and its subnet — nothing host-wide.
            Stripped = maps:without([nft_tables, ct_guard, guard], Config),
            PatchedConfig = Stripped#{pods => PatchedPods},
            Formatted = io_lib:format("~tp.~n", [PatchedConfig]),
            file:write_file(TermFile, Formatted),
            ok;
        {error, Reason} ->
            {error, {parse_failed, Reason}}
    end.

wait_for_containers(N, TimeoutMs) ->
    wait_for_containers(N, TimeoutMs, erlang:system_time(millisecond)).

wait_for_containers(N, TimeoutMs, Start) ->
    Now = erlang:system_time(millisecond),
    case Now - Start > TimeoutMs of
        true ->
            Pids = try pg:get_members(erlkoenig_pg, erlkoenig_cts)
                   catch error:_ -> []
                   end,
            States = [try
                         I = erlkoenig:inspect(P),
                         {maps:get(name, I, <<"?">>), maps:get(state, I, unknown)}
                     catch _:_ -> {P, crashed}
                     end || P <- Pids],
            io:format("~n    states at timeout: ~p~n", [States]),
            {error, {timeout, N, States}};
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
                     wait_for_containers(N, TimeoutMs, Start)
            end
    end.

find_container_netns(NameBin) ->
    Pids = try pg:get_members(erlkoenig_pg, erlkoenig_cts)
           catch error:_ -> []
           end,
    Match = [Pid || Pid <- Pids,
                    try #{name := N} = erlkoenig:inspect(Pid),
                         N =:= NameBin
                    catch _:_ -> false end],
    case Match of
        [Pid | _] ->
            case erlkoenig:inspect(Pid) of
                #{netns_path := NS} when is_list(NS) -> {ok, NS};
                #{netns_path := NS} when is_binary(NS) -> {ok, binary_to_list(NS)};
                _ -> {error, no_netns}
            end;
        [] -> {error, {container_not_found, NameBin}}
    end.

expect_reachable(NameBin, DstIp, DstPort) ->
    case find_container_netns(NameBin) of
        {ok, NS} ->
            Cmd = io_lib:format(
                "timeout 2 nsenter --net=~s bash -c "
                "'echo > /dev/tcp/~s/~b' 2>&1; echo $?",
                [NS, DstIp, DstPort]),
            Out = os:cmd(lists:flatten(Cmd)),
            Code = last_line(Out),
            case Code of
                "0" -> ok;
                _   -> {error, {unexpectedly_blocked, Out}}
            end;
        {error, _} = E -> E
    end.

expect_blocked(NameBin, DstIp, DstPort) ->
    case find_container_netns(NameBin) of
        {ok, NS} ->
            Cmd = io_lib:format(
                "timeout 2 nsenter --net=~s bash -c "
                "'echo > /dev/tcp/~s/~b' 2>&1; echo $?",
                [NS, DstIp, DstPort]),
            Out = os:cmd(lists:flatten(Cmd)),
            Code = last_line(Out),
            case Code of
                "0" -> {error, {unexpectedly_reachable, Out}};
                _   -> ok  %% non-zero = blocked (SYN timeout or RST)
            end;
        {error, _} = E -> E
    end.

expect_pingable(NameBin, DstIp) ->
    case find_container_netns(NameBin) of
        {ok, NS} ->
            Cmd = io_lib:format(
                "nsenter --net=~s ping -c1 -W2 ~s >/dev/null 2>&1; echo $?",
                [NS, DstIp]),
            case string:trim(os:cmd(lists:flatten(Cmd))) of
                "0" -> ok;
                _   -> {error, not_pingable}
            end;
        {error, _} = E -> E
    end.

last_line(Str) ->
    Lines = [L || L <- string:split(string:trim(Str), "\n", all),
                  L =/= ""],
    case Lines of
        [] -> "";
        _  -> lists:last(Lines)
    end.

exit_code(Str) ->
    last_line(Str).

shell_quote(S) ->
    Escaped = lists:flatten(
                [case C of
                     $' -> "'\\''";
                     Other -> Other
                 end || C <- S]),
    "'" ++ Escaped ++ "'".
