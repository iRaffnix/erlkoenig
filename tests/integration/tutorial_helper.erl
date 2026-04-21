%%% tutorial_helper.erl — shared plumbing for tutorial integration tests 46–51.
%%%
%%% The 6 tutorial files under examples/tutorial/ each declare a
%%% complete erlkoenig stack: host, zones, pods, nft, guard. The
%%% integration tests compile them via mix, patch the placeholder
%%% binary path + parent dummy names so they work on any host, load
%%% the term, wait for containers to reach `running`, and assert
%%% runtime state against the tutorial's @moduledoc promise.
%%%
%%% This module centralises the plumbing every test needs so each
%%% escript only has to describe its own assertions.
-module(tutorial_helper).

-export([compile_dsl/3,
         patch_term/2,
         load_and_wait/3,
         find_pid/1,
         find_pids_by_pod/1,
         host_ruleset/0,
         ct_ruleset/1,
         ensure_dummy/2,
         cleanup_dummy/1,
         cleanup_all/0,
         shell_quote/1]).

%% ============================================================
%% DSL compile: .exs → .term via mix
%% ============================================================

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

%% ============================================================
%% Term patching — make the tutorial runnable on this host
%%
%% Each tutorial hard-codes:
%%   * /opt/erlkoenig/rt/demo/test-erlkoenig-echo_server for binaries
%%   * `ek_<name>` dummy parents per zone
%%
%% Patching replaces all container binaries with test_helper:demo,
%% and maps tutorial parents to a single test parent (one per zone).
%% ============================================================

patch_term(TermFile, #{binary := BinPath, parents := Parents}) ->
    {ok, Config0} = erlkoenig_config:parse(TermFile),

    %% 1. Binary paths: every container → BinPath
    Pods0 = maps:get(pods, Config0, []),
    Pods1 = [patch_pod_binaries(P, BinPath) || P <- Pods0],

    %% 2. Parent dummy names: original → test-scoped
    Host0 = maps:get(host, Config0, #{}),
    Zones0 = maps:get(zones, Config0, []),
    Host1 = remap_host_parent(Host0, Parents),
    Zones1 = [remap_zone_parent(Z, Parents) || Z <- Zones0],

    Config1 = Config0#{pods => Pods1, host => Host1, zones => Zones1},
    Formatted = io_lib:format("~tp.~n", [Config1]),
    ok = file:write_file(TermFile, Formatted),
    ok.

patch_pod_binaries(Pod, BinPath) ->
    Containers = maps:get(containers, Pod, []),
    Patched = [C#{binary => BinPath} || C <- Containers],
    Pod#{containers => Patched}.

remap_host_parent(#{network := #{parent := Original} = Net} = Host, Parents) ->
    case maps:find(Original, Parents) of
        {ok, NewParent} ->
            Host#{network => Net#{parent => NewParent}};
        error ->
            Host
    end;
remap_host_parent(Host, _) -> Host.

remap_zone_parent(#{network := #{parent := Original} = Net} = Zone, Parents) ->
    case maps:find(Original, Parents) of
        {ok, NewParent} ->
            Zone#{network => Net#{parent => NewParent}};
        error ->
            Zone
    end;
remap_zone_parent(Zone, _) -> Zone.

%% ============================================================
%% Dummy parent lifecycle
%% ============================================================

ensure_dummy(Name, Cidr) ->
    os:cmd("ip link del " ++ binary_to_list(Name) ++ " 2>/dev/null"),
    os:cmd("ip link add " ++ binary_to_list(Name) ++ " type dummy"),
    os:cmd("ip addr add " ++ Cidr ++ " dev " ++ binary_to_list(Name)),
    os:cmd("ip link set " ++ binary_to_list(Name) ++ " up"),
    ok.

cleanup_dummy(Name) ->
    os:cmd("ip link del " ++ binary_to_list(Name) ++ " 2>/dev/null"),
    %% Host-side slave (ensure_dummy creates one for inbound host→ct)
    os:cmd("ip link del h." ++ binary_to_list(Name) ++ " 2>/dev/null"),
    ok.

%% Force-teardown every erlkoenig container, flush nft state,
%% destroy every ipvlan slave. Used at start + end of each test.
cleanup_all() ->
    Pids = case persistent_term:get({?MODULE, loaded_pids}, undefined) of
        undefined ->
            try pg:get_members(erlkoenig_pg, erlkoenig_cts)
            catch error:_ -> [] end;
        Named -> [P || {_, P} <- Named]
    end,
    lists:foreach(fun(P) -> catch erlkoenig:stop(P) end, Pids),
    _ = persistent_term:erase({?MODULE, loaded_pids}),
    timer:sleep(500),
    %% Flush any remaining ipvlan slaves (they carry IPs that block
    %% respawn).  The `ipv.` prefix is the erlkoenig convention.
    _ = os:cmd("for l in $(ip -o link show | awk -F': ' '/ipv\\./ {print $2}'); do "
               "ip link del $l 2>/dev/null; done"),
    ok.

%% ============================================================
%% Load + wait for N containers to reach running
%% ============================================================

load_and_wait(TermFile, ExpectedN, TimeoutMs) ->
    case erlkoenig_config:load(TermFile) of
        {ok, NamedPids} when length(NamedPids) =:= ExpectedN ->
            Pids = [P || {_, P} <- NamedPids],
            persistent_term:put({?MODULE, loaded_pids}, NamedPids),
            wait_for_running(Pids, ExpectedN, TimeoutMs);
        {ok, Other} ->
            {error, {expected_n, ExpectedN, got, length(Other), Other}};
        {error, Reason} ->
            {error, {load_failed, Reason}}
    end.

wait_for_running(Pids, N, TimeoutMs) ->
    Dl = erlang:system_time(millisecond) + TimeoutMs,
    wait_for_running_loop(Pids, N, Dl).

wait_for_running_loop(Pids, N, Dl) ->
    case running_count(Pids) of
        N -> ok;
        C ->
            case erlang:system_time(millisecond) > Dl of
                true -> {error, {timeout_waiting_for_running, N, C,
                                 [container_state(P) || P <- Pids]}};
                false -> timer:sleep(300),
                         wait_for_running_loop(Pids, N, Dl)
            end
    end.

running_count(Pids) ->
    length([P || P <- Pids, container_running(P)]).

container_running(Pid) ->
    try erlkoenig:inspect(Pid) of
        #{state := running} -> true;
        _ -> false
    catch _:_ -> false
    end.

container_state(Pid) ->
    try erlkoenig:inspect(Pid) of
        #{name := N, state := S} = Info ->
            {N, S, maps:get(error, Info, undefined)};
        {error, not_found} ->
            {Pid, gone, not_found};
        Other ->
            {Pid, unknown, Other}
    catch _:_ -> {Pid, crashed, undefined}
    end.

%% ============================================================
%% Pid discovery by name / pod
%% ============================================================

find_pid(NameBin) ->
    %% First try the cached pid list (fast, authoritative for the
    %% originally-loaded set).  If that pid is dead (container was
    %% killed and respawned by the supervisor with a NEW pid), fall
    %% back to scanning pg for a currently-alive container with the
    %% same name.
    case lists:keyfind(NameBin, 1, loaded_pids()) of
        {_, Pid} when is_pid(Pid) ->
            case is_process_alive(Pid) of
                true  -> {ok, Pid};
                false -> find_pid_via_pg(NameBin)
            end;
        false ->
            find_pid_via_pg(NameBin)
    end.

find_pid_via_pg(NameBin) ->
    Pids = try pg:get_members(erlkoenig_pg, erlkoenig_cts)
           catch error:_ -> [] end,
    case lists:filter(
           fun(P) ->
               try erlkoenig:inspect(P) of
                   #{name := N} -> N =:= NameBin;
                   _ -> false
               catch _:_ -> false end
           end, Pids) of
        [P | _] -> {ok, P};
        []      -> not_found
    end.

%% Returns [{Name, Pid}] for every running container whose name
%% starts with `<PodName>-`.
find_pids_by_pod(PodNameBin) ->
    Prefix = <<PodNameBin/binary, "-">>,
    PSize = byte_size(Prefix),
    lists:filter(fun({N, _Pid}) ->
        case N of
            <<Prefix:PSize/binary, _/binary>> -> true;
            _ -> false
        end
    end, loaded_pids()).

loaded_pids() ->
    %% Prefer the list we captured from erlkoenig_config:load/1 — it
    %% is authoritative and avoids the pg-scope-miss race seen when
    %% running single escripts in isolation.  Fall back to pg for
    %% callers that skipped load_and_wait.
    case persistent_term:get({?MODULE, loaded_pids}, undefined) of
        undefined ->
            try pg:get_members(erlkoenig_pg, erlkoenig_cts) of
                Pids -> [{inspect_name(P), P} || P <- Pids]
            catch error:_ -> [] end;
        Named -> Named
    end.

inspect_name(P) ->
    try erlkoenig:inspect(P) of
        #{name := N} -> N
    catch _:_ -> <<"?">>
    end.

%% ============================================================
%% nft ruleset dumps
%% ============================================================

host_ruleset() ->
    os:cmd("nft list ruleset 2>&1").

ct_ruleset(Pid) when is_pid(Pid) ->
    case erlkoenig:inspect(Pid) of
        #{os_pid := OsPid} ->
            os:cmd(io_lib:format(
                     "nsenter --target ~B --net nft list ruleset 2>&1",
                     [OsPid]));
        _ ->
            ""
    end.

%% ============================================================
%% Misc
%% ============================================================

shell_quote(S) ->
    Escaped = lists:flatten(
                [case C of
                     $' -> "'\\''";
                     Other -> Other
                 end || C <- S]),
    "'" ++ Escaped ++ "'".
