%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%

-module(erlkoenig_config_spawn).
-moduledoc """
Translate flattened container specs into runtime spawn opts and
start the containers — individually or grouped under pod
supervisors.

`spawn_pods/2' groups by `{pod, pod_instance}' and calls
`erlkoenig_sup:start_pod/3' when there is a real pod; standalone
containers go straight through `erlkoenig:spawn/2'.

`build_spawn_opts/1' is the Glasbox-critical seam for capability
fields: its `Keys' list decides which DSL fields travel from the
flattened container spec into the runtime. Bug #64 in the
97-bug sweep lived here — any DSL field we forget to copy gets
silently dropped at spawn time. Keep the list in sync when new
capability surfaces are added.

`maybe_add_health_check/2' arms the post-spawn health-check
timer if the container declares one.
""".

-export([
    spawn_pods/2,
    spawn_container/1,
    build_spawn_opts/1,
    maybe_add_health_check/2
]).

%% Group containers by pod instance and start via pod supervisors.
%% Containers without a pod field are started individually (isolated).
-spec spawn_pods([map()], [map()]) -> [{binary(), pid()}].
spawn_pods(Containers, PodDefs) ->
    %% Build strategy lookup: PodName → OTP strategy
    StrategyMap = lists:foldl(fun(PodDef, Acc) ->
        PodName = iolist_to_binary(maps:get(name, PodDef, <<>>)),
        Strategy = maps:get(strategy, PodDef, one_for_one),
        Acc#{PodName => Strategy}
    end, #{}, PodDefs),

    %% Group by {pod, pod_instance}
    Groups = lists:foldl(fun(Ct, Acc) ->
        Key = case {maps:get(pod, Ct, undefined), maps:get(pod_instance, Ct, undefined)} of
            {undefined, _} -> {standalone, iolist_to_binary(maps:get(name, Ct))};
            {Pod, Inst}    -> {iolist_to_binary(Pod), Inst}
        end,
        maps:update_with(Key, fun(L) -> L ++ [Ct] end, [Ct], Acc)
    end, #{}, Containers),

    %% Start each group
    lists:flatmap(fun({{standalone, _Name}, [Ct]}) ->
        case spawn_container(Ct) of
            {true, Result} -> [Result];
            false -> []
        end;
    ({{PodName, Inst}, Cts}) ->
        PodInstName = <<PodName/binary, "-", (integer_to_binary(Inst))/binary>>,
        Strategy = maps:get(PodName, StrategyMap, one_for_one),
        Children = [{iolist_to_binary(maps:get(binary, Ct)), build_spawn_opts(Ct)}
                    || Ct <- Cts],
        %% Build name→index mapping from Cts list
        CtNames = [iolist_to_binary(maps:get(name, Ct)) || Ct <- Cts],
        case erlkoenig_sup:start_pod(PodInstName, Strategy, Children) of
            {ok, PodPid} ->
                logger:info("erlkoenig_config: started pod ~s (strategy=~p, ~p containers)",
                            [PodInstName, Strategy, length(Children)]),
                %% Collect child PIDs — match by position (same order as Children)
                ChildPids = supervisor:which_children(PodPid),
                %% which_children returns in reverse start order
                OrderedPids = lists:reverse([Pid || {_, Pid, _, _} <- ChildPids,
                                                    is_pid(Pid)]),
                [{N, P} || {N, P} <- lists:zip(CtNames, OrderedPids)];
            {error, Reason} ->
                logger:warning("erlkoenig_config: failed to start pod ~s: ~p",
                               [PodInstName, Reason]),
                []
        end
    end, maps:to_list(Groups)).

-spec spawn_container(map()) -> {true, {binary(), pid()}} | false.
spawn_container(#{name := Name, binary := Binary} = Ct) ->
    SpawnOpts = build_spawn_opts(Ct),
    BinPath = iolist_to_binary(Binary),
    case erlkoenig:spawn(BinPath, SpawnOpts) of
        {ok, Pid} ->
            logger:info("erlkoenig_config: spawned ~s (~p)", [Name, Pid]),
            maybe_add_health_check(Pid, Ct),
            {true, {iolist_to_binary(Name), Pid}};
        {error, Reason} ->
            logger:warning("erlkoenig_config: failed to spawn ~s: ~p",
                           [Name, Reason]),
            false
    end.

-spec build_spawn_opts(map()) -> map().
build_spawn_opts(Ct) ->
    %% Capability-driven fields must travel through too — without
    %% them the DSL `requires :"..."` declarations emit their side
    %% effects into the term but `erlkoenig_ct' never sees them at
    %% spawn time, so e.g. `dns.allowlist' doesn't register and
    %% `journal.local' doesn't get its socket bind-mount. That is
    %% exactly the failure mode that integration test 32 catches.
    Keys = [ip, ports, args, env, firewall, limits, seccomp,
            restart, name, files, zone, volumes, image_path,
            publish, stream, nft,
            %% capability surfaces:
            requires, socket_mounts, dns_allowlist,
            %% PKI / signature gating (SPEC-EK-017):
            %% `signature_required' forces per-container enforcement
            %% even when the global PKI mode is `off'.  `sig_path' is
            %% the explicit detached-signature location.
            signature_required, sig_path,
            %% cgroup user/group IDs (Pod.Builder emits these):
            uid, gid,
            %% internal but reachable via pod-supervisor code path:
            pod_supervised,
            %% PTY is internal-only (no DSL surface) but reach the
            %% runtime via manual-opts callers (tests, CLI):
            pty],
    lists:foldl(fun(K, Acc) -> copy_if(K, Ct, Acc) end, #{}, Keys).

-spec copy_if(atom(), map(), map()) -> map().
copy_if(Key, From, To) ->
    case maps:find(Key, From) of
        {ok, Val} -> maps:put(Key, Val, To);
        error -> To
    end.

-spec maybe_add_health_check(pid(), map()) -> ok.
maybe_add_health_check(Pid, #{health_check := Opts}) when is_map(Opts) ->
    %% Small delay so the container has time to bind its port
    _ = timer:apply_after(2000, erlkoenig_health, add, [Pid, Opts]),
    ok;
maybe_add_health_check(_Pid, _Ct) ->
    ok.
