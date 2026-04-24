%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%

-module(erlkoenig_config_drift).
-moduledoc """
Reload-time drift detection between an old and a new config.

`detect_drifted/2' returns the names of containers whose
spec-affecting fields changed between two config files.  The
reconciler uses that list to decide which running containers
need a restart.

`container_differs/2' is the Glasbox seam: every field in its
`Keys' list causes a restart, every field NOT in the list gets
silently reused. A historical bug (#64) had this list missing
`env', `files', `firewall', `requires', `dns_allowlist',
`signature_required', `rootfs' — operators editing those fields
and calling reload saw the old spec keep running with no
warning. The current list covers every field that affects
container behaviour at spawn time; when a new spawn field is
added, add it here too.

`running_container_names/0' reads the `erlkoenig_cts' pg group
directly, so the set of "currently running" containers is
independent of any persisted config.
""".

-export([
    detect_drifted/2,
    containers_by_name/1,
    container_differs/2,
    running_container_names/0
]).

%% Compare two configs and return the names of containers whose
%% fields changed in a way that requires a restart.
%%
%% Fields considered meaningful for drift detection:
%%   binary, args, zone, limits, seccomp, uid, gid, caps,
%%   volumes, image, publish, stream, nft
%% Other fields (e.g. replicas) change the flattened container set
%% itself, so they show up as add/remove rather than drift.
-spec detect_drifted(map() | undefined, map()) -> [binary()].
detect_drifted(undefined, _New) ->
    [];
detect_drifted(OldConfig, NewConfig) ->
    OldByName = containers_by_name(OldConfig),
    NewByName = containers_by_name(NewConfig),
    maps:fold(fun(Name, NewCt, Acc) ->
        case maps:find(Name, OldByName) of
            {ok, OldCt} ->
                case container_differs(OldCt, NewCt) of
                    true  -> [Name | Acc];
                    false -> Acc
                end;
            error ->
                Acc
        end
    end, [], NewByName).

-spec containers_by_name(map()) -> #{binary() => map()}.
containers_by_name(Config) ->
    lists:foldl(fun(C, Acc) ->
        Name = iolist_to_binary(maps:get(name, C)),
        Acc#{Name => C}
    end, #{}, erlkoenig_config_flatten:flatten_containers(Config)).

-spec container_differs(map(), map()) -> boolean().
container_differs(Old, New) ->
    %% Keys that require a restart to take effect. The original list
    %% silently omitted `env', `files', `firewall', `requires',
    %% `dns_allowlist', `signature_required', `rootfs' — operators
    %% editing any of those in the DSL + calling reload saw the
    %% container keep running with the OLD spec and got no warning.
    %% Classic Muster-3: DSL accepts the change, config apply
    %% silently ignores it.
    %%
    %% The list below covers every field that affects container
    %% behavior at spawn time. Fields that alter the flattened
    %% container set (name, replicas) show up as add/remove instead.
    Keys = [binary, args, env, files, zone, limits, seccomp,
            uid, gid, caps, volumes, image, rootfs,
            publish, stream, nft, firewall, restart,
            requires, dns_allowlist, signature_required],
    lists:any(fun(K) ->
        maps:get(K, Old, undefined) =/= maps:get(K, New, undefined)
    end, Keys).

%% Names of currently-running containers, derived from the `erlkoenig_cts'
%% process group. This is the authoritative runtime state, independent
%% of any persisted config. Used by reconciliation to decide which
%% containers are new (ToStart) and which are removed (ToStop).
-spec running_container_names() -> [binary()].
running_container_names() ->
    Pids = try pg:get_members(erlkoenig_pg, erlkoenig_cts)
           catch _:_ -> []
           end,
    lists:filtermap(fun(Pid) ->
        try erlkoenig_ct:get_info(Pid) of
            #{name := Name} when is_binary(Name) -> {true, Name};
            #{name := Name} -> {true, iolist_to_binary(Name)};
            _ -> false
        catch _:_ -> false
        end
    end, Pids).
