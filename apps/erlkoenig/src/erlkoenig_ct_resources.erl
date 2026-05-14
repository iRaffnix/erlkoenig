%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%

-module(erlkoenig_ct_resources).
-moduledoc """
External-resource register / unregister helpers for the container
gen_statem.

These functions announce the container's existence to the rest
of the node (DNS, dns-filter, DETS, audit) when the container
enters `running' and retract the announcements when it leaves.
They are the counterparts of the setup/teardown flow in
`erlkoenig_ct' — pulling them out makes the `stopped`/`failed'
state-entry callbacks readable as a short cleanup checklist.

Each helper is tolerant of the relevant target service being
down (DNS, volume_store, node_state) so the state machine can
keep progressing even when a peer gen_server crashes at the
wrong moment.

Functions:

  DNS:              dns_register/1,   dns_unregister/1
  DNS filter:       dns_filter_register/1, dns_filter_unregister/1
  DETS state:       dets_register/1,  dets_unregister/1
  Topology derived: netns_path/1, cgroup_path_for_id/1
  Socket cleanup:   safe_sock_close/1, cleanup_socket_file/1
  Volume audit:     audit_volumes_mounted/1, audit_volumes_released/1
  Volume cleanup:   cleanup_ephemeral_volumes/1
  IP pool:          release_ip/1
""".

-include("erlkoenig_ct_state.hrl").

-export([
    %% DNS
    dns_register/1,
    dns_unregister/1,
    %% DNS filter
    dns_filter_register/1,
    dns_filter_unregister/1,
    %% DETS state
    dets_register/1,
    dets_unregister/1,
    %% Topology helpers (kept here because dets_register uses them)
    netns_path/1,
    cgroup_path_for_id/1,
    %% Socket cleanup
    safe_sock_close/1,
    cleanup_socket_file/1,
    %% Volume audit + cleanup
    audit_volumes_mounted/1,
    audit_volumes_released/1,
    cleanup_ephemeral_volumes/1,
    %% IP pool
    release_ip/1
]).

%% -- DNS registration ---------------------------------------------

-spec dns_register(#ct_data{}) -> ok.
dns_register(#ct_data{ip = undefined}) -> ok;
dns_register(#ct_data{name = Name, id = Id, ip = Ip, zone = Zone}) ->
    DnsName = case Name of
        undefined -> Id;
        _         -> Name
    end,
    try
        DnsPid = erlkoenig_zone:dns(Zone),
        gen_server:call(DnsPid, {register, DnsName, Ip})
    catch Class:Reason ->
        logger:warning("container ~s: DNS register failed: ~p:~p",
                       [Id, Class, Reason])
    end,
    ok.

-spec dns_unregister(#ct_data{}) -> ok.
dns_unregister(#ct_data{ip = undefined}) -> ok;
dns_unregister(#ct_data{name = Name, id = Id, zone = Zone}) ->
    DnsName = case Name of
        undefined -> Id;
        _         -> Name
    end,
    try
        DnsPid = erlkoenig_zone:dns(Zone),
        gen_server:call(DnsPid, {unregister, DnsName})
    catch Class:Reason ->
        logger:warning("container ~s: DNS unregister failed: ~p:~p",
                       [Id, Class, Reason])
    end,
    ok.

%% -- DNS egress allowlist (SPEC-AS-009) ---------------------------
%%
%% Container spawned with `requires :"dns.allowlist", hosts: [...]` →
%% the DSL emits `dns_allowlist => [Host, ...]` in the spawn opts;
%% we register that against the container's IP at `running' so the
%% per-zone DNS can deny everything outside the list. Unregister at
%% `stopped' so a recycled IP doesn't inherit the previous tenant's
%% policy.

-spec dns_filter_register(#ct_data{}) -> ok.
dns_filter_register(#ct_data{dns_allowlist = undefined}) -> ok;
dns_filter_register(#ct_data{ip = undefined}) -> ok;
dns_filter_register(#ct_data{ip = Ip, dns_allowlist = Hosts, id = Id}) ->
    try
        ok = erlkoenig_dns_filter:register_allowlist(Ip, Hosts)
    catch Class:Reason ->
        logger:warning("container ~s: dns_filter register failed: ~p:~p",
                       [Id, Class, Reason])
    end,
    ok.

-spec dns_filter_unregister(#ct_data{}) -> ok.
dns_filter_unregister(#ct_data{dns_allowlist = undefined}) -> ok;
dns_filter_unregister(#ct_data{ip = undefined}) -> ok;
dns_filter_unregister(#ct_data{ip = Ip, id = Id}) ->
    try
        ok = erlkoenig_dns_filter:unregister(Ip)
    catch Class:Reason ->
        logger:warning("container ~s: dns_filter unregister failed: ~p:~p",
                       [Id, Class, Reason])
    end,
    ok.

%% -- DETS state persistence ----------------------------------------

-spec dets_register(#ct_data{}) -> ok.
dets_register(#ct_data{id = Id, os_pid = OsPid, socket_path = SocketPath,
                        ip = Ip, zone = Zone, binary_path = BinaryPath,
                        net_info = NetInfo,
                        firewall = Firewall, restart = Restart,
                        limits = Limits, seccomp = Seccomp,
                        caps_keep = CapsKeep, name = Name,
                        args = Args, env = Env, uid = Uid, gid = Gid,
                        extra_opts = ExtraOpts, volumes = Volumes} = _Data) ->
    case whereis(erlkoenig_node_state) of
        undefined -> ok;
        _ ->
            Iface = case NetInfo of
                #{iface := I} -> I;
                _ -> undefined
            end,
            Attach = case NetInfo of
                #{attach := A} -> A;
                _ -> undefined
            end,
            CgroupPath = cgroup_path_for_id(Id),
            Config = #{
                args => Args,
                env => Env,
                uid => Uid,
                gid => Gid,
                zone => Zone,
                restart => Restart,
                limits => Limits,
                seccomp => Seccomp,
                caps_keep => CapsKeep,
                name => Name,
                firewall => Firewall,
                extra_opts => ExtraOpts,
                volumes => Volumes
            },
            Info = #{
                os_pid => OsPid,
                socket_path => SocketPath,
                ip => Ip,
                netns => netns_path(OsPid),
                cgroup => CgroupPath,
                iface => Iface,
                attach => Attach,
                zone => Zone,
                binary_path => BinaryPath,
                config => Config,
                started_at => erlang:system_time(second)
            },
            try erlkoenig_node_state:register_container(Id, Info)
            catch _:_ -> ok
            end
    end,
    ok.

-spec dets_unregister(#ct_data{}) -> ok.
dets_unregister(#ct_data{id = Id}) ->
    case whereis(erlkoenig_node_state) of
        undefined -> ok;
        _ ->
            try erlkoenig_node_state:unregister_container(Id)
            catch _:_ -> ok
            end
    end,
    ok.

-spec netns_path(non_neg_integer() | undefined) -> binary() | undefined.
netns_path(undefined) -> undefined;
netns_path(Pid) when is_integer(Pid), Pid > 0 ->
    list_to_binary("/proc/" ++ integer_to_list(Pid) ++ "/ns/net");
netns_path(_) -> undefined.

-spec cgroup_path_for_id(binary()) -> binary().
cgroup_path_for_id(Id) ->
    try
        case erlkoenig_cgroup:path(Id) of
            {ok, Path} -> list_to_binary(Path);
            _ -> <<>>
        end
    catch _:_ ->
        <<>>
    end.

%% -- Socket cleanup -----------------------------------------------

-spec safe_sock_close(gen_tcp:socket() | undefined) -> ok.
safe_sock_close(undefined) -> ok;
safe_sock_close(Sock) ->
    gen_tcp:close(Sock),
    ok.

-spec cleanup_socket_file(binary() | undefined) -> ok.
cleanup_socket_file(undefined) -> ok;
cleanup_socket_file(Path) ->
    _ = file:delete(Path),
    ok.

%% -- Volume audit -------------------------------------------------

-spec audit_volumes_mounted(#ct_data{}) -> ok.
audit_volumes_mounted(#ct_data{volumes = []}) -> ok;
audit_volumes_mounted(#ct_data{id = Id, name = Name, volumes = Volumes}) ->
    ContainerName = case Name of undefined -> Id; N -> N end,
    lists:foreach(fun(V) -> audit_one_volume(ContainerName, V) end, Volumes),
    ok.

audit_one_volume(ContainerName, #{kind := socket_mount, host := Host,
                                   container := ContPath,
                                   read_only := RO}) ->
    erlkoenig_audit:log(#{
        type => socket_mount_bound,
        subject => ContainerName,
        result => ok,
        details => #{kind => socket_mount,
                     host => Host,
                     container_path => ContPath,
                     read_only => RO}
    });
audit_one_volume(ContainerName, #{host := Host, container := ContPath,
                                   persist := Persist, read_only := RO}) ->
    erlkoenig_audit:log(#{
        type => volume_mounted,
        subject => ContainerName,
        result => ok,
        details => #{
            persist => Persist,
            host => Host,
            container_path => ContPath,
            read_only => RO
        }
    }).

-spec audit_volumes_released(#ct_data{}) -> ok.
audit_volumes_released(#ct_data{volumes = []}) -> ok;
audit_volumes_released(#ct_data{id = Id, name = Name, volumes = Volumes}) ->
    ContainerName = case Name of undefined -> Id; N -> N end,
    lists:foreach(fun
        (#{kind := socket_mount}) ->
            %% Socket bind-mounts have no persistent state to release;
            %% they live and die with the container's mount namespace.
            ok;
        (#{persist := Persist}) ->
            erlkoenig_audit:log(#{
                type => volume_released,
                subject => ContainerName,
                result => ok,
                details => #{persist => Persist}
            })
    end, Volumes),
    ok.

%% Destroy ephemeral volumes belonging to this container. Called from
%% the stopped/failed state entry actions. Persistent volumes are left
%% alone — they outlive their container by design.
-spec cleanup_ephemeral_volumes(#ct_data{}) -> ok.
cleanup_ephemeral_volumes(#ct_data{name = Name, id = Id}) ->
    ContainerName = case Name of
        undefined -> Id;
        N -> N
    end,
    %% This runs during the `stopped`/`failed' state-entry callback,
    %% which also fires in unit-test contexts where the volume store
    %% hasn't been started. Treat a missing store as "nothing to do"
    %% instead of propagating a noproc exit that would take the
    %% gen_statem (and any linked test fixtures) down with it.
    try erlkoenig_volume_store:cleanup_ephemeral(ContainerName) of
        {ok, []} -> ok;
        {ok, Destroyed} ->
            logger:info("container ~s: cleaned up ~p ephemeral volume(s): ~p",
                        [Id, length(Destroyed), Destroyed]),
            ok;
        {error, Reason} ->
            logger:warning("container ~s: ephemeral cleanup failed: ~p",
                           [Id, Reason]),
            ok
    catch
        exit:{noproc, _} ->
            %% volume_store not up (bare test VM) — no volumes to clean.
            ok;
        exit:{timeout, _} ->
            logger:warning("container ~s: volume_store timeout on cleanup",
                           [Id]),
            ok
    end.

%% -- IP pool ------------------------------------------------------

-spec release_ip(#ct_data{}) -> #ct_data{}.
release_ip(#ct_data{ip = undefined} = Data) ->
    Data;
release_ip(#ct_data{ip = Ip} = Data) ->
    erlkoenig_ip_pool:release(Ip),
    Data#ct_data{ip = undefined}.
