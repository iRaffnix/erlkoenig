%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%

-module(erlkoenig_ct_net).
-moduledoc """
Container-side network + firewall lifecycle.

Owns the paired create/teardown of every network-y thing the
container gets when it transitions from `creating' → `running':

  * `do_container_net_setup/1' — the orchestrator that configures
    the IPVLAN slave, retries EADDRINUSE during pod respawn, then
    attaches the per-container firewall and optional nft_table,
    then sends `CMD_GO' to the C runtime.
  * `try_net_setup_with_retry/7' + `try_net_setup_loop/3' —
    EADDRINUSE retry wrapper.
  * `firewall_add/4' + `firewall_remove/1' — per-container nft
    chain lifecycle.
  * `maybe_apply_container_nft/1' — SPEC-EK-023 per-container
    nft_table with synchronous reply handling.
  * `teardown_veth/1' — paired with `setup_container_net'.
  * `write_container_files/2' — file injection (part of the
    pre-GO sequence, stays with the other pre-GO ops).
  * `zone_dns_ip/1', `ip4_to_u32/1', `effective_dns_ip/1' — DNS
    IP resolution for the spawn-time `/etc/resolv.conf' write.

The state machine itself still owns the transition tuples
(`{next_state, starting, _}' / `{next_state, failed, _}'). Only
the work that lives *under* the transition moved.

The extraction preserves the `skip_firewall` glasbox semantic and
the two separate `{error, {net_setup_failed, -98, _}}' match
shapes — the inner-wrapped form and the bare form — that the
original code had accreted for IPVLAN cleanup timing.
""".

-include("erlkoenig_ct_state.hrl").
-include("erlkoenig_error.hrl").

-export([
    do_container_net_setup/1,
    try_net_setup_with_retry/7,
    try_net_setup_loop/3,
    firewall_add/4,
    firewall_remove/1,
    maybe_apply_container_nft/1,
    teardown_veth/1,
    write_container_files/2,
    zone_dns_ip/1,
    ip4_to_u32/1,
    effective_dns_ip/1
]).

-spec do_container_net_setup(#ct_data{}) ->
    {next_state, atom(), #ct_data{}}.
do_container_net_setup(#ct_data{id = Id, ip = Ip,
                                os_pid = OsPid, zone = Zone} = Data) ->
    %% erlkoenig_net needs a handle to send CMD_NET_SETUP to the C runtime.
    %% In socket mode, we temporarily set active=false for synchronous recv.
    Handle = erlkoenig_ct_rt:rt_io_handle(Data),
    ok = erlkoenig_ct_rt:maybe_set_active(Data, false),
    Name = Data#ct_data.name,
    %% Retry-on-EADDRINUSE:  when a :one_for_all / :rest_for_one pod
    %% member dies and the supervisor respawns it, the dying
    %% container's IPVLAN slave may still be live in the dying netns
    %% (kernel cleanup is asynchronous to gen_statem exit).  The new
    %% slave's `ip addr add' then trips EADDRINUSE (-98).  Bridge
    %% the teardown window with a few short retries instead of
    %% bubbling up and letting the pod-sup burn its restart budget.
    NetResult = try_net_setup_with_retry(Handle, Id, OsPid, Ip, Zone, Name, 12),
    ok = erlkoenig_ct_rt:maybe_set_active(Data, true),
    case NetResult of
        {ok, NetInfo} ->
            firewall_add(Id, NetInfo, Data#ct_data.firewall, Data#ct_data.name),
            maybe_apply_container_nft(Data),
            write_container_files(Data, Data#ct_data.files),
            %% If GO fails to reach the runtime, tcp_closed in starting
            %% will land us in failed; safe to ignore return here.
            _ = erlkoenig_ct_rt:send_to_rt(erlkoenig_proto:encode_cmd_go(), Data),
            Data2 = case Ip of
                undefined -> Data#ct_data{net_info = NetInfo,
                                          ip = maps:get(ip, NetInfo)};
                _         -> Data#ct_data{net_info = NetInfo}
            end,
            {next_state, starting, Data2};
        {error, Reason} ->
            _ = erlkoenig_cgroup:destroy(Id),
            erlkoenig_error:emit(
              ?EK_ERROR(network, net_setup_failed,
                        "erlkoenig_net:setup_container_net failed",
                        #{zone  => Data#ct_data.zone,
                          reason => Reason}),
              Id),
            {next_state, failed,
             Data#ct_data{error_reason = {net_setup_failed, Reason}}}
    end.

%% -- Container files ----------------------------------------------

-spec write_container_files(#ct_data{}, #{binary() => binary()}) -> ok.
write_container_files(_Data, Files) when map_size(Files) =:= 0 -> ok;
write_container_files(CtData, Files) ->
    maps:foreach(fun(Path, FileContent) ->
        Cmd = erlkoenig_proto:encode_cmd_write_file(Path, 8#644, FileContent),
        _ = erlkoenig_ct_rt:send_to_rt(Cmd, CtData)
    end, Files).

%% -- Firewall (direct nft integration) ----------------------------

-spec firewall_add(binary(), map(), map() | skip_firewall, binary() | undefined) -> ok.
firewall_add(_ContainerId, _NetInfo, skip_firewall, _Name) ->
    %% nft_tables mode (ADR-0015): firewall defined in DSL, not auto-generated
    ok;
firewall_add(ContainerId, #{ip := Ip} = NetInfo, FwTerm, Name) ->
    Veth = maps:get(host_veth, NetInfo, undefined),
    Ports = [],  %% Port mappings handled via firewall term
    case erlkoenig_ct_firewall:add_container(ContainerId, Ip, Veth, Ports, FwTerm, Name) of
        ok -> ok;
        {error, Reason} ->
            logger:warning("firewall: failed to create chain for ~s: ~p",
                           [ContainerId, Reason])
    end,
    ok.

%% -- Per-container nft (SPEC-EK-023) ---------------------------------

-spec maybe_apply_container_nft(#ct_data{}) -> ok.
maybe_apply_container_nft(#ct_data{extra_opts = Opts} = Data) ->
    case maps:find(nft, Opts) of
        {ok, NftConfig} when is_map(NftConfig) ->
            TableName = <<"ct_", (Data#ct_data.name)/binary>>,
            Batch = erlkoenig_nft_container:build_batch(
                      NftConfig#{table => TableName}),
            Handle = erlkoenig_ct_rt:rt_io_handle(Data),
            ok = erlkoenig_ct_rt:maybe_set_active(Data, false),
            Cmd = erlkoenig_proto:encode_cmd_nft_setup(Batch),
            case Handle of
                {socket, Sock} ->
                    ok = gen_tcp:send(Sock, Cmd),
                    case gen_tcp:recv(Sock, 0, 10000) of
                        {ok, Reply} ->
                            case erlkoenig_proto:decode(Reply) of
                                {ok, reply_ok, _} ->
                                    logger:info("container ~s: nft applied (~b bytes)",
                                                [Data#ct_data.name, byte_size(Batch)]);
                                {ok, reply_error, #{code := Code, message := Msg}} ->
                                    logger:warning("container ~s: nft failed: ~p ~s",
                                                   [Data#ct_data.name, Code, Msg])
                            end;
                        {error, Reason} ->
                            logger:warning("container ~s: nft recv failed: ~p",
                                           [Data#ct_data.name, Reason])
                    end;
                Port when is_port(Port) ->
                    port_command(Port, Cmd),
                    receive
                        {Port, {data, Reply}} ->
                            case erlkoenig_proto:decode(Reply) of
                                {ok, reply_ok, _} ->
                                    logger:info("container ~s: nft applied (~b bytes)",
                                                [Data#ct_data.name, byte_size(Batch)]);
                                {ok, reply_error, #{code := Code, message := Msg}} ->
                                    logger:warning("container ~s: nft failed: ~p ~s",
                                                   [Data#ct_data.name, Code, Msg])
                            end
                    after 10000 ->
                        logger:warning("container ~s: nft timeout", [Data#ct_data.name])
                    end
            end,
            ok = erlkoenig_ct_rt:maybe_set_active(Data, true),
            ok;
        error ->
            ok
    end.

-spec firewall_remove(binary()) -> ok.
firewall_remove(ContainerId) ->
    %% The callee returns {error, _} when the nft batch is rejected
    %% (kernel busy, nfnl_server dead, rule already gone) and does
    %% NOT log on failure itself. Without a log here the operator has
    %% no signal that container-scoped rules may have leaked — they'd
    %% only discover it via manual `nft list ruleset'. Keep the
    %% fire-and-forget semantics (state transition must proceed), but
    %% make the failure observable.
    case erlkoenig_ct_firewall:remove_container(ContainerId) of
        ok -> ok;
        {error, Reason} ->
            logger:warning("container ~s: firewall remove failed: ~p "
                           "(nft rules may leak)", [ContainerId, Reason]),
            ok
    end.

%% -- Network teardown ---------------------------------------------

-spec teardown_veth(#ct_data{}) -> ok.
teardown_veth(#ct_data{net_info = undefined}) ->
    ok;
teardown_veth(#ct_data{net_info = NetInfo}) ->
    erlkoenig_net:teardown_container_veth(NetInfo).

%% See do_container_net_setup for the rationale.
-spec try_net_setup_with_retry(term(), binary(), non_neg_integer(),
                                inet:ip4_address() | undefined, atom(),
                                binary() | undefined, pos_integer()) ->
    {ok, map()} | {error, term()}.
try_net_setup_with_retry(Handle, Id, OsPid, Ip, Zone, Name, Attempts) ->
    Call = fun() ->
        case Ip of
            undefined ->
                erlkoenig_net:setup_container_net(Handle, Id, OsPid, Zone);
            _ ->
                erlkoenig_net:setup_container_net(Handle, Id, OsPid, Ip,
                                                    Zone, Name)
        end
    end,
    try_net_setup_loop(Call, Attempts, undefined).

-spec try_net_setup_loop(fun(() -> {ok, map()} | {error, term()}),
                         non_neg_integer(), term()) ->
    {ok, map()} | {error, term()}.
try_net_setup_loop(_Call, 0, LastErr) ->
    LastErr;
try_net_setup_loop(Call, N, _) ->
    case Call() of
        {ok, _} = Ok -> Ok;
        {error, {net_setup_failed, -98, _}} = Err ->
            timer:sleep(500),
            try_net_setup_loop(Call, N - 1, Err);
        {error, {net_setup_failed, {net_setup_failed, -98, _}}} = Err ->
            timer:sleep(500),
            try_net_setup_loop(Call, N - 1, Err);
        {error, _} = Err ->
            Err
    end.

-doc "Get the DNS IP for a zone as a 32-bit network-order integer.".
%% The DNS server runs on the zone's gateway IP.
-spec zone_dns_ip(atom()) -> non_neg_integer().
zone_dns_ip(default) ->
    ip4_to_u32(application:get_env(erlkoenig, gateway, {10, 0, 0, 1}));
zone_dns_ip(ZoneName) ->
    #{network := Net} = erlkoenig_zone:zone_config(ZoneName),
    Gw = maps:get(gateway, Net, {10, 0, 0, 1}),
    case Gw of
        undefined -> ip4_to_u32({10, 0, 0, 1});
        _         -> ip4_to_u32(Gw)
    end.

-spec ip4_to_u32(inet:ip4_address()) -> non_neg_integer().
ip4_to_u32({A, B, C, D}) ->
    (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D.

%% Resolve the DNS resolver IP for this container.
%%
%% Strict capability mode (`strict_capabilities = true`):
%%   * Container declared `requires :"dns.local"' → resolver IP from zone.
%%   * Container did NOT declare it → resolver IP `0`. The C runtime
%%     skips the `/etc/resolv.conf' write entirely, so the workload
%%     cannot resolve names. Forces the operator to be explicit
%%     about which workloads need DNS.
%%
%% Loose mode (default `false'): zone-derived IP regardless. Same
%% behaviour as before the capability framework landed; existing
%% deployments need no migration.
-spec effective_dns_ip(#ct_data{}) -> non_neg_integer().
effective_dns_ip(#ct_data{zone = Zone, requires = Requires,
                          id = Id, name = Name}) ->
    case application:get_env(erlkoenig, strict_capabilities, false) of
        false ->
            zone_dns_ip(Zone);
        true ->
            case lists:member('dns.local', Requires) of
                true  ->
                    zone_dns_ip(Zone);
                false ->
                    %% Strict opt-out — surface so operators can spot
                    %% missing `requires :"dns.local"' declarations
                    %% during the migration. Container will boot
                    %% without /etc/resolv.conf; the action tag tells
                    %% the dashboard exactly what was withheld.
                    DisplayName = case Name of
                        undefined -> Id;
                        N -> N
                    end,
                    catch erlkoenig_events:notify(
                            {capability_unmet, Id, DisplayName,
                             'dns.local', no_resolv_conf}),
                    0
            end
    end.
