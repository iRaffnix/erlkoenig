%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%

-module(erlkoenig_ct_info).
-moduledoc """
Public-map projection for `erlkoenig:inspect/1' / `get_info/1'.

`build_info/2' is a pure mapping from `(State, #ct_data{})' into
the `erlkoenig:container_info()' map the operator sees. It makes
no state transitions and has no side effects beyond the
`erlkoenig_ct_observe:maybe_add_stats/3' read of cgroup stats for
the `running' state.

Extracted so `erlkoenig_ct' is uniformly a state-machine module
(state callbacks + their direct helpers), and so inspection
changes don't touch the lifecycle file.

`build_info/2' return type is extended dynamically by
`maybe_add_optional_fields/3', so dialyzer gets a
`no_contracts' hint.
""".

-include("erlkoenig_ct_state.hrl").

-dialyzer({no_contracts, [build_info/2, maybe_add_optional_fields/3]}).

-export([build_info/2]).

-spec build_info(atom(), #ct_data{}) -> erlkoenig:container_info().
build_info(State, Data) ->
    Info = #{
        id            => Data#ct_data.id,
        state         => operator_state(State, Data),
        binary        => Data#ct_data.binary_path,
        os_pid        => Data#ct_data.os_pid,
        netns_path    => Data#ct_data.netns_path,
        restart       => Data#ct_data.restart,
        restart_count => Data#ct_data.restart_count,
        limits        => Data#ct_data.limits,
        seccomp       => erlkoenig_ct_opts:seccomp_profile_name(Data#ct_data.seccomp),
        caps          => erlkoenig_ct_opts:mask_to_caps(Data#ct_data.caps_keep),
        name          => Data#ct_data.name,
        zone          => Data#ct_data.zone,
        args          => Data#ct_data.args,
        ports         => maps:get(ports, Data#ct_data.extra_opts, []),
        volumes       => Data#ct_data.volumes,
        handshake     => Data#ct_data.handshake
    },
    maybe_add_optional_fields(State, Data, Info).

-spec operator_state(atom(), #ct_data{}) -> atom().
operator_state(stopped, #ct_data{user_stopped = false,
                                 exit_info = #{exit_code := 0,
                                               term_signal := 0}}) ->
    stopped;
operator_state(stopped, #ct_data{user_stopped = false,
                                 exit_info = #{}}) ->
    failed;
operator_state(State, _Data) ->
    State.

-spec maybe_add_optional_fields(atom(), #ct_data{}, map()) ->
    erlkoenig:container_info().
maybe_add_optional_fields(State, Data, Info0) ->
    Info1 = maybe_put(net_info,    Data#ct_data.net_info,     Info0),
    Info2 = maybe_put(exit_info,   Data#ct_data.exit_info,    Info1),
    Info3 = maybe_put(runtime_timeline, Data#ct_data.runtime_timeline, Info2),
    Info4 = maybe_put(error,       Data#ct_data.error_reason, Info3),
    Info5 = maybe_put(socket_path, Data#ct_data.socket_path,  Info4),
    erlkoenig_ct_observe:maybe_add_stats(State, Data#ct_data.id, Info5).

-spec maybe_put(atom(), term(), map()) -> map().
maybe_put(_Key, undefined, Map) -> Map;
maybe_put(_Key, [], Map)        -> Map;
maybe_put(Key, Value, Map)      -> Map#{Key => Value}.
