%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_error_tests).

-include_lib("eunit/include/eunit.hrl").
-include("erlkoenig_error.hrl").

make_minimal_test() ->
    E = erlkoenig_error:make(network, econnrefused),
    ?assertEqual(network, maps:get(type, E)),
    ?assertEqual(econnrefused, maps:get(reason, E)),
    ?assertEqual('EK_NETWORK_ECONNREFUSED', maps:get(code, E)),
    ?assertEqual(<<>>, maps:get(context, E)),
    ?assertEqual(#{}, maps:get(data, E)),
    ?assertEqual(error, maps:get(severity, E)),
    ?assertEqual(undefined, maps:get(container, E)),
    ?assert(is_integer(maps:get(ts, E))).

make_with_context_test() ->
    E = erlkoenig_error:make(config, parse_failed, "bad term"),
    ?assertEqual(<<"bad term">>, maps:get(context, E)).

make_with_data_test() ->
    E = erlkoenig_error:make(network, timeout, "connect", #{ip => {10,0,0,1}, port => 80}),
    ?assertEqual(#{ip => {10,0,0,1}, port => 80}, maps:get(data, E)).

make_with_severity_test() ->
    E = erlkoenig_error:make(security, cap_drop_failed, "", #{}, #{severity => critical}),
    ?assertEqual(critical, maps:get(severity, E)).

iodata_context_accepted_test() ->
    %% io_lib:format returns iodata, must be accepted.
    E = erlkoenig_error:make(network, econnrefused,
                             io_lib:format("file ~s", ["/tmp/x"])),
    ?assertEqual(<<"file /tmp/x">>, maps:get(context, E)).

routing_key_test() ->
    E = erlkoenig_error:make(network, econnrefused),
    ?assertEqual(<<"error.network.econnrefused">>,
                 erlkoenig_error:routing_key(E)).

payload_maps_types_to_binaries_test() ->
    E = erlkoenig_error:make(network, timeout, "connect",
                              #{ip => {10,0,0,1}, port => 7777}),
    P = erlkoenig_error:payload(E),
    ?assertEqual(<<"network">>,  maps:get(<<"type">>, P)),
    ?assertEqual(<<"timeout">>,  maps:get(<<"reason">>, P)),
    ?assertEqual(<<"EK_NETWORK_TIMEOUT">>, maps:get(<<"code">>, P)),
    ?assertEqual(<<"connect">>,  maps:get(<<"context">>, P)),
    ?assertEqual(<<"error">>,    maps:get(<<"severity">>, P)),
    ?assertEqual(<<"10.0.0.1">>, maps:get(<<"ip">>, maps:get(<<"data">>, P))),
    ?assertEqual(7777,           maps:get(<<"port">>, maps:get(<<"data">>, P))).

to_string_minimal_test() ->
    E = erlkoenig_error:make(network, econnrefused),
    S = iolist_to_binary(erlkoenig_error:to_string(E)),
    ?assertEqual(<<"[error/network/econnrefused]">>, S).

to_string_with_context_and_container_test() ->
    E0 = erlkoenig_error:make(network, timeout, "connect to rt", #{port => 7}),
    E  = E0#{container => <<"web-0-nginx">>},
    S  = iolist_to_binary(erlkoenig_error:to_string(E)),
    ?assertMatch(<<"[error/network/timeout] ct=web-0-nginx: connect to rt ",
                   _/binary>>, S).

macro_captures_source_test() ->
    %% The ?EK_ERROR macro bakes module/function/arity/line into the map.
    E = ?EK_ERROR(runtime, not_connected, "oops", #{}),
    ?assertEqual('EK_RUNTIME_NOT_CONNECTED', maps:get(code, E)),
    Src = maps:get(source, E),
    ?assertEqual(?MODULE, maps:get(module, Src)),
    ?assertEqual(macro_captures_source_test, maps:get(function, Src)),
    ?assertEqual(0, maps:get(arity, Src)),
    ?assert(is_integer(maps:get(line, Src))).

emit_without_bus_is_safe_test() ->
    %% erlkoenig_events is not started in eunit — emit must not crash.
    E = erlkoenig_error:make(runtime, not_connected, "no runtime socket"),
    ?assertEqual(ok, erlkoenig_error:emit(E)).

emit_with_container_tag_test() ->
    E = erlkoenig_error:make(network, timeout),
    %% Should not crash and should attach container id.
    ?assertEqual(ok, erlkoenig_error:emit(E, <<"my-ct">>)).

amqp_codec_round_trip_test() ->
    %% An {error, ErrMap} event must be routed onto error.<type>.<reason>
    %% and round-trip through the codec into valid JSON.
    Err = erlkoenig_error:make(network, econnrefused,
                                "connect to runtime",
                                #{ip => {10,0,0,12}, port => 7777}),
    {ok, Key, Json} = erlkoenig_amqp_codec:encode({error, Err}),
    ?assertEqual(<<"error.network.econnrefused">>, Key),
    Bin     = iolist_to_binary(Json),
    Decoded = json:decode(Bin),
    ?assertEqual(2,                              maps:get(<<"v">>, Decoded)),
    ?assertEqual(<<"error.network.econnrefused">>,
                 maps:get(<<"key">>, Decoded)),
    P = maps:get(<<"payload">>, Decoded),
    ?assertEqual(<<"network">>,      maps:get(<<"type">>, P)),
    ?assertEqual(<<"econnrefused">>, maps:get(<<"reason">>, P)),
    ?assertEqual(<<"EK_NETWORK_ECONNREFUSED">>, maps:get(<<"code">>, P)),
    ?assertEqual(<<"10.0.0.12">>,    maps:get(<<"ip">>,   maps:get(<<"data">>, P))),
    ?assertEqual(7777,               maps:get(<<"port">>, maps:get(<<"data">>, P))).

payload_handles_pids_and_refs_test() ->
    %% Opaque terms still produce a valid payload (iolist-binary fallback).
    Pid = self(),
    Ref = erlang:make_ref(),
    E   = erlkoenig_error:make(runtime, handshake_failed, "caller died",
                                #{pid => Pid, ref => Ref}),
    P   = erlkoenig_error:payload(E),
    ?assert(is_binary(maps:get(<<"pid">>, maps:get(<<"data">>, P)))),
    ?assert(is_binary(maps:get(<<"ref">>, maps:get(<<"data">>, P)))).

code_is_stable_public_atom_test() ->
    ?assertEqual('EK_RUNTIME_SOCKET_CONNECT_FAILED',
                 erlkoenig_error:code(runtime, socket_connect_failed)).

catalog_validates_test() ->
    ?assertEqual(ok, erlkoenig_error:validate_catalog()).

catalog_lookup_test() ->
    {ok, Meta} = erlkoenig_error:lookup('EK_RUNTIME_SOCKET_CONNECT_FAILED'),
    ?assertEqual(runtime, maps:get(component, Meta)),
    ?assertEqual(socket_connect_failed, maps:get(reason, Meta)),
    ?assertEqual('EK_RUNTIME_SOCKET_CONNECT_FAILED', maps:get(code, Meta)),
    ?assert(maps:is_key(operator_action, Meta)).

wave1_runtime_codes_are_cataloged_test() ->
    Codes = [
        erlkoenig_error:code(runtime, binary_quarantined),
        erlkoenig_error:code(runtime, socket_connect_failed),
        erlkoenig_error:code(runtime, spawn_failed),
        erlkoenig_error:code(runtime, unexpected_spawn_reply)
    ],
    [?assertMatch({ok, _}, erlkoenig_error:lookup(Code)) || Code <- Codes].

format_cataloged_code_test() ->
    Text = iolist_to_binary(
             erlkoenig_error:format(
               'EK_RUNTIME_SOCKET_CONNECT_FAILED',
               #{socket_path => <<"/run/erlkoenig/demo.sock">>,
                 reason => timeout})),
    ?assertMatch(<<"EK_RUNTIME_SOCKET_CONNECT_FAILED", _/binary>>, Text),
    ?assertNotEqual(nomatch, binary:match(Text, <<"action: ">>)),
    ?assertNotEqual(nomatch, binary:match(Text, <<"socket_path">>)).
