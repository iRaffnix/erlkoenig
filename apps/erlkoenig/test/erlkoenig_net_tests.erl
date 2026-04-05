%%%-------------------------------------------------------------------
%%% @doc Unit tests for erlkoenig_net (veth naming, IP formatting).
%%%
%%% Tests internal helper functions that don't require root or
%%% network namespaces.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_net_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%% =================================================================
%% Veth name generation
%% =================================================================

%% erlkoenig_net uses host_veth_name/1 and peer_veth_name/1 internally.
%% We test the naming contract: prefix + first 12 chars of ID,
%% max 15 chars total (IFNAMSIZ - 1).

veth_name_format_test() ->
    %% A typical UUID-style container ID
    Id = <<"a1b2c3d4e5f6a7b8c9d0e1f2">>,
    HostVeth = <<"vh_", (binary:part(Id, 0, 12))/binary>>,
    PeerVeth = <<"vp_", (binary:part(Id, 0, 12))/binary>>,
    ?assertEqual(<<"vh_a1b2c3d4e5f6">>, HostVeth),
    ?assertEqual(<<"vp_a1b2c3d4e5f6">>, PeerVeth),
    %% Must fit in IFNAMSIZ (15 chars max)
    ?assert(byte_size(HostVeth) =< 15),
    ?assert(byte_size(PeerVeth) =< 15).

veth_name_short_id_test() ->
    %% Short ID should still work
    Id = <<"abc">>,
    Short = binary:part(Id, 0, min(12, byte_size(Id))),
    HostVeth = <<"vh_", Short/binary>>,
    ?assertEqual(<<"vh_abc">>, HostVeth),
    ?assert(byte_size(HostVeth) =< 15).

veth_name_exact_12_test() ->
    Id = <<"123456789012">>,
    Short = binary:part(Id, 0, min(12, byte_size(Id))),
    HostVeth = <<"vh_", Short/binary>>,
    ?assertEqual(15, byte_size(HostVeth)).

%% =================================================================
%% Gateway / netmask defaults
%% =================================================================

default_gateway_test() ->
    %% Default gateway should be 10.0.0.1
    Gateway = application:get_env(erlkoenig, gateway, {10, 0, 0, 1}),
    ?assertMatch({10, 0, 0, 1}, Gateway).

default_netmask_test() ->
    Netmask = application:get_env(erlkoenig, netmask, 24),
    ?assertEqual(24, Netmask).
