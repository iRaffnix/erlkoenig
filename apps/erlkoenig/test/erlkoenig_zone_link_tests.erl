%%%-------------------------------------------------------------------
%%% @doc Unit tests for erlkoenig_zone_link (IPVLAN-only, ADR-0020).
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_zone_link_tests).

-include_lib("eunit/include/eunit.hrl").

%% =================================================================
%% IPVLAN init
%% =================================================================

ipvlan_init_with_lo_test() ->
    Config = #{network => #{mode => ipvlan,
                            parent => <<"lo">>,
                            parent_type => device,
                            ipvlan_mode => l3s}},
    {ok, State} = erlkoenig_zone_link:init(Config),
    ?assertMatch(#{parent_ifindex := Idx} when is_integer(Idx) andalso Idx > 0, State),
    ?assertEqual(l3s, maps:get(ipvlan_mode, State)).

ipvlan_init_bad_parent_test() ->
    Config = #{network => #{mode => ipvlan,
                            parent => <<"nonexistent_xyz">>,
                            parent_type => device,
                            ipvlan_mode => l3s}},
    ?assertMatch({error, _}, erlkoenig_zone_link:init(Config)).

ipvlan_init_default_mode_test() ->
    Config = #{network => #{mode => ipvlan,
                            parent => <<"lo">>,
                            parent_type => device}},
    {ok, State} = erlkoenig_zone_link:init(Config),
    ?assertEqual(l3s, maps:get(ipvlan_mode, State)).

%% =================================================================
%% IPVLAN detach is no-op
%% =================================================================

ipvlan_detach_noop_test() ->
    State = #{parent_ifindex => 1, ipvlan_mode => l3s},
    ?assertEqual(ok, erlkoenig_zone_link:detach_container(
                       State, #{slave => <<"ipv.test">>, mode => ipvlan})).

ipvlan_detach_empty_info_test() ->
    State = #{parent_ifindex => 1, ipvlan_mode => l3s},
    ?assertEqual(ok, erlkoenig_zone_link:detach_container(State, #{})).
