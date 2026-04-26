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

%% =================================================================
%% Config shape / error paths
%% =================================================================

init_missing_network_returns_error_test() ->
    %% The whole module branches on #{network := #{parent := _}}. A
    %% config without `network` must surface a structured error the
    %% supervisor can classify, not a badmatch.
    ?assertMatch({error, {missing_network_config, _}},
                 erlkoenig_zone_link:init(#{})).

init_network_without_parent_returns_error_test() ->
    %% `network` present but `parent` missing — the outer pattern
    %% match in init/1 fails and falls through to the error clause.
    ?assertMatch({error, {missing_network_config, _}},
                 erlkoenig_zone_link:init(#{network => #{mode => ipvlan}})).

%% =================================================================
%% parent_type default + explicit :device (no side effects)
%% =================================================================

ipvlan_init_parent_type_defaults_to_device_test() ->
    %% Config without parent_type must default to :device — otherwise
    %% ensure_dummy would fire, shelling out to `ip link add` and
    %% mutating host state during a plain unit test.
    Config = #{network => #{mode => ipvlan,
                            parent => <<"lo">>,
                            ipvlan_mode => l3s}},
    {ok, State} = erlkoenig_zone_link:init(Config),
    ?assertEqual(device, maps:get(parent_type, State)).

ipvlan_init_parent_type_device_explicit_test() ->
    Config = #{network => #{mode => ipvlan,
                            parent => <<"lo">>,
                            parent_type => device,
                            ipvlan_mode => l3s}},
    {ok, State} = erlkoenig_zone_link:init(Config),
    ?assertEqual(device, maps:get(parent_type, State)).

%% =================================================================
%% ipvlan_mode round-trip for l2 / l3 / l3s
%% =================================================================

ipvlan_init_mode_l2_test() ->
    {ok, State} = erlkoenig_zone_link:init(
        #{network => #{mode => ipvlan, parent => <<"lo">>,
                       parent_type => device, ipvlan_mode => l2}}),
    ?assertEqual(l2, maps:get(ipvlan_mode, State)).

ipvlan_init_mode_l3_test() ->
    {ok, State} = erlkoenig_zone_link:init(
        #{network => #{mode => ipvlan, parent => <<"lo">>,
                       parent_type => device, ipvlan_mode => l3}}),
    ?assertEqual(l3, maps:get(ipvlan_mode, State)).

ipvlan_init_mode_l3s_explicit_test() ->
    {ok, State} = erlkoenig_zone_link:init(
        #{network => #{mode => ipvlan, parent => <<"lo">>,
                       parent_type => device, ipvlan_mode => l3s}}),
    ?assertEqual(l3s, maps:get(ipvlan_mode, State)).

%% =================================================================
%% Returned state shape (contract with erlkoenig_ct)
%% =================================================================

ipvlan_init_returns_expected_keys_test() ->
    %% The orchestrator reads these four keys. Pin the contract so a
    %% rename doesn't break the caller silently.
    {ok, State} = erlkoenig_zone_link:init(
        #{network => #{mode => ipvlan, parent => <<"lo">>,
                       parent_type => device, ipvlan_mode => l3s}}),
    ?assert(is_map_key(parent, State)),
    ?assert(is_map_key(parent_type, State)),
    ?assert(is_map_key(parent_ifindex, State)),
    ?assert(is_map_key(ipvlan_mode, State)),
    ?assertEqual(<<"lo">>, maps:get(parent, State)).

%% =================================================================
%% host_slave_name — IFNAMSIZ arithmetic (TEST-only export)
%% =================================================================

host_slave_name_short_test() ->
    %% Short dummy name: `h.ek0' fits easily.
    ?assertEqual(<<"h.ek0">>,
                 erlkoenig_zone_link_ipvlan:host_slave_name(<<"ek0">>)).

host_slave_name_at_13_byte_boundary_test() ->
    %% 13 bytes of dummy name + `h.' prefix = 15 bytes = IFNAMSIZ-1.
    %% The exact boundary — must still succeed.
    Dummy = binary:copy(<<"a">>, 13),
    ?assertEqual(<<"h.", Dummy/binary>>,
                 erlkoenig_zone_link_ipvlan:host_slave_name(Dummy)).

host_slave_name_at_14_bytes_raises_test() ->
    %% 14-byte dummy → 16-byte host slave name, overflows IFNAMSIZ.
    %% The kernel would reject the RTM_NEWLINK silently; fail loud
    %% before the syscall with a structured error so the operator
    %% sees "name too long" not an opaque netlink EINVAL.
    Dummy = binary:copy(<<"b">>, 14),
    ?assertError({dummy_name_too_long_for_host_slave, Dummy, 16, max_13},
                 erlkoenig_zone_link_ipvlan:host_slave_name(Dummy)).

host_slave_name_empty_input_test() ->
    %% An empty dummy name still produces a valid 2-byte candidate.
    %% Pinning this keeps the caller's `filelib:is_dir' path from
    %% getting its input silently truncated in a future refactor.
    ?assertEqual(<<"h.">>,
                 erlkoenig_zone_link_ipvlan:host_slave_name(<<>>)).

%% =================================================================
%% subnet / netmask fallback precedence
%% =================================================================

ipvlan_init_accepts_subnet_in_network_test() ->
    %% Subnet can live either on the top-level Cfg or inside the
    %% network subconfig. Both paths produce a usable state — the
    %% difference only matters when parent_type => dummy (ensure_dummy
    %% consumes the subnet). Here we only exercise the pattern match
    %% does not choke on either shape.
    {ok, State} = erlkoenig_zone_link:init(
        #{network => #{mode => ipvlan, parent => <<"lo">>,
                       parent_type => device, ipvlan_mode => l3s,
                       subnet => {10, 20, 30, 0}, netmask => 24}}),
    ?assertEqual(l3s, maps:get(ipvlan_mode, State)).

ipvlan_init_accepts_subnet_in_top_level_cfg_test() ->
    {ok, State} = erlkoenig_zone_link:init(
        #{network => #{mode => ipvlan, parent => <<"lo">>,
                       parent_type => device, ipvlan_mode => l3s},
          subnet => {10, 20, 30, 0}, netmask => 24}),
    ?assertEqual(l3s, maps:get(ipvlan_mode, State)).

%% =================================================================
%% Input type quirks — current behaviour pinned (not graceful today)
%% =================================================================

init_non_map_config_surfaces_structured_error_test() ->
    %% A proplist never matches the #{network := ...} pattern, so the
    %% default clause fires. The structured error is what the zone
    %% supervisor classifies — make sure a rename of the atom here
    %% does not go unnoticed.
    ?assertMatch({error, {missing_network_config, _}},
                 erlkoenig_zone_link:init([{network, foo}])).

init_non_binary_parent_crashes_today_test() ->
    %% Documented quirk: `parent' must be a binary. Passing a charlist
    %% or atom crashes deep in the netlink stack with `badarg' rather
    %% than a clean `{error, ...}' tuple. The DSL always emits binary,
    %% so this matters only for programmatic callers. Pin the
    %% behaviour so a future normalisation (accepting iolist) is a
    %% deliberate improvement.
    ?assertError(badarg,
                 erlkoenig_zone_link:init(
                     #{network => #{mode => ipvlan, parent => "lo",
                                    parent_type => device,
                                    ipvlan_mode => l3s}})),
    ?assertError(badarg,
                 erlkoenig_zone_link:init(
                     #{network => #{mode => ipvlan, parent => lo,
                                    parent_type => device,
                                    ipvlan_mode => l3s}})).
