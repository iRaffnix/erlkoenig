#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 48: tutorial/03_firewall.exs — nft primitive coverage.
%%
%% Proves every primitive the tutorial demonstrates reaches the
%% kernel:
%%   * nft_set "ban", "trusted_cidrs" (interval flag)
%%   * nft_counter input_drop / input_ban / forward_drop
%%   * nft_map lb_backends
%%   * nft_vmap port_dispatch
%%   * nft_flowtable ft0
%%   * base chains prerouting_raw / input / forward / postrouting
%%   * container-local conn_limit per_ip: 100
-mode(compile).

-define(PARENT, <<"ek_t48">>).
-define(GW_CIDR, "10.30.0.1/24").

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 48: tutorial 03_firewall ===~n~n"),
    require_root(),

    test_helper:boot(),
    logger:set_primary_config(level, error),
    application:set_env(erlkoenig, quarantine_enabled, false),

    Root     = test_helper:project_root(),
    Example  = filename:join(Root, "examples/tutorial/03_firewall.exs"),
    TermFile = "/tmp/erlkoenig_tutorial_03.term",
    DemoBin  = test_helper:demo("echo_server"),

    tutorial_helper:cleanup_all(),
    tutorial_helper:cleanup_dummy(?PARENT),
    tutorial_helper:ensure_dummy(?PARENT, ?GW_CIDR),

    test_helper:step("compile 03_firewall.exs → term", fun() ->
        tutorial_helper:compile_dsl(Root, Example, TermFile)
    end),

    test_helper:step("patch term", fun() ->
        tutorial_helper:patch_term(TermFile,
            #{binary => DemoBin, parents => #{<<"ek_fw">> => ?PARENT}})
    end),

    test_helper:step("load + edge reaches running", fun() ->
        tutorial_helper:load_and_wait(TermFile, 1, 15_000)
    end),

    test_helper:step("host nft table has all declared primitives",
      fun() ->
        Out = tutorial_helper:host_ruleset(),
        Expected = [
            %% Sets
            "set ban",
            "set trusted_cidrs",
            "flags interval",
            %% Counters
            "counter input_drop",
            "counter input_ban",
            "counter forward_drop",
            %% Map + vmap (may print as "map lb_backends" / "map port_dispatch"
            %% on different nft versions)
            "map lb_backends",
            "map port_dispatch",
            %% Flowtable
            "flowtable ft0",
            %% Chains
            "chain prerouting_raw",
            "chain input",
            "chain forward",
            "chain postrouting"
        ],
        case [Pat || Pat <- Expected,
                     re:run(Out, Pat, [{capture, none}]) =/= match] of
            [] -> ok;
            Missing -> {error, {missing_in_host_nft, Missing, Out}}
        end
    end),

    test_helper:step("trusted_cidrs set contains 4 interval elements",
      fun() ->
        Out = os:cmd("nft list set inet host trusted_cidrs 2>&1"),
        Checks = ["10.0.0.0/8", "192.168.0.0/16",
                  "203.0.113.0/24", "198.51.100.42"],
        case [C || C <- Checks,
                   re:run(Out, C, [{capture, none}]) =/= match] of
            [] -> ok;
            Missing -> {error, {missing_cidrs, Missing, Out}}
        end
    end),

    test_helper:step("container-local conn_limit rule in edge netns",
      fun() ->
        {ok, Pid} = tutorial_helper:find_pid(<<"web-0-edge">>),
        Out = tutorial_helper:ct_ruleset(Pid),
        case re:run(Out, "ct count over 100.*drop", [{capture, none}]) of
            match -> ok;
            _ -> {error, {no_connlimit_rule, Out}}
        end
    end),

    test_helper:step("container netns has output chain "
                     "with udp/53 egress rule (explicit by operator)",
      fun() ->
        {ok, Pid} = tutorial_helper:find_pid(<<"web-0-edge">>),
        Out = tutorial_helper:ct_ruleset(Pid),
        case re:run(Out, "udp dport 53", [{capture, none}]) of
            match -> ok;
            _ -> {error, {no_egress_udp53, Out}}
        end
    end),

    test_helper:step("cleanup", fun() ->
        tutorial_helper:cleanup_all(),
        tutorial_helper:cleanup_dummy(?PARENT),
        file:delete(TermFile),
        ok
    end),

    io:format("~n=== Test 48 passed ===~n~n"),
    halt(0).

require_root() ->
    case string:trim(os:cmd("id -u")) of
        "0" -> ok;
        _   -> io:format("ERROR: must run as root~n"), halt(1)
    end.
