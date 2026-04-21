#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 46: tutorial/01_overview.exs — minimal stack system test.
%%
%% Proves the tutorial's @moduledoc promise:
%%   "eine IPVLAN-Zone, ein Pod mit einem Container, eine Host-Firewall"
%%
%% End-to-end chain:
%%   .exs → mix → term → load → spawn → container running
%%   host nft table present with input_drop counter visible in kernel
-mode(compile).

-define(PARENT, <<"ek_t46">>).
-define(GW_CIDR, "10.10.0.1/24").

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 46: tutorial 01_overview ===~n~n"),
    require_root(),

    test_helper:boot(),
    logger:set_primary_config(level, error),
    application:set_env(erlkoenig, quarantine_enabled, false),

    Root     = test_helper:project_root(),
    Example  = filename:join(Root, "examples/tutorial/01_overview.exs"),
    TermFile = "/tmp/erlkoenig_tutorial_01.term",
    DemoBin  = test_helper:demo("echo_server"),

    tutorial_helper:cleanup_all(),
    tutorial_helper:cleanup_dummy(?PARENT),
    tutorial_helper:ensure_dummy(?PARENT, ?GW_CIDR),

    test_helper:step("compile 01_overview.exs → term", fun() ->
        tutorial_helper:compile_dsl(Root, Example, TermFile)
    end),

    test_helper:step("patch term (binary + parent)", fun() ->
        tutorial_helper:patch_term(TermFile,
            #{binary => DemoBin, parents => #{<<"ek_demo">> => ?PARENT}})
    end),

    test_helper:step("load + 1 container reaches running", fun() ->
        tutorial_helper:load_and_wait(TermFile, 1, 15_000)
    end),

    test_helper:step("container 'hello-0-web' is alive", fun() ->
        case tutorial_helper:find_pid(<<"hello-0-web">>) of
            {ok, Pid} ->
                Info = erlkoenig:inspect(Pid),
                case Info of
                    #{state := running, os_pid := OsPid}
                        when is_integer(OsPid) -> ok;
                    _ -> {error, {unexpected_state, Info}}
                end;
            not_found -> {error, container_not_found}
        end
    end),

    test_helper:step("host nft table 'host' exists with input_drop counter",
      fun() ->
        Out = tutorial_helper:host_ruleset(),
        Checks = [
            {"table inet host",      "table inet host"},
            {"counter input_drop",   "counter input_drop"},
            {"policy drop",          "policy drop"}
        ],
        case [Name || {Name, Pat} <- Checks,
                      re:run(Out, Pat, [{capture, none}]) =/= match] of
            [] -> ok;
            Missing -> {error, {missing_in_host_nft, Missing, Out}}
        end
    end),

    test_helper:step("container netns has ipvlan iface", fun() ->
        {ok, Pid} = tutorial_helper:find_pid(<<"hello-0-web">>),
        #{os_pid := OsPid} = erlkoenig:inspect(Pid),
        Out = os:cmd(io_lib:format(
                "nsenter --target ~B --net ip -4 addr show 2>&1", [OsPid])),
        case re:run(Out, "inet 10\\.10\\.0\\.", [{capture, none}]) of
            match -> ok;
            _ -> {error, {no_zone_ip, Out}}
        end
    end),

    test_helper:step("cleanup", fun() ->
        tutorial_helper:cleanup_all(),
        tutorial_helper:cleanup_dummy(?PARENT),
        file:delete(TermFile),
        ok
    end),

    io:format("~n=== Test 46 passed ===~n~n"),
    halt(0).

require_root() ->
    case string:trim(os:cmd("id -u")) of
        "0" -> ok;
        _   -> io:format("ERROR: must run as root~n"), halt(1)
    end.
