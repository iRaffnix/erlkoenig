#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 47: tutorial/02_capabilities.exs — 4 capabilities system test.
%%
%% Proves:
%%   - dns.local, dns.allowlist, journal.local, postgres.local all
%%     declared and reach the runtime (not just the term).
%%   - dns_filter has the allowlist registered for the container IP.
%%   - socket mounts are present in the container's mount namespace.
%%   - The explicit egress nft rule the operator wrote is visible
%%     in kernel (Glasbox: no magic inject).
-mode(compile).

-define(PARENT, <<"ek_t47">>).
-define(GW_CIDR, "10.20.0.1/24").

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 47: tutorial 02_capabilities ===~n~n"),
    require_root(),

    test_helper:boot(),
    logger:set_primary_config(level, error),
    application:set_env(erlkoenig, quarantine_enabled, false),

    Root     = test_helper:project_root(),
    Example  = filename:join(Root, "examples/tutorial/02_capabilities.exs"),
    TermFile = "/tmp/erlkoenig_tutorial_02.term",
    DemoBin  = test_helper:demo("echo_server"),

    tutorial_helper:cleanup_all(),
    tutorial_helper:cleanup_dummy(?PARENT),
    tutorial_helper:ensure_dummy(?PARENT, ?GW_CIDR),

    test_helper:step("compile 02_capabilities.exs → term", fun() ->
        tutorial_helper:compile_dsl(Root, Example, TermFile)
    end),

    test_helper:step("patch term", fun() ->
        tutorial_helper:patch_term(TermFile,
            #{binary => DemoBin, parents => #{<<"ek_caps">> => ?PARENT}})
    end),

    test_helper:step("load + worker reaches running", fun() ->
        tutorial_helper:load_and_wait(TermFile, 1, 15_000)
    end),

    CtPid = element(2, {ok, begin
        {ok, P} = tutorial_helper:find_pid(<<"agents-0-worker">>),
        P
    end}),

    CtIp = test_helper:step("discover container IP", fun() ->
        Info = erlkoenig:inspect(CtPid),
        NetInfo = maps:get(net_info, Info, #{}),
        case maps:get(ip, NetInfo, undefined) of
            Ip when Ip =/= undefined -> {ok, Ip};
            _ -> {error, {no_ip_in_net_info, Info}}
        end
    end),

    test_helper:step("dns_filter has allowlist registered for container IP",
      fun() ->
        case erlkoenig_dns_filter:check(CtIp, <<"api.openai.com">>) of
            allow -> ok;
            Other -> {error, {expected_allow, Other}}
        end
    end),

    test_helper:step("dns_filter wildcard *.s3.amazonaws.com works", fun() ->
        case erlkoenig_dns_filter:check(CtIp, <<"foo.s3.amazonaws.com">>) of
            allow -> ok;
            Other -> {error, {expected_allow_wildcard, Other}}
        end
    end),

    test_helper:step("dns_filter denies name outside allowlist", fun() ->
        case erlkoenig_dns_filter:check(CtIp, <<"evil.example.org">>) of
            {deny, not_in_allowlist} -> ok;
            Other -> {error, {expected_deny, Other}}
        end
    end),

    test_helper:step("/run/erlkoenig socket-mount is bind-mounted "
                     "into container", fun() ->
        #{os_pid := OsPid} = erlkoenig:inspect(CtPid),
        Out = os:cmd(io_lib:format(
                "cat /proc/~B/mountinfo 2>&1", [OsPid])),
        case re:run(Out, "/run/erlkoenig", [{capture, none}]) of
            match -> ok;
            _ -> {error, {socket_mount_not_present, Out}}
        end
    end),

    test_helper:step("explicit output rule for UDP/53 is "
                     "visible in container netns (Glasbox check)",
      fun() ->
        Out = tutorial_helper:ct_ruleset(CtPid),
        %% Tutorial writes the rule explicitly; capability must
        %% NOT auto-inject anything magical.
        case re:run(Out, "udp dport 53", [{capture, none}]) of
            match -> ok;
            _ -> {error, {no_dns_egress_rule, Out}}
        end
    end),

    test_helper:step("explicit TLS/443 egress rule present", fun() ->
        Out = tutorial_helper:ct_ruleset(CtPid),
        case re:run(Out, "tcp dport 443", [{capture, none}]) of
            match -> ok;
            _ -> {error, {no_https_rule, Out}}
        end
    end),

    test_helper:step("cleanup + dns_filter unregistered", fun() ->
        tutorial_helper:cleanup_all(),
        timer:sleep(500),
        case erlkoenig_dns_filter:check(CtIp, <<"api.openai.com">>) of
            no_filter -> ok;
            Other -> {error, {filter_leaked, Other}}
        end
    end),

    test_helper:step("tear-down parent", fun() ->
        tutorial_helper:cleanup_dummy(?PARENT),
        file:delete(TermFile),
        ok
    end),

    io:format("~n=== Test 47 passed ===~n~n"),
    halt(0).

require_root() ->
    case string:trim(os:cmd("id -u")) of
        "0" -> ok;
        _   -> io:format("ERROR: must run as root~n"), halt(1)
    end.
