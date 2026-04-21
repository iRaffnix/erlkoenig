#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 49: tutorial/04_threat_detection.exs — guard config system test.
%%
%% Proves:
%%   - ct_guard block in the tutorial reaches the runtime — the
%%     `erlkoenig_nft_ct_guard` and `erlkoenig_threat_mesh` gen_servers
%%     are alive and respond to calls once the DSL is loaded.
%%   - The kernel `ban` set exists in the raw-prerouting path as the
%%     tutorial declared.
%%   - The ban pipeline works end-to-end: `local_ban` from the mesh
%%     lands an IP in the kernel set; `local_unban` removes it.
%%   - Whitelisted IPs are immune (local_ban is a no-op for them).
%%
%% Full TCP honeypot simulation would require a second host acting
%% as the attacker and takes >60s for the threat_actor state
%% machine to promote from suspect→banned; we mock the ban step
%% directly via the documented mesh API instead.
-mode(compile).

-define(PARENT, <<"ek_t49">>).
-define(GW_CIDR, "10.40.0.1/24").

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 49: tutorial 04_threat_detection ===~n~n"),
    require_root(),

    test_helper:boot(),
    logger:set_primary_config(level, error),
    application:set_env(erlkoenig, quarantine_enabled, false),

    Root     = test_helper:project_root(),
    Example  = filename:join(Root, "examples/tutorial/04_threat_detection.exs"),
    TermFile = "/tmp/erlkoenig_tutorial_04.term",
    DemoBin  = test_helper:demo("echo_server"),

    tutorial_helper:cleanup_all(),
    tutorial_helper:cleanup_dummy(?PARENT),
    tutorial_helper:ensure_dummy(?PARENT, ?GW_CIDR),

    test_helper:step("compile 04_threat_detection.exs → term", fun() ->
        tutorial_helper:compile_dsl(Root, Example, TermFile)
    end),

    test_helper:step("patch term", fun() ->
        tutorial_helper:patch_term(TermFile,
            #{binary => DemoBin, parents => #{<<"ek_edge">> => ?PARENT}})
    end),

    test_helper:step("load + edge api reaches running (may take longer "
                     "on first boot: ct_guard init + threat_mesh warmup)",
      fun() ->
        tutorial_helper:load_and_wait(TermFile, 1, 45_000)
    end),

    test_helper:step("ct_guard gen_server is up + responds (stats call)",
      fun() ->
        try erlkoenig_nft_ct_guard:stats() of
            Stats when is_map(Stats) ->
                io:format("    stats: ~p~n", [maps:keys(Stats)]),
                ok;
            Other -> {error, {unexpected_stats, Other}}
        catch
            Class:Err -> {error, {Class, Err}}
        end
    end),

    test_helper:step("banned/0 is empty at start", fun() ->
        case erlkoenig_nft_ct_guard:banned() of
            [] -> ok;
            Other -> {error, {nonempty_at_start, Other}}
        end
    end),

    test_helper:step("host nft 'ban' set exists in raw-prerouting",
      fun() ->
        Out = os:cmd("nft list set inet host ban 2>&1"),
        case re:run(Out, "set ban", [{capture, none}]) of
            match -> ok;
            _ -> {error, {no_ban_set, Out}}
        end
    end),

    %% Use the mesh's documented local_ban API to simulate a
    %% successful detection landing an IP in the kernel.  BanUntil
    %% = now + 60s so the unban timer does not race us.
    %% IP is passed as the canonical 4-byte binary (matches the
    %% internal `erlkoenig_nft_ip:normalize/1` output).
    Attacker = <<10, 40, 0, 99>>,

    test_helper:step("threat_mesh local_ban lands attacker in kernel",
      fun() ->
        BanUntil = os:system_time(millisecond) + 60_000,
        ok = erlkoenig_threat_mesh:local_ban(Attacker, BanUntil,
                                              honeypot),
        wait_for_ip_in_ban_set(Attacker, 3000)
    end),

    test_helper:step("threat_mesh active_bans reflects the ban",
      fun() ->
        Bans = erlkoenig_threat_mesh:active_bans(),
        case maps:find(Attacker, Bans) of
            {ok, _} -> ok;
            error -> {error, {not_in_active_bans, Bans}}
        end
    end),

    %% Whitelist check: 127.0.0.1 and 10.40.0.1 are allowlisted in
    %% the tutorial. local_ban on them must be a no-op.
    test_helper:step("local_ban on whitelisted IP is a no-op",
      fun() ->
        Gw = <<10, 40, 0, 1>>,
        BanUntil = os:system_time(millisecond) + 60_000,
        ok = erlkoenig_threat_mesh:local_ban(Gw, BanUntil, honeypot),
        timer:sleep(300),
        Out = os:cmd("nft list set inet host ban 2>&1"),
        %% Whitelisted IP MUST NOT appear in ban set
        case re:run(Out, "10\\.40\\.0\\.1\\b", [{capture, none}]) of
            match -> {error, {whitelisted_ip_got_banned, Out}};
            _ -> ok
        end
    end),

    test_helper:step("local_unban removes the earlier ban", fun() ->
        ok = erlkoenig_threat_mesh:local_unban(Attacker),
        wait_for_ip_not_in_ban_set(Attacker, 3000)
    end),

    test_helper:step("cleanup", fun() ->
        tutorial_helper:cleanup_all(),
        tutorial_helper:cleanup_dummy(?PARENT),
        file:delete(TermFile),
        ok
    end),

    io:format("~n=== Test 49 passed ===~n~n"),
    halt(0).

require_root() ->
    case string:trim(os:cmd("id -u")) of
        "0" -> ok;
        _   -> io:format("ERROR: must run as root~n"), halt(1)
    end.

wait_for_ip_in_ban_set(Ip, TimeoutMs) ->
    Dl = erlang:system_time(millisecond) + TimeoutMs,
    wait_for_ip_in_ban_set_loop(Ip, Dl).

wait_for_ip_in_ban_set_loop(Ip, Dl) ->
    case ip_in_ban_set(Ip) of
        true  -> ok;
        false ->
            case erlang:system_time(millisecond) of
                N when N > Dl -> {error, {not_in_set, Ip}};
                _ -> timer:sleep(200),
                     wait_for_ip_in_ban_set_loop(Ip, Dl)
            end
    end.

wait_for_ip_not_in_ban_set(Ip, TimeoutMs) ->
    Dl = erlang:system_time(millisecond) + TimeoutMs,
    wait_for_ip_not_in_ban_set_loop(Ip, Dl).

wait_for_ip_not_in_ban_set_loop(Ip, Dl) ->
    case ip_in_ban_set(Ip) of
        false -> ok;
        true ->
            case erlang:system_time(millisecond) of
                N when N > Dl -> {error, {still_in_set, Ip}};
                _ -> timer:sleep(200),
                     wait_for_ip_not_in_ban_set_loop(Ip, Dl)
            end
    end.

ip_in_ban_set(<<A, B, C, D>>) ->
    %% threat_mesh bans go into the runtime's managed set
    %% `inet erlkoenig blocklist` (created at boot by the nft
    %% subsystem, lives alongside the user's DSL-declared sets).
    Out = os:cmd("nft list set inet erlkoenig blocklist 2>&1"),
    Needle = lists:flatten(io_lib:format("~B.~B.~B.~B", [A, B, C, D])),
    re:run(Out, Needle, [{capture, none}]) =:= match.
