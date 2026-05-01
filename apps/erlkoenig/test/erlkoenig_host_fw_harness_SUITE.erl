-module(erlkoenig_host_fw_harness_SUITE).
-moduledoc false.

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

suite() ->
    [{timetrap, {seconds, 30}}].

all() ->
    [
        veth_pair_reaches_host,
        tcp_dport_18080_hits_accept_counter,
        default_drop_counter_delta,
        kernel_set_drop_counter_delta,
        erlkoenig_firewall_config_applies_host_rules
    ].

init_per_suite(Config) ->
    case prerequisites() of
        ok -> Config;
        {skip, _} = Skip -> Skip
    end.

end_per_suite(_Config) ->
    ok.

init_per_testcase(_TC, Config) ->
    Ctx = new_ctx(),
    cleanup(Ctx),
    try
        ok = setup_netns(Ctx),
        Extra = setup_testcase(_TC, Ctx),
        [{ctx, Ctx}, {tc_timeout, 30000} | Extra ++ Config]
    catch
        Class:Reason:Stacktrace ->
            cleanup(Ctx),
            erlang:raise(Class, Reason, Stacktrace)
    end.

end_per_testcase(_TC, Config) ->
    stop_erlkoenig_firewall(?config(erlkoenig_firewall_pid, Config)),
    stop_nfnl_server(?config(nfnl_server_pid, Config)),
    cleanup(?config(ctx, Config)),
    ok.

veth_pair_reaches_host(Config) ->
    Ctx = ?config(ctx, Config),
    ?assertEqual(ok, cmd_ok(fmt("ip netns exec ~s ping -c 1 -W 1 ~s",
                                [maps:get(ns, Ctx), maps:get(host_ip, Ctx)]))).

tcp_dport_18080_hits_accept_counter(Config) ->
    Ctx = ?config(ctx, Config),
    Before = counter_packets(Ctx, "tcp_hits"),
    _ = sh(fmt("ip netns exec ~s sh -c 'nc -z -w 1 ~s 18080 || true'",
               [maps:get(ns, Ctx), maps:get(host_ip, Ctx)])),
    After = counter_packets(Ctx, "tcp_hits"),
    ?assertEqual(Before + 1, After).

default_drop_counter_delta(Config) ->
    Ctx = ?config(ctx, Config),
    Before = counter_packets(Ctx, "default_drop"),
    _ = sh(fmt("ip netns exec ~s sh -c 'nc -z -w 1 ~s 18081 || true'",
               [maps:get(ns, Ctx), maps:get(host_ip, Ctx)])),
    After = counter_packets(Ctx, "default_drop"),
    ?assertEqual(Before + 1, After).

kernel_set_drop_counter_delta(Config) ->
    Ctx = ?config(ctx, Config),
    ok = cmd_ok(fmt("nft add element inet ~s banned \\{ ~s \\}",
                    [maps:get(table, Ctx), maps:get(ns_ip, Ctx)])),
    Before = counter_packets(Ctx, "ban_hits"),
    IcmpBefore = counter_packets(Ctx, "icmp_hits"),
    _ = sh(fmt("ip netns exec ~s ping -c 1 -W 1 ~s || true",
               [maps:get(ns, Ctx), maps:get(host_ip, Ctx)])),
    After = counter_packets(Ctx, "ban_hits"),
    IcmpAfter = counter_packets(Ctx, "icmp_hits"),
    ?assertEqual(Before + 1, After),
    ?assertEqual(IcmpBefore, IcmpAfter).

erlkoenig_firewall_config_applies_host_rules(Config) ->
    Ctx = ?config(ctx, Config),
    BeforeTcp = counter_packets(Ctx, "tcp_hits"),
    _ = sh(fmt("ip netns exec ~s sh -c 'nc -z -w 1 ~s 18080 || true'",
               [maps:get(ns, Ctx), maps:get(host_ip, Ctx)])),
    ?assertEqual(BeforeTcp + 1, counter_packets(Ctx, "tcp_hits")),

    BeforeDrop = counter_packets(Ctx, "default_drop"),
    _ = sh(fmt("ip netns exec ~s sh -c 'nc -z -w 1 ~s 18081 || true'",
               [maps:get(ns, Ctx), maps:get(host_ip, Ctx)])),
    ?assertEqual(BeforeDrop + 1, counter_packets(Ctx, "default_drop")),

    BeforeBan = counter_packets(Ctx, "ban_hits"),
    ok = erlkoenig_nft_firewall:ban(maps:get(ns_ip, Ctx)),
    _ = sh(fmt("ip netns exec ~s ping -c 1 -W 1 ~s || true",
               [maps:get(ns, Ctx), maps:get(host_ip, Ctx)])),
    ?assertEqual(BeforeBan + 1, counter_packets(Ctx, "ban_hits")).

setup_testcase(erlkoenig_firewall_config_applies_host_rules, Ctx) ->
    {ok, ServerPid} = nfnl_server:start_link([{name, erlkoenig_nft_srv}]),
    Config = erlkoenig_firewall_config(Ctx),
    case erlkoenig_nft_firewall:start_link(Config) of
        {ok, FirewallPid} ->
            [{nfnl_server_pid, ServerPid}, {erlkoenig_firewall_pid, FirewallPid}];
        {error, Reason} ->
            stop_nfnl_server(ServerPid),
            error({firewall_start_failed, Reason})
    end;
setup_testcase(_TC, Ctx) ->
    ok = setup_nft(Ctx),
    [{nfnl_server_pid, undefined}, {erlkoenig_firewall_pid, undefined}].

prerequisites() ->
    case os:cmd("id -u") of
        "0\n" ->
            case require_cmds(["ip", "nft", "ping", "nc", "sysctl"]) of
                ok ->
                    case require_runtime_free() of
                        ok -> require_net_admin();
                        {skip, _} = Skip -> Skip
                    end;
                {skip, _} = Skip -> Skip
            end;
        _ ->
            {skip, "host firewall harness requires root"}
    end.

require_cmds([]) ->
    ok;
require_cmds([Cmd | Rest]) ->
    case os:cmd("command -v " ++ Cmd) of
        [] -> {skip, "host firewall harness requires command: " ++ Cmd};
        _ -> require_cmds(Rest)
    end.

require_net_admin() ->
    Probe = "ekprobe" ++ integer_to_list(erlang:unique_integer([positive]) rem 100000),
    Cmd = "ip netns add " ++ Probe,
    Cleanup = "ip netns del " ++ Probe,
    case cmd_result(Cmd) of
        {0, _} ->
            _ = sh(Cleanup),
            ok;
        {_Code, Out} ->
            _ = sh(Cleanup),
            {skip, "host firewall harness requires CAP_NET_ADMIN: " ++ Out}
    end.

require_runtime_free() ->
    Names = [erlkoenig_nft_srv, erlkoenig_nft_firewall],
    Busy = [{Name, Pid} || Name <- Names,
                           (Pid = erlang:whereis(Name)) =/= undefined],
    case Busy of
        [] -> ok;
        _ -> {skip, "host firewall harness requires nft runtime stopped: " ++ fmt("~p", [Busy])}
    end.

new_ctx() ->
    Unique = erlang:unique_integer([positive]),
    Suffix = integer_to_list(Unique rem 100000),
    ThirdOctet = integer_to_list(1 + (Unique rem 200)),
    #{
        ns => "ekns" ++ Suffix,
        host_veth => "ekht" ++ Suffix,
        ns_veth => "ekct" ++ Suffix,
        table => "ekhfw" ++ Suffix,
        host_ip => "198.18." ++ ThirdOctet ++ ".1",
        ns_ip => "198.18." ++ ThirdOctet ++ ".2"
    }.

setup_netns(Ctx) ->
    Ns = maps:get(ns, Ctx),
    HostVeth = maps:get(host_veth, Ctx),
    NsVeth = maps:get(ns_veth, Ctx),
    HostIp = maps:get(host_ip, Ctx),
    NsIp = maps:get(ns_ip, Ctx),
    ok = cmd_ok("ip netns add " ++ Ns),
    ok = cmd_ok(fmt("ip link add ~s type veth peer name ~s", [HostVeth, NsVeth])),
    ok = cmd_ok(fmt("ip link set ~s netns ~s", [NsVeth, Ns])),
    ok = cmd_ok("sysctl -qw net.ipv6.conf." ++ HostVeth ++ ".disable_ipv6=1"),
    ok = cmd_ok(fmt("ip addr add ~s/24 dev ~s", [HostIp, HostVeth])),
    ok = cmd_ok("ip link set " ++ HostVeth ++ " up"),
    ok = cmd_ok(fmt("ip netns exec ~s sysctl -qw net.ipv6.conf.~s.disable_ipv6=1",
                    [Ns, NsVeth])),
    ok = cmd_ok(fmt("ip netns exec ~s ip addr add ~s/24 dev ~s", [Ns, NsIp, NsVeth])),
    ok = cmd_ok(fmt("ip netns exec ~s ip link set lo up", [Ns])),
    ok = cmd_ok(fmt("ip netns exec ~s ip link set ~s up", [Ns, NsVeth])),
    ok = wait_link_ready(Ctx),
    ok = wait_connectivity(Ctx),
    ok.

setup_nft(Ctx) ->
    Table = maps:get(table, Ctx),
    HostVeth = maps:get(host_veth, Ctx),
    ScriptPath = "/tmp/" ++ Table ++ ".nft",
    Script = nft_setup_script(Table, HostVeth),
    ok = file:write_file(ScriptPath, Script),
    try
        ok = cmd_ok("nft -f " ++ ScriptPath)
    after
        _ = file:delete(ScriptPath)
    end.

erlkoenig_firewall_config(Ctx) ->
    Table = list_to_binary(maps:get(table, Ctx)),
    HostVeth = list_to_binary(maps:get(host_veth, Ctx)),
    #{
        table => Table,
        ban_set => #{ipv4 => <<"banned">>},
        counters => [<<"tcp_hits">>, <<"ban_hits">>, <<"default_drop">>],
        sets => [{<<"banned">>, ipv4_addr, #{flags => [timeout]}}],
        chains => [
            #{
                name => <<"input">>,
                type => filter,
                hook => input,
                priority => -150,
                policy => accept,
                rules => [
                    {rule, drop, #{iif => HostVeth,
                                   set => <<"banned">>,
                                   counter => <<"ban_hits">>}},
                    {rule, accept, #{iif => HostVeth,
                                     tcp => 18080,
                                     counter => <<"tcp_hits">>}},
                    {rule, drop, #{iif => HostVeth,
                                   counter => <<"default_drop">>}}
                ]
            }
        ]
    }.

nft_setup_script(Table, HostVeth) ->
    Veth = nft_string(HostVeth),
    lines([
        "add table inet " ++ Table,
        "add counter inet " ++ Table ++ " tcp_hits",
        "add counter inet " ++ Table ++ " icmp_hits",
        "add counter inet " ++ Table ++ " ban_hits",
        "add counter inet " ++ Table ++ " default_drop",
        "add set inet " ++ Table ++ " banned { type ipv4_addr; }",
        "add chain inet " ++ Table ++ " input { type filter hook input priority -150; policy accept; }",
        "add rule inet " ++ Table ++ " input iifname " ++ Veth ++
            " ip saddr @banned counter name ban_hits drop",
        "add rule inet " ++ Table ++ " input iifname " ++ Veth ++
            " ip protocol icmp counter name icmp_hits accept",
        "add rule inet " ++ Table ++ " input iifname " ++ Veth ++
            " tcp dport 18080 counter name tcp_hits accept",
        "add rule inet " ++ Table ++ " input iifname " ++ Veth ++
            " counter name default_drop drop"
    ]).

lines(Lines) ->
    [[Line, "\n"] || Line <- Lines].

wait_link_ready(Ctx) ->
    HostVeth = maps:get(host_veth, Ctx),
    Ns = maps:get(ns, Ctx),
    NsVeth = maps:get(ns_veth, Ctx),
    wait_until(fun() ->
                       cmd_result("ip link show dev " ++ HostVeth ++ " | grep -q 'state UP'") =:= {0, []}
                           andalso
                           cmd_result(fmt("ip netns exec ~s ip link show dev ~s | grep -q 'state UP'",
                                          [Ns, NsVeth])) =:= {0, []}
               end, 30, 100).

wait_connectivity(Ctx) ->
    Ns = maps:get(ns, Ctx),
    HostIp = maps:get(host_ip, Ctx),
    wait_until(fun() ->
                       {Code, _Out} = cmd_result(fmt("ip netns exec ~s ping -c 1 -W 1 ~s",
                                                     [Ns, HostIp])),
                       Code =:= 0
               end, 3, 250).

wait_until(_Fun, 0, _SleepMs) ->
    error(link_not_ready);
wait_until(Fun, Attempts, SleepMs) ->
    case Fun() of
        true ->
            ok;
        false ->
            timer:sleep(SleepMs),
            wait_until(Fun, Attempts - 1, SleepMs)
    end.

cleanup(undefined) ->
    ok;
cleanup(Ctx) ->
    _ = sh("nft delete table inet " ++ maps:get(table, Ctx)),
    _ = sh("ip link del " ++ maps:get(host_veth, Ctx)),
    _ = sh("ip netns del " ++ maps:get(ns, Ctx)),
    ok.

stop_erlkoenig_firewall(undefined) ->
    ok;
stop_erlkoenig_firewall(Pid) when is_pid(Pid) ->
    _ = catch gen_server:stop(Pid, normal, 5000),
    ok.

stop_nfnl_server(undefined) ->
    ok;
stop_nfnl_server(Pid) when is_pid(Pid) ->
    _ = catch nfnl_server:stop(Pid),
    ok.

counter_packets(Ctx, Counter) ->
    Out = sh("nft list counter inet " ++ maps:get(table, Ctx) ++ " " ++ Counter),
    case re:run(Out, "packets ([0-9]+)", [{capture, [1], list}]) of
        {match, [N]} -> list_to_integer(N);
        nomatch -> error({counter_parse_failed, Counter, Out})
    end.

cmd_ok(Cmd) ->
    case cmd_result(Cmd) of
        {0, _Out} -> ok;
        {Code, Out} -> error({cmd_failed, Cmd, Code, Out})
    end.

cmd_result(Cmd) ->
    Marker = "__EK_RC:",
    Wrapped = Cmd ++ "\nRC=$?\nprintf '\\n" ++ Marker ++ "%s\\n' \"$RC\"\nexit 0",
    Out = sh(Wrapped),
    case re:run(Out, Marker ++ "([0-9]+)", [{capture, [1], list}]) of
        {match, [Code]} ->
            {list_to_integer(Code), strip_marker(Out, Marker)};
        nomatch ->
            {127, Out}
    end.

strip_marker(Out, Marker) ->
    case string:find(Out, "\n" ++ Marker) of
        nomatch -> Out;
        Prefix -> lists:sublist(Out, length(Out) - length(Prefix))
    end.

sh(Cmd) ->
    os:cmd("sh -c " ++ shell_quote(Cmd) ++ " 2>&1").

fmt(Fmt, Args) ->
    lists:flatten(io_lib:format(Fmt, Args)).

nft_string(S) ->
    "\"" ++ nft_string_chars(S) ++ "\"".

nft_string_chars([]) ->
    [];
nft_string_chars([$" | Rest]) ->
    "\\\"" ++ nft_string_chars(Rest);
nft_string_chars([$\\ | Rest]) ->
    "\\\\" ++ nft_string_chars(Rest);
nft_string_chars([C | Rest]) ->
    [C | nft_string_chars(Rest)].

shell_quote(S) ->
    "'" ++ quote_chars(S) ++ "'".

quote_chars([]) ->
    [];
quote_chars([$' | Rest]) ->
    "'\\''" ++ quote_chars(Rest);
quote_chars([C | Rest]) ->
    [C | quote_chars(Rest)].
