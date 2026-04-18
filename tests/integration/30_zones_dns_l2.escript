#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 30: Networking primitives — DNS resolution, L2 isolation,
%%         host-slave criticality.
%%
%% Spawns a tutorial-shaped stack (web + api in zone "net30") with no
%% per-container nft (so DNS / ICMP can flow freely), then verifies:
%%
%%   1. erlkoenig_dns answers `app-0-api.erlkoenig` from inside web's
%%      netns with web's gateway as resolver
%%   2. ARP from web → api's IP returns *no* responses (L3S blocks L2)
%%   3. ICMP from web → api's IP works (L3 routing does)
%%   4. Removing the host-side slave breaks host → web TCP, leaves
%%      container ↔ container TCP intact
%%
%% Skips host nft + ct_guard from the tutorial DSL (host firewall would
%% drop test SSH; we only care about IPVLAN/DNS plumbing here).
-mode(compile).

-define(PARENT, "ek_net30_test").
-define(GW_CIDR, "10.99.30.1/24").

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 30: Networking primitives ===~n~n"),

    require_root(),
    require_ipvlan_module(),
    require_tools([arping, nslookup]),

    test_helper:boot(),
    logger:set_primary_config(level, warning),

    Root     = test_helper:project_root(),
    Example  = filename:join(Root, "examples/tutorial.exs"),
    TermFile = "/tmp/erlkoenig_integration_30.term",
    DemoBin  = binary_to_list(test_helper:demo("echo_server")),

    ensure_parent(),

    %% Park any pre-existing host nft tables that have a drop-policy
    %% input chain — they would compete with the host firewall this
    %% test installs and silently drop UDP/53 from the test subnet
    %% (which is exactly the behaviour we are trying to verify).
    %% Save state so we can put them back at the end.
    backup_competing_host_tables(),

    test_helper:step("compile + retarget tutorial.exs", fun() ->
        compile_dsl(Root, Example, TermFile),
        patch_term(TermFile, list_to_binary(DemoBin))
    end),

    test_helper:step("erlkoenig_config:load/1 -> 3 containers", fun() ->
        case erlkoenig_config:load(TermFile) of
            {ok, Names} when length(Names) =:= 3 -> ok;
            Other -> {error, {load, Other}}
        end
    end),

    test_helper:step("wait for 3 running", fun() ->
        wait_for_running(3, 30_000)
    end),
    timer:sleep(1500),

    {ok, WebPid} = find_pid(<<"app-0-web">>),
    {ok, ApiPid} = find_pid(<<"app-0-api">>),
    #{netns_path := NS,
      net_info   := #{ip := WebIp, iface := WebIface}}
        = erlkoenig:inspect(WebPid),
    #{net_info := #{ip := ApiIp}} = erlkoenig:inspect(ApiPid),
    NSStr     = ns_to_list(NS),
    WebIfStr  = binary_to_list(WebIface),
    ApiIpStr  = ip_to_string(ApiIp),
    WebIpStr  = ip_to_string(WebIp),

    io:format("    web=~s (iface ~s, netns ~s)~n",
              [WebIpStr, WebIfStr, NSStr]),
    io:format("    api=~s~n", [ApiIpStr]),

    %% --- DNS server-side check (from host) --------------------------
    %%
    %% We verify the DNS gen_server is alive and answers correct
    %% queries when reached over the host netns (where the test
    %% itself runs). Reaching it from inside a container netns is a
    %% separate concern — it requires the host nft input chain to
    %% allow UDP/53 from the container subnet, which the
    %% tutorial.exs host firewall does NOT do by default. That is
    %% documented as a chapter-5 caveat and is out of scope for this
    %% test (which would otherwise fail on any operator-grade host
    %% with a strict input policy).
    test_helper:step("DNS: gen_server up + answers from host", fun() ->
        Out = os:cmd("nslookup -timeout=2 -retry=1 "
                     "app-0-api.erlkoenig 10.99.30.1 2>&1"),
        case string:find(Out, ApiIpStr) of
            nomatch -> {error, {dns_no_answer, Out}};
            _       -> ok
        end
    end),

    %% End-to-end Glasbox check: with the Runtime-Services UDP/53 rule
    %% installed in the host firewall (per the Chapter 6 pattern that
    %% every example DSL now carries), a container can reach the
    %% gateway's DNS resolver and resolve sibling names. Without that
    %% rule the lookup would silently time out — that's the whole point
    %% of the explicit-not-magic discipline.
    test_helper:step("DNS: web container resolves app-0-api by name",
                     fun() ->
        Cmd = io_lib:format(
            "nsenter --net=~s nslookup -timeout=2 -retry=1 "
            "app-0-api.erlkoenig 10.99.30.1 2>&1",
            [NSStr]),
        Out = os:cmd(lists:flatten(Cmd)),
        case string:find(Out, ApiIpStr) of
            nomatch -> {error, {container_dns_blocked, Out}};
            _       -> ok
        end
    end),

    %% --- L2 isolation ------------------------------------------------

    test_helper:step("L2: arping web -> api returns 0 responses", fun() ->
        Cmd = io_lib:format(
            "nsenter --net=~s arping -c 2 -w 2 -I ~s ~s 2>&1; echo RC=$?",
            [NSStr, WebIfStr, ApiIpStr]),
        Out = os:cmd(lists:flatten(Cmd)),
        %% arping with 0 replies returns non-zero. Either way, we
        %% explicitly check for "Received 0 response" or non-zero RC.
        case {string:find(Out, "Received 0"),
              string:find(Out, "RC=0")} of
            {nomatch, {_, _}} ->
                {error, {arp_unexpectedly_succeeded, Out}};
            _ ->
                ok
        end
    end),

    %% --- L3 routing works in spite of L2 isolation -------------------

    test_helper:step("L3: ping web -> api works", fun() ->
        Cmd = io_lib:format(
            "nsenter --net=~s ping -c 1 -W 2 ~s >/dev/null 2>&1; echo $?",
            [NSStr, ApiIpStr]),
        case string:trim(os:cmd(lists:flatten(Cmd))) of
            "0" -> ok;
            Rc  -> {error, {ping_failed, Rc}}
        end
    end),

    %% --- Host-slave criticality --------------------------------------

    test_helper:step("host can reach web on 8080 via host-slave", fun() ->
        case gen_tcp:connect({10,99,30,2}, 8080,
                             [binary, {active, false}], 2000) of
            {ok, S} -> gen_tcp:close(S), ok;
            E       -> {error, {host_to_web_pre, E}}
        end
    end),

    HostSlave = "h." ?PARENT,
    test_helper:step("removing host-slave breaks host -> web", fun() ->
        os:cmd("ip link del " ++ HostSlave ++ " 2>&1"),
        timer:sleep(500),
        case gen_tcp:connect({10,99,30,2}, 8080,
                             [binary, {active, false}], 1500) of
            {error, _} -> ok;  %% expected
            {ok, S} ->
                gen_tcp:close(S),
                {error, host_to_web_still_works}
        end
    end),

    test_helper:step("container -> container still works", fun() ->
        Cmd = io_lib:format(
            "nsenter --net=~s bash -c 'echo ping > /dev/tcp/~s/4000 "
            "&& echo ok' 2>&1",
            [NSStr, ApiIpStr]),
        case string:find(os:cmd(lists:flatten(Cmd)), "ok") of
            nomatch -> {error, ct_to_ct_broke};
            _       -> ok
        end
    end),

    %% Cleanup
    test_helper:step("cleanup", fun() ->
        Pids = try pg:get_members(erlkoenig_pg, erlkoenig_cts)
               catch error:_ -> []
               end,
        test_helper:cleanup(Pids),
        file:delete(TermFile),
        cleanup_parent(),
        restore_competing_host_tables(),
        ok
    end),

    io:format("~n=== Test 30 bestanden ===~n~n"),
    halt(0).

%% ──────────────────────────────────────────────────────────────

require_root() ->
    case string:trim(os:cmd("id -u")) of
        "0" -> ok;
        _   -> io:format("ERROR: must run as root~n"), halt(1)
    end.

require_ipvlan_module() ->
    Out = os:cmd("modprobe ipvlan 2>&1; echo $?"),
    case lists:last(string:split(string:trim(Out), "\n", all)) of
        "0" -> ok;
        _   -> io:format("SKIP: ipvlan kernel module not available~n"),
               halt(77)
    end.

require_tools(Tools) ->
    Missing = [T || T <- Tools,
                    string:trim(os:cmd("command -v " ++ atom_to_list(T)
                                       ++ " >/dev/null && echo ok"))
                    =/= "ok"],
    case Missing of
        []     -> ok;
        _      -> io:format("SKIP: missing tools: ~p~n", [Missing]),
                  halt(77)
    end.

ensure_parent() ->
    os:cmd("ip link del h." ?PARENT " 2>/dev/null"),
    os:cmd("ip link del " ?PARENT " 2>/dev/null"),
    "0" = exit_code(os:cmd("ip link add " ?PARENT " type dummy 2>&1; echo $?")),
    "0" = exit_code(os:cmd("ip addr add " ?GW_CIDR " dev " ?PARENT " 2>&1; echo $?")),
    "0" = exit_code(os:cmd("ip link set " ?PARENT " up 2>&1; echo $?")),
    ok.

cleanup_parent() ->
    os:cmd("ip link del h." ?PARENT " 2>/dev/null"),
    os:cmd("ip link del " ?PARENT " 2>/dev/null"),
    ok.

-define(NFT_BACKUP, "/tmp/erlkoenig_test30_nft_backup.nft").

%% Park any existing host nft tables that share the input hook with
%% drop policy (they would race with the firewall this test installs
%% and silently drop UDP/53 from the test subnet). State is dumped
%% to ?NFT_BACKUP so we can restore on the way out.
backup_competing_host_tables() ->
    %% Webserver-style operator firewalls are the common case on
    %% production-grade hosts (e.g. erlkoenig-2). Collect every host
    %% table that has at least one chain at hook=input policy=drop,
    %% then dump and delete just those.
    Listing = os:cmd("nft -a list ruleset 2>/dev/null"),
    case Listing of
        "" -> ok;
        _ ->
            Tables = candidates_to_park(Listing),
            case Tables of
                [] -> ok;
                _ ->
                    Dump = lists:foldl(fun({Family, Name}, Acc) ->
                        Acc ++ os:cmd("nft list table " ++ Family ++ " " ++
                                       Name ++ " 2>/dev/null")
                    end, "", Tables),
                    file:write_file(?NFT_BACKUP, Dump),
                    lists:foreach(fun({Family, Name}) ->
                        os:cmd("nft delete table " ++ Family ++ " " ++
                               Name ++ " 2>/dev/null")
                    end, Tables),
                    io:format("    parked ~p host nft table(s) "
                              "during test~n", [length(Tables)])
            end
    end.

restore_competing_host_tables() ->
    case filelib:is_regular(?NFT_BACKUP) of
        true ->
            os:cmd("nft -f " ?NFT_BACKUP " 2>&1"),
            file:delete(?NFT_BACKUP),
            ok;
        false ->
            ok
    end.

%% Walk `nft -a list ruleset' output and pick out any (Family, Name)
%% of a table that owns a chain hooked on input with policy drop —
%% but exclude erlkoenig's own tables so we don't tear down state
%% that the in-process BEAM owns.
candidates_to_park(Listing) ->
    Lines = string:split(Listing, "\n", all),
    {_, Tables} = lists:foldl(fun(L, {Cur, Acc}) ->
        Trim = string:trim(L),
        case Trim of
            "table " ++ Rest ->
                case string:split(Rest, " ", all) of
                    [Family, Name | _] ->
                        Clean = string:trim(string:trim(Name, trailing, "{}"),
                                            both, " "),
                        {{Family, Clean}, Acc};
                    _ -> {Cur, Acc}
                end;
            _ ->
                case Cur of
                    undefined -> {Cur, Acc};
                    {_F, N} = T ->
                        case is_input_drop_chain(Trim) andalso
                             not is_erlkoenig_owned(N) andalso
                             not lists:member(T, Acc) of
                            true  -> {Cur, [T | Acc]};
                            false -> {Cur, Acc}
                        end
                end
        end
    end, {undefined, []}, Lines),
    Tables.

is_input_drop_chain(Line) ->
    string:find(Line, "hook input") =/= nomatch andalso
    string:find(Line, "policy drop") =/= nomatch.

is_erlkoenig_owned("erlkoenig" ++ _) -> true;
is_erlkoenig_owned("ek_" ++ _)        -> true;
is_erlkoenig_owned(_)                 -> false.

compile_dsl(Root, Example, TermFile) ->
    DslDir = filename:join(Root, "dsl"),
    Snippet = io_lib:format(
                "[{mod, _} | _] = Code.compile_file(~p); mod.write!(~p)",
                [Example, TermFile]),
    Cmd = "cd " ++ DslDir ++
          " && MIX_ENV=test mix run --no-deps-check --no-compile -e " ++
          shell_quote(lists:flatten(Snippet)) ++ " 2>&1",
    Output = os:cmd(Cmd),
    case filelib:is_regular(TermFile) of
        true  -> ok;
        false -> {error, {term_not_created, Output}}
    end.

%% Retarget the dummy parent and subnet, drop per-container nft so
%% DNS / ICMP can flow inside the test, AND patch the host nft table:
%%  - SSH from tcp_dport 22222 (tutorial default) to 22 so the test
%%    runner's session isn't dropped when the new firewall lands;
%%  - Replace the runtime-services UDP/53 rule's source CIDR to match
%%    the test zone's actual subnet (10.99.30.0/24 instead of the
%%    tutorial's 10.99.0.0/24).
%% The ct_guard block is dropped — irrelevant for this test and would
%% only add noise.
patch_term(TermFile, BinPath) ->
    {ok, Config} = erlkoenig_config:parse(TermFile),
    Pods = [strip_pod_nft(patch_pod_binaries(P, BinPath))
            || P <- maps:get(pods, Config, [])],
    Zones = [retarget_zone(Z) || Z <- maps:get(zones, Config, [])],
    Host  = retarget_host(maps:get(host, Config, #{})),
    NftTables = [patch_host_nft(T) || T <- maps:get(nft_tables, Config, [])],
    Stripped = maps:without([ct_guard, guard], Config),
    Final = Stripped#{pods => Pods, zones => Zones, host => Host,
                      nft_tables => NftTables},
    file:write_file(TermFile, io_lib:format("~tp.~n", [Final])),
    ok.

patch_host_nft(#{name := <<"host">>, chains := Chains} = Table) ->
    NewChains = [patch_input_chain(C) || C <- Chains],
    Table#{chains => NewChains};
patch_host_nft(Table) -> Table.

patch_input_chain(#{name := <<"input">>, rules := Rules} = Chain) ->
    Patched = [patch_rule(R) || R <- Rules],
    Chain#{rules => Patched};
patch_input_chain(Chain) -> Chain.

%% SSH port 22222 → 22 (test runner's port).
patch_rule({accept, #{tcp_dport := 22222}}) ->
    {accept, #{tcp_dport => 22}};
%% Runtime-services rule: tutorial uses 10.99.0.0/24, test uses 10.99.30.0/24.
patch_rule({accept, #{ip_saddr := {10, 99, 0, 0, 24}, udp_dport := 53}}) ->
    {accept, #{ip_saddr => {10, 99, 30, 0, 24}, udp_dport => 53}};
patch_rule(R) -> R.

patch_pod_binaries(Pod, BinPath) ->
    Cts = [Ct#{binary => BinPath} || Ct <- maps:get(containers, Pod, [])],
    Pod#{containers => Cts}.

strip_pod_nft(Pod) ->
    Cts = [maps:without([nft], Ct) || Ct <- maps:get(containers, Pod, [])],
    Pod#{containers => Cts}.

retarget_zone(#{network := Net} = Zone) ->
    Zone#{name => <<"tutorial">>,
          subnet => {10, 99, 30, 0},
          netmask => 24,
          network => Net#{parent => list_to_binary(?PARENT),
                          subnet => {10, 99, 30, 0},
                          netmask => 24}};
retarget_zone(Zone) -> Zone.

retarget_host(#{network := Net} = Host) ->
    Host#{network => Net#{parent => list_to_binary(?PARENT),
                          subnet => {10, 99, 30, 0},
                          netmask => 24}};
retarget_host(Host) -> Host.

wait_for_running(N, TimeoutMs) ->
    wait_for_running(N, TimeoutMs, erlang:system_time(millisecond)).
wait_for_running(N, TimeoutMs, Start) ->
    Now = erlang:system_time(millisecond),
    case Now - Start > TimeoutMs of
        true -> {error, {timeout, N}};
        false ->
            Pids = try pg:get_members(erlkoenig_pg, erlkoenig_cts)
                   catch _:_ -> []
                   end,
            Running = [P || P <- Pids,
                            try #{state := running} = erlkoenig:inspect(P), true
                            catch _:_ -> false end],
            case length(Running) of
                N -> ok;
                _ -> timer:sleep(200),
                     wait_for_running(N, TimeoutMs, Start)
            end
    end.

find_pid(NameBin) ->
    Pids = try pg:get_members(erlkoenig_pg, erlkoenig_cts)
           catch _:_ -> [] end,
    Match = [P || P <- Pids,
                  try #{name := N} = erlkoenig:inspect(P),
                       N =:= NameBin
                  catch _:_ -> false end],
    case Match of
        [Pid | _] -> {ok, Pid};
        []        -> not_found
    end.

ns_to_list(NS) when is_list(NS)   -> NS;
ns_to_list(NS) when is_binary(NS) -> binary_to_list(NS).

ip_to_string({A,B,C,D}) ->
    integer_to_list(A) ++ "." ++ integer_to_list(B) ++ "." ++
    integer_to_list(C) ++ "." ++ integer_to_list(D).

exit_code(Str) ->
    Lines = [L || L <- string:split(string:trim(Str), "\n", all), L =/= ""],
    case Lines of [] -> ""; _ -> lists:last(Lines) end.

shell_quote(S) ->
    Escaped = lists:flatten(
                [case C of $' -> "'\\''"; Other -> Other end || C <- S]),
    "'" ++ Escaped ++ "'".
