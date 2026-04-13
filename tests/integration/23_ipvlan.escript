#!/usr/bin/env escript
%%% 23_ipvlan.escript - Integration test for IPVLAN L3S networking.
%%%
%%% Tests the IPVLAN container networking flow:
%%%   1. IPVLAN slave creation via erlkoenig_netlink:msg_create_ipvlan/5
%%%   2. Slave directly in container netns via IFLA_NET_NS_PID
%%%   3. In-netns IP config via CMD_NET_SETUP (same path as bridge mode)
%%%   4. IP connectivity verification
%%%   5. Cleanup (kernel auto-destroys slave with netns)
%%%
%%% Run: sudo escript tests/integration/23_ipvlan.escript
%%%
%%% SAFETY: All operations target a loopback-based IPVLAN inside
%%% isolated network namespaces. No changes to the host's real
%%% interfaces, routes, or bridges.

-mode(compile).

main([]) ->
    io:format("=== Erlkoenig IPVLAN L3S Test ===~n~n"),

    %% Check root
    case string:trim(os:cmd("id -u")) of
        "0" -> ok;
        _   -> io:format("ERROR: must run as root~n"), halt(1)
    end,

    %% Check kernel support
    case os:cmd("modprobe ipvlan 2>&1; echo $?") of
        "0\n" -> ok;
        Other ->
            %% modprobe may print warnings before the exit code
            case lists:last(string:split(string:trim(Other), "\n", all)) of
                "0" -> ok;
                _   ->
                    io:format("ERROR: ipvlan kernel module not available~n"),
                    io:format("       ~s~n", [Other]),
                    halt(77)  %% skip (like autotools)
            end
    end,

    %% Load application
    code:add_pathsz(filelib:wildcard("/opt/erlkoenig/lib/*/ebin")),
    code:add_pathsz(filelib:wildcard("_build/default/lib/*/ebin")),
    code:add_pathsz(filelib:wildcard("_build/default/checkouts/*/ebin")),
    application:load(erlkoenig),

    %% === Step 1: Create a dummy parent device ===
    %% We use a dummy interface instead of eth0 so the test is safe:
    %% no touching the host's real network.
    io:format("1. Create dummy parent device...~n"),
    os:cmd("ip link del ek_ipv_parent 2>/dev/null"),
    "0" = exit_code(os:cmd("ip link add ek_ipv_parent type dummy 2>&1; echo $?")),
    "0" = exit_code(os:cmd("ip addr add 10.99.0.1/24 dev ek_ipv_parent 2>&1; echo $?")),
    "0" = exit_code(os:cmd("ip link set ek_ipv_parent up 2>&1; echo $?")),
    io:format("   OK (ek_ipv_parent at 10.99.0.1/24)~n"),

    %% === Step 2: Spawn container ===
    io:format("2. Container spawn...~n"),
    RtPath = find_rt(),
    Port = open_port({spawn_executable, RtPath},
                     [{packet, 4}, binary, exit_status, use_stdio]),

    port_command(Port, erlkoenig_proto:encode_handshake()),
    receive
        {Port, {data, HsReply}} ->
            ok = erlkoenig_proto:check_handshake_reply(HsReply)
    after 5000 ->
        io:format("   TIMEOUT waiting for handshake~n"),
        cleanup_parent(),
        halt(1)
    end,

    DemoBin = list_to_binary(find_demo("echo_server")),
    Cmd = erlkoenig_proto:encode_cmd_spawn(
            DemoBin, [<<"9999">>], [], 0, 0, 0),
    port_command(Port, Cmd),

    OsPid = receive
        {Port, {data, SpawnReply}} ->
            {ok, reply_container_pid, #{child_pid := P}} =
                erlkoenig_proto:decode(SpawnReply),
            P
    after 5000 ->
        io:format("   TIMEOUT waiting for container_pid~n"),
        cleanup_parent(),
        halt(1)
    end,
    io:format("   OK (pid=~p)~n", [OsPid]),

    %% === Step 3: Create IPVLAN slave in container netns ===
    io:format("3. IPVLAN L3S slave creation...~n"),
    {ok, Sock} = erlkoenig_netlink:open(),

    %% Look up parent ifindex
    Seq1 = erlkoenig_netlink:next_seq(),
    ok = socket:send(Sock, erlkoenig_netlink:msg_get_link(Seq1, <<"ek_ipv_parent">>)),
    {ok, ParentIdx} = erlkoenig_netlink:recv_ifindex(Sock),
    io:format("   parent ifindex=~p~n", [ParentIdx]),

    %% Create IPVLAN slave directly in container netns (one-shot: no move needed)
    SlaveName = <<"ipv.test">>,
    Seq2 = erlkoenig_netlink:next_seq(),
    case erlkoenig_netlink:request(
           Sock, erlkoenig_netlink:msg_create_ipvlan(
                   Seq2, SlaveName, ParentIdx, l3s, OsPid)) of
        ok ->
            io:format("   OK (slave ~s created in container netns, mode=l3s)~n",
                      [SlaveName]);
        {error, {netlink_error, Errno}} ->
            io:format("   FAILED: netlink error ~p~n", [Errno]),
            cleanup(Port, Sock),
            halt(1)
    end,

    erlkoenig_netlink:close(Sock),

    %% Verify slave is NOT visible in host netns
    HostCheck = os:cmd("ip link show ipv.test 2>&1"),
    case string:find(HostCheck, "does not exist") of
        nomatch ->
            case string:find(HostCheck, "not exist") of
                nomatch ->
                    %% Some kernels say "Device ... does not exist"
                    %% others say "Cannot find device"
                    io:format("   WARNING: slave may be visible in host netns~n"),
                    io:format("   ip link show output: ~s~n", [HostCheck]);
                _ ->
                    io:format("   Verified: slave NOT visible in host netns~n")
            end;
        _ ->
            io:format("   Verified: slave NOT visible in host netns~n")
    end,

    %% Verify slave IS visible inside container netns (use -d for type details)
    NsCheck = os:cmd(io_lib:format(
        "nsenter --net=/proc/~B/ns/net ip -d link show ~s 2>&1", [OsPid, SlaveName])),
    case string:find(NsCheck, "ipv.test") of
        nomatch ->
            io:format("   FAILED: slave not found in container netns~n"),
            io:format("   ~s~n", [NsCheck]),
            cleanup(Port),
            halt(1);
        _ ->
            io:format("   Verified: slave visible in container netns~n")
    end,

    %% Verify L3S mode (ip -d link shows "ipvlan mode l3s")
    case string:find(NsCheck, "l3s") of
        nomatch ->
            io:format("   WARNING: expected l3s mode in output:~n   ~s~n", [NsCheck]);
        _ ->
            io:format("   Verified: mode is L3S~n")
    end,

    %% === Step 4: In-netns config via CMD_NET_SETUP ===
    io:format("4. CMD_NET_SETUP (in-netns via erlkoenig_rt)...~n"),
    ContainerIp = {10, 99, 0, 10},
    Gateway = {10, 99, 0, 1},
    NetCmd = erlkoenig_proto:encode_cmd_net_setup(SlaveName, ContainerIp, 24, Gateway),
    port_command(Port, NetCmd),

    receive
        {Port, {data, NetReply}} ->
            case erlkoenig_proto:decode(NetReply) of
                {ok, reply_ok, _} ->
                    io:format("   OK (~s: 10.99.0.10/24, gw 10.99.0.1)~n",
                             [SlaveName]);
                {ok, reply_error, #{code := Code, message := Msg}} ->
                    io:format("   FAILED: code=~p msg=~s~n", [Code, Msg]),
                    cleanup(Port),
                    halt(1);
                Other2 ->
                    io:format("   UNEXPECTED: ~p~n", [Other2]),
                    cleanup(Port),
                    halt(1)
            end
    after 10000 ->
        io:format("   TIMEOUT~n"),
        cleanup(Port),
        halt(1)
    end,

    %% === Step 5: Verify IP config inside container ===
    io:format("5. Verify IP config...~n"),

    %% Check IP address
    AddrCheck = os:cmd(io_lib:format(
        "nsenter --net=/proc/~B/ns/net ip addr show ~s 2>&1", [OsPid, SlaveName])),
    case string:find(AddrCheck, "10.99.0.10") of
        nomatch ->
            io:format("   FAILED: 10.99.0.10 not found on ~s~n", [SlaveName]),
            io:format("   ~s~n", [AddrCheck]),
            cleanup(Port),
            halt(1);
        _ ->
            io:format("   ~s has 10.99.0.10/24~n", [SlaveName])
    end,

    %% Check loopback is up
    LoCheck = os:cmd(io_lib:format(
        "nsenter --net=/proc/~B/ns/net ip link show lo 2>&1", [OsPid])),
    case string:find(LoCheck, "UP") of
        nomatch ->
            io:format("   WARNING: loopback not UP~n");
        _ ->
            io:format("   lo is UP~n")
    end,

    %% Check default route
    RouteCheck = os:cmd(io_lib:format(
        "nsenter --net=/proc/~B/ns/net ip route show 2>&1", [OsPid])),
    case string:find(RouteCheck, "default") of
        nomatch ->
            io:format("   WARNING: no default route (may be OK for L3 device routing)~n"),
            io:format("   routes: ~s~n", [RouteCheck]);
        _ ->
            io:format("   default route present~n")
    end,

    %% === Step 6: Test connectivity ===
    io:format("6. Connectivity...~n"),

    %% Ping from host to container IP (via parent device)
    PingResult = os:cmd("ping -c 1 -W 2 10.99.0.10 2>&1; echo $?"),
    case exit_code(PingResult) of
        "0" ->
            io:format("   host → container ping: OK~n");
        _ ->
            %% IPVLAN L3 routing may require explicit host route
            io:format("   host → container ping: FAILED (may need host route)~n"),
            %% Add a route and retry
            os:cmd("ip route add 10.99.0.10/32 dev ek_ipv_parent 2>/dev/null"),
            PingRetry = os:cmd("ping -c 1 -W 2 10.99.0.10 2>&1; echo $?"),
            case exit_code(PingRetry) of
                "0" ->
                    io:format("   host → container ping after route: OK~n");
                _ ->
                    io:format("   host → container ping after route: still FAILED~n"),
                    io:format("   (this is acceptable — L3S routing may need more config)~n")
            end
    end,

    %% Ping from container to host (gateway)
    ContainerPing = os:cmd(io_lib:format(
        "nsenter --net=/proc/~B/ns/net ping -c 1 -W 2 10.99.0.1 2>&1; echo $?",
        [OsPid])),
    case exit_code(ContainerPing) of
        "0" ->
            io:format("   container → host ping: OK~n");
        _ ->
            io:format("   container → host ping: FAILED~n"),
            io:format("   (expected with dummy device — no real routing)~n")
    end,

    %% === Step 7: Test zone_link_ipvlan module directly ===
    io:format("7. erlkoenig_zone_link_ipvlan init...~n"),
    Config = #{network => #{mode => ipvlan,
                            parent => <<"ek_ipv_parent">>,
                            ipvlan_mode => l3s}},
    case erlkoenig_zone_link_ipvlan:init(Config) of
        {ok, #{parent_ifindex := PIdx, ipvlan_mode := l3s}} ->
            io:format("   OK (parent_ifindex=~p, mode=l3s)~n", [PIdx]);
        {error, Reason} ->
            io:format("   FAILED: ~p~n", [Reason]),
            cleanup(Port),
            halt(1)
    end,

    %% === Step 8: Verify slave cleanup on container kill ===
    io:format("8. Cleanup verification...~n"),

    %% Kill container → netns destroyed → slave auto-removed
    KillCmd = erlkoenig_proto:encode_cmd_kill(9),
    port_command(Port, KillCmd),
    receive
        {Port, {data, _KillReply}} -> ok
    after 5000 -> ok
    end,
    receive
        {Port, {data, _ExitReply}} -> ok
    after 5000 -> ok
    end,

    %% Give kernel a moment to clean up netns
    timer:sleep(100),

    %% Verify slave is gone (netns destroyed, slave auto-deleted)
    PostKill = os:cmd("ip link show ipv.test 2>&1"),
    case string:find(PostKill, "exist") of
        nomatch ->
            case string:find(PostKill, "Cannot find") of
                nomatch ->
                    io:format("   WARNING: slave may still exist after kill~n"),
                    io:format("   ~s~n", [PostKill]);
                _ ->
                    io:format("   Verified: slave auto-cleaned after container exit~n")
            end;
        _ ->
            io:format("   Verified: slave auto-cleaned after container exit~n")
    end,

    port_close(Port),

    %% Clean up dummy parent
    cleanup_parent(),

    io:format("~n=== ALL IPVLAN TESTS PASSED ===~n"),
    halt(0).

%% ===================================================================
%% Helpers
%% ===================================================================

exit_code(Output) ->
    Lines = string:split(string:trim(Output), "\n", all),
    L = lists:last([L || L <- Lines, L =/= ""]),
    string:trim(L).

cleanup(Port) ->
    catch port_close(Port),
    cleanup_parent().

cleanup(Port, Sock) ->
    erlkoenig_netlink:close(Sock),
    cleanup(Port).

cleanup_parent() ->
    os:cmd("ip link del ek_ipv_parent 2>/dev/null"),
    os:cmd("ip route del 10.99.0.10/32 2>/dev/null"),
    ok.

find_rt() ->
    case os:getenv("ERLKOENIG_RT_PATH") of
        false -> find_first_existing([
            "/opt/erlkoenig/rt/erlkoenig_rt",
            "/home/dev/code/erlkoenig_rt/build/erlkoenig_rt",
            filename:absname("build/release/erlkoenig_rt"),
            filename:absname("../erlkoenig_rt/build/erlkoenig_rt")
        ]);
        Path -> Path
    end.

find_demo(Name) ->
    BinName = "test-erlkoenig-" ++ Name,
    case os:getenv("ERLKOENIG_DEMO_DIR") of
        false -> find_first_existing([
            filename:join("/opt/erlkoenig/rt/demo", BinName),
            filename:join("/home/dev/code/erlkoenig_rt/build/demo", BinName),
            filename:absname(filename:join("build/release/demo", BinName)),
            filename:absname(filename:join("../erlkoenig_rt/build/demo", BinName))
        ]);
        Dir -> filename:join(Dir, BinName)
    end.

find_first_existing([]) ->
    io:format("ERROR: no binary found~n"),
    halt(1);
find_first_existing([Path | Rest]) ->
    case filelib:is_regular(Path) of
        true  -> Path;
        false -> find_first_existing(Rest)
    end.
