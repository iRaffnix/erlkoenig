#!/usr/bin/env escript
%%% net_setup_test.escript - Integration test for Phase 3 networking.
%%%
%%% Tests the full container network setup flow:
%%%   1. Bridge creation (via erlkoenig_bridge gen_server)
%%%   2. Container spawn (via erlkoenig_rt port)
%%%   3. Host-side veth setup (via erlkoenig_netlink)
%%%   4. In-netns config via CMD_NET_SETUP
%%%   5. Cleanup
%%%
%%% Run: sudo escript test/net_setup_test.escript
%%%
%%% This test is safe for SSH: all network operations target
%%% the erlkoenig_br0 bridge and container network namespace,
%%% never the host's default route or primary interface.

-mode(compile).

main([]) ->
    io:format("=== Erlkoenig Network Setup Test ===~n~n"),

    %% Check root
    case string:trim(os:cmd("id -u")) of
        "0" -> ok;
        _   -> io:format("ERROR: must run as root~n"), halt(1)
    end,

    %% Load application — OTP release or local build
    code:add_pathsz(filelib:wildcard("/opt/erlkoenig/lib/*/ebin")),
    code:add_pathsz(filelib:wildcard("_build/default/lib/*/ebin")),
    code:add_pathsz(filelib:wildcard("_build/default/checkouts/*/ebin")),
    application:load(erlkoenig_core),

    %% Cleanup leftovers from previous runs
    os:cmd("ip link del veth_testnet0 2>/dev/null"),
    os:cmd("ip link del vp_testnet00 2>/dev/null"),
    os:cmd("ip link del erlkoenig_br0 2>/dev/null"),

    %% === Step 1: Test IP pool ===
    io:format("1. IP Pool...~n"),
    {ok, _} = erlkoenig_ip_pool:start_link(),
    {ok, {10,0,0,2}} = erlkoenig_ip_pool:allocate(),
    {ok, {10,0,0,3}} = erlkoenig_ip_pool:allocate(),
    erlkoenig_ip_pool:release({10,0,0,2}),
    {ok, {10,0,0,2}} = erlkoenig_ip_pool:allocate(),  %% recycled
    io:format("   OK (allocate, release, recycle)~n"),

    %% === Step 2: Test bridge ===
    io:format("2. Bridge...~n"),
    {ok, _} = erlkoenig_bridge:start_link(),
    BrIdx = erlkoenig_bridge:ifindex(),
    io:format("   OK (erlkoenig_br0, ifindex=~p)~n", [BrIdx]),

    %% Verify bridge exists
    BrCheck = string:trim(os:cmd("ip link show erlkoenig_br0 2>&1; echo $?")),
    Lines1 = string:split(BrCheck, "\n", all),
    "0" = lists:last(Lines1),
    io:format("   Verified: bridge visible via ip link~n"),

    %% === Step 3: Spawn container ===
    io:format("3. Container spawn...~n"),
    RtPath = find_rt(),
    Port = open_port({spawn_executable, RtPath},
                     [{packet, 4}, binary, exit_status, use_stdio]),

    %% Protocol handshake
    port_command(Port, erlkoenig_proto:encode_handshake()),
    receive
        {Port, {data, HsReply}} ->
            ok = erlkoenig_proto:check_handshake_reply(HsReply)
    after 5000 ->
        io:format("   TIMEOUT waiting for handshake~n"),
        halt(1)
    end,

    SleeperBin = list_to_binary(find_demo("sleeper")),
    Cmd = erlkoenig_proto:encode_cmd_spawn(
            SleeperBin, [<<"300">>], [], 0, 0, 0),
    port_command(Port, Cmd),

    {OsPid, _NsPath} = receive
        {Port, {data, SpawnReply}} ->
            {ok, reply_container_pid, #{child_pid := P, netns_path := N}} =
                erlkoenig_proto:decode(SpawnReply),
            {P, N}
    after 5000 ->
        io:format("   TIMEOUT waiting for container_pid~n"),
        halt(1)
    end,
    io:format("   OK (pid=~p, uid_map written by C runtime)~n", [OsPid]),

    %% === Step 4: Host-side veth setup ===
    io:format("4. Host-side veth...~n"),
    HostVeth = <<"veth_testnet0">>,
    PeerVeth = <<"vp_testnet00">>,  %% temp name, renamed after move

    {ok, Sock} = erlkoenig_netlink:open(),

    %% Create veth pair
    Seq1 = erlkoenig_netlink:next_seq(),
    ok = erlkoenig_netlink:request(
           Sock, erlkoenig_netlink:msg_create_veth(Seq1, HostVeth, PeerVeth)),
    io:format("   veth pair created~n"),

    %% Move container end into netns
    Seq2 = erlkoenig_netlink:next_seq(),
    ok = socket:send(Sock, erlkoenig_netlink:msg_get_link(Seq2, PeerVeth)),
    {ok, PeerIdx} = erlkoenig_netlink:recv_ifindex(Sock),
    Seq3 = erlkoenig_netlink:next_seq(),
    ok = erlkoenig_netlink:request(
           Sock, erlkoenig_netlink:msg_set_netns_by_pid(Seq3, PeerIdx, OsPid)),
    io:format("   eth0 moved to container netns~n"),

    %% Attach host end to bridge
    Seq4 = erlkoenig_netlink:next_seq(),
    ok = socket:send(Sock, erlkoenig_netlink:msg_get_link(Seq4, HostVeth)),
    {ok, HostIdx} = erlkoenig_netlink:recv_ifindex(Sock),
    Seq5 = erlkoenig_netlink:next_seq(),
    ok = erlkoenig_netlink:request(
           Sock, erlkoenig_netlink:msg_set_master(Seq5, HostIdx, BrIdx)),
    io:format("   veth attached to bridge~n"),

    %% Bring host end up
    Seq6 = erlkoenig_netlink:next_seq(),
    ok = erlkoenig_netlink:request(
           Sock, erlkoenig_netlink:msg_set_up(Seq6, HostIdx)),
    io:format("   host veth up~n"),

    erlkoenig_netlink:close(Sock),

    %% === Step 5: In-netns config via CMD_NET_SETUP ===
    io:format("5. CMD_NET_SETUP (in-netns via erlkoenig_rt)...~n"),
    NetCmd = erlkoenig_proto:encode_cmd_net_setup(
               PeerVeth, {10,0,0,2}, 24, {10,0,0,1}),
    port_command(Port, NetCmd),

    receive
        {Port, {data, NetReply}} ->
            case erlkoenig_proto:decode(NetReply) of
                {ok, reply_ok, _} ->
                    io:format("   OK (~s configured: 10.0.0.2/24, gw 10.0.0.1)~n",
                             [PeerVeth]);
                {ok, reply_error, #{code := Code, message := Msg}} ->
                    io:format("   FAILED: code=~p msg=~s~n", [Code, Msg]),
                    halt(1);
                Other ->
                    io:format("   UNEXPECTED: ~p~n", [Other]),
                    halt(1)
            end
    after 10000 ->
        io:format("   TIMEOUT~n"),
        halt(1)
    end,

    %% === Step 6: Verify connectivity ===
    io:format("6. Verify...~n"),

    %% Check that container's eth0 has the IP (via nsenter)
    NsCheck = os:cmd(
        io_lib:format("nsenter --net=/proc/~B/ns/net ip addr show ~s 2>&1",
                      [OsPid, PeerVeth])),
    case string:find(NsCheck, "10.0.0.2") of
        nomatch ->
            io:format("   FAILED: 10.0.0.2 not found on ~s~n", [PeerVeth]),
            io:format("   Output: ~s~n", [NsCheck]),
            halt(1);
        _ ->
            io:format("   ~s has 10.0.0.2/24~n", [PeerVeth])
    end,

    %% Ping from host to container
    PingResult = os:cmd("ping -c 1 -W 2 10.0.0.2 2>&1; echo $?"),
    PingLines = string:split(PingResult, "\n", all),
    PingExit = lists:last([L || L <- PingLines, L =/= ""]),
    case PingExit of
        "0" -> io:format("   ping 10.0.0.2: OK~n");
        _   -> io:format("   ping 10.0.0.2: FAILED~n"),
               io:format("   ~s~n", [PingResult])
               %% Don't halt -- ping may fail in some environments
    end,

    %% === Step 7: Cleanup ===
    io:format("7. Cleanup...~n"),

    %% Kill container
    KillCmd = erlkoenig_proto:encode_cmd_kill(9),
    port_command(Port, KillCmd),
    receive
        {Port, {data, _KillReply}} -> ok
    after 5000 -> ok
    end,

    %% Wait for exit notification
    receive
        {Port, {data, _ExitReply}} -> ok
    after 5000 -> ok
    end,

    %% Delete veth (host side)
    {ok, Sock2} = erlkoenig_netlink:open(),
    Seq7 = erlkoenig_netlink:next_seq(),
    ok = socket:send(Sock2, erlkoenig_netlink:msg_get_link(Seq7, HostVeth)),
    case erlkoenig_netlink:recv_ifindex(Sock2) of
        {ok, DelIdx} ->
            Seq8 = erlkoenig_netlink:next_seq(),
            erlkoenig_netlink:request(
              Sock2, erlkoenig_netlink:msg_delete_link(Seq8, DelIdx)),
            io:format("   veth deleted~n");
        _ ->
            io:format("   veth already gone~n")
    end,
    erlkoenig_netlink:close(Sock2),

    %% Stop bridge (deletes it)
    gen_server:stop(erlkoenig_bridge),
    io:format("   bridge deleted~n"),

    %% Close port
    port_close(Port),

    io:format("~n=== ALL TESTS PASSED ===~n"),
    halt(0).

%% Find erlkoenig_rt binary.
%% Search order: $ERLKOENIG_RT_PATH -> /opt/erlkoenig/rt -> build/release
find_rt() ->
    case os:getenv("ERLKOENIG_RT_PATH") of
        false -> find_rt_installed();
        Path  -> Path
    end.

find_rt_installed() ->
    Installed = "/opt/erlkoenig/rt/erlkoenig_rt",
    case filelib:is_regular(Installed) of
        true  -> Installed;
        false -> filename:absname("build/release/erlkoenig_rt")
    end.

%% Find a demo binary by short name (e.g. "sleeper").
%% Search order: $ERLKOENIG_DEMO_DIR -> /opt/erlkoenig/rt/demo -> build/release/demo
find_demo(Name) ->
    BinName = "test-erlkoenig-" ++ Name,
    case os:getenv("ERLKOENIG_DEMO_DIR") of
        false -> find_demo_installed(BinName);
        Dir   -> filename:join(Dir, BinName)
    end.

find_demo_installed(BinName) ->
    Installed = filename:join("/opt/erlkoenig/rt/demo", BinName),
    case filelib:is_regular(Installed) of
        true  -> Installed;
        false -> filename:absname(filename:join("build/release/demo", BinName))
    end.
