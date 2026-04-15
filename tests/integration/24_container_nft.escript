#!/usr/bin/env escript
%%% 24_container_nft.escript - Test CMD_NFT_SETUP (per-container firewall).
%%%
%%% Spawns a container, creates IPVLAN slave, configures IP,
%%% sends CMD_NFT_SETUP with a pre-built nft batch, then
%%% verifies rules with nsenter.
%%%
%%% Run: sudo escript tests/integration/24_container_nft.escript

-mode(compile).

main([]) ->
    io:format("=== CMD_NFT_SETUP Test ===~n~n"),

    case string:trim(os:cmd("id -u")) of
        "0" -> ok;
        _   -> io:format("ERROR: must run as root~n"), halt(1)
    end,

    true = code:add_patha(filename:dirname(escript:script_name())),
    Root = test_helper:project_root(),
    code:add_pathsz(filelib:wildcard("/opt/erlkoenig/lib/*/ebin")),
    code:add_pathsz(filelib:wildcard(
        filename:join(Root, "_build/default/lib/*/ebin"))),
    application:load(erlkoenig),

    %% Ensure dummy parent
    os:cmd("ip link show ek_ct0 2>/dev/null || (ip link add ek_ct0 type dummy && ip addr add 10.50.100.1/24 dev ek_ct0 && ip link set ek_ct0 up)"),

    %% 1. Spawn container
    io:format("1. Spawn...~n"),
    RtPath = test_helper:rt_binary(),
    Port = open_port({spawn_executable, RtPath},
                     [{packet, 4}, binary, exit_status, use_stdio]),
    port_command(Port, erlkoenig_proto:encode_handshake()),
    receive
        {Port, {data, HsReply}} ->
            ok = erlkoenig_proto:check_handshake_reply(HsReply)
    after 5000 -> io:format("TIMEOUT handshake~n"), halt(1) end,

    DemoBin = test_helper:demo("echo_server"),
    Cmd = erlkoenig_proto:encode_cmd_spawn(DemoBin, [<<"7777">>], [], 0, 0, 0),
    port_command(Port, Cmd),
    OsPid = receive
        {Port, {data, SpawnReply}} ->
            {ok, reply_container_pid, #{child_pid := P}} =
                erlkoenig_proto:decode(SpawnReply), P
    after 5000 -> io:format("TIMEOUT spawn~n"), halt(1) end,
    io:format("   pid=~p~n", [OsPid]),

    %% 2. Create IPVLAN slave
    io:format("2. IPVLAN slave...~n"),
    {ok, Sock} = erlkoenig_netlink:open(),
    Seq1 = erlkoenig_netlink:next_seq(),
    ok = socket:send(Sock, erlkoenig_netlink:msg_get_link(Seq1, <<"ek_ct0">>)),
    {ok, ParentIdx} = erlkoenig_netlink:recv_ifindex(Sock),
    Seq2 = erlkoenig_netlink:next_seq(),
    ok = erlkoenig_netlink:request(Sock,
           erlkoenig_netlink:msg_create_ipvlan(Seq2, <<"ipv.nfttest">>,
                                               ParentIdx, l3s, OsPid)),
    erlkoenig_netlink:close(Sock),
    io:format("   ipvlan slave created~n"),

    %% 3. CMD_NET_SETUP (IP + loopback UP, no gateway)
    io:format("3. NET_SETUP...~n"),
    NetCmd = erlkoenig_proto:encode_cmd_net_setup(
               <<"ipv.nfttest">>, {10,50,100,99}, 24, {0,0,0,0}),
    port_command(Port, NetCmd),
    receive
        {Port, {data, NetReply}} ->
            {ok, reply_ok, _} = erlkoenig_proto:decode(NetReply)
    after 10000 -> io:format("TIMEOUT net_setup~n"), halt(1) end,
    io:format("   OK~n"),

    %% 4. CMD_NFT_SETUP — the real test!
    io:format("4. NFT_SETUP...~n"),
    NftConfig = #{chains => [
        #{name => <<"output">>, hook => output, type => filter,
          priority => 0, policy => drop,
          rules => [{accept, #{ct => established}}, {accept, #{tcp => 4000}}]},
        #{name => <<"input">>, hook => input, type => filter,
          priority => 0, policy => drop,
          rules => [{accept, #{ct => established}}, {accept, #{tcp => 7777}}]}
    ]},
    Batch = erlkoenig_nft_container:build_batch(NftConfig, <<"ct_nfttest">>),
    io:format("   batch: ~b bytes~n", [byte_size(Batch)]),

    NftCmd = erlkoenig_proto:encode_cmd_nft_setup(Batch),
    port_command(Port, NftCmd),
    receive
        {Port, {data, NftReply}} ->
            case erlkoenig_proto:decode(NftReply) of
                {ok, reply_ok, _} ->
                    io:format("   CMD_NFT_SETUP: OK!~n");
                {ok, reply_error, #{code := Code, message := Msg}} ->
                    io:format("   CMD_NFT_SETUP FAILED: ~p ~s~n", [Code, Msg]),
                    cleanup(Port),
                    halt(1)
            end
    after 10000 ->
        io:format("   CMD_NFT_SETUP TIMEOUT~n"),
        cleanup(Port),
        halt(1)
    end,

    %% 5. Verify with nsenter
    io:format("5. Verify...~n"),
    Ruleset = os:cmd(io_lib:format(
        "nsenter --net=/proc/~B/ns/net nft list ruleset 2>&1", [OsPid])),
    io:format("~s~n", [Ruleset]),

    %% Check for expected content
    case string:find(Ruleset, "ct_nfttest") of
        nomatch ->
            io:format("FAILED: table ct_nfttest not found~n"),
            cleanup(Port),
            halt(1);
        _ -> io:format("   table ct_nfttest present~n")
    end,
    case string:find(Ruleset, "policy drop") of
        nomatch ->
            io:format("FAILED: policy drop not found~n"),
            cleanup(Port),
            halt(1);
        _ -> io:format("   policy drop present~n")
    end,

    %% 6. Cleanup
    cleanup(Port),
    io:format("~n=== CMD_NFT_SETUP TEST PASSED ===~n"),
    halt(0).

cleanup(Port) ->
    port_command(Port, erlkoenig_proto:encode_cmd_kill(9)),
    receive {Port, {data, _}} -> ok after 5000 -> ok end,
    receive {Port, {data, _}} -> ok after 5000 -> ok end,
    port_close(Port).

