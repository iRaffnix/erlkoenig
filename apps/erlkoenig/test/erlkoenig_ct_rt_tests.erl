%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%

-module(erlkoenig_ct_rt_tests).

-include_lib("eunit/include/eunit.hrl").
-include("erlkoenig_ct_state.hrl").

%% =================================================================
%% connect_to_runtime/1 handshake behaviour
%% =================================================================
%%
%% The C runtime (erlkoenig_rt.c::do_handshake) expects a version byte
%% as the FIRST frame on every fresh connection. Before this test,
%% connect_to_runtime/1 opened the socket and returned immediately, so
%% both reconnect call sites (recovering, disconnected) sent
%% CMD_QUERY_STATUS as the first frame — interpreted by the runtime as
%% a version byte 0x14 (=20), rejected, socket closed. BEAM-crash
%% recovery was silently 100% broken for this reason (on top of the
%% REPLY_STATUS decode drift that masked it).
%% =================================================================

connect_to_runtime_sends_handshake_first_test() ->
    {SockPath, LSock, ServerPid} = start_fake_rt_ok(),
    try
        Data = #ct_data{socket_path = list_to_binary(SockPath),
                        id = <<"test-ct">>},
        {ok, Sock} = erlkoenig_ct_rt:connect_to_runtime(Data),

        %% The fake server recorded the first frame it received BEFORE
        %% replying to the handshake. That frame must be the Erlang
        %% side's handshake (<<?PROTOCOL_VERSION:8>>), NOT CMD_QUERY_STATUS.
        ExpectedHS = erlkoenig_proto:encode_handshake(),
        ?assertEqual({ok, ExpectedHS}, recv_server_frame(ServerPid, 2000)),

        %% Socket must come back in {active, true} so subsequent
        %% query_status replies arrive as info messages.
        {ok, [{active, true}]} = inet:getopts(Sock, [active]),

        %% Send CMD_QUERY_STATUS; the fake server must now observe it
        %% as the SECOND frame.
        ok = gen_tcp:send(Sock, erlkoenig_proto:encode_cmd_query_status()),
        ExpectedQS = erlkoenig_proto:encode_cmd_query_status(),
        ?assertEqual({ok, ExpectedQS}, recv_server_frame(ServerPid, 2000)),

        ok = gen_tcp:close(Sock)
    after
        cleanup(SockPath, LSock, ServerPid)
    end.

connect_to_runtime_fails_on_wrong_handshake_reply_test() ->
    {SockPath, LSock, ServerPid} = start_fake_rt_bad_handshake(),
    try
        Data = #ct_data{socket_path = list_to_binary(SockPath),
                        id = <<"test-ct">>},
        %% check_handshake_reply rejects anything that's not v=1 or v=2,
        %% so the fake server's 0xFF reply is a clean protocol_mismatch.
        ?assertMatch({error, {handshake_failed, {protocol_mismatch, _, _}}},
                     erlkoenig_ct_rt:connect_to_runtime(Data))
    after
        cleanup(SockPath, LSock, ServerPid)
    end.

connect_to_runtime_fails_on_closed_socket_test() ->
    {SockPath, LSock, ServerPid} = start_fake_rt_close_immediately(),
    try
        Data = #ct_data{socket_path = list_to_binary(SockPath),
                        id = <<"test-ct">>},
        %% Server accepts then closes; the handshake send may succeed
        %% but the recv returns closed. Surfaced as handshake_recv.
        ?assertMatch({error, {handshake_recv, _}},
                     erlkoenig_ct_rt:connect_to_runtime(Data))
    after
        cleanup(SockPath, LSock, ServerPid)
    end.

%% =================================================================
%% Fake-RT helpers
%% =================================================================

%% Fake server that plays the C runtime's handshake contract correctly:
%% records the first incoming frame, replies with a valid handshake,
%% records the second incoming frame, then closes.
start_fake_rt_ok() ->
    start_fake_rt(fun fake_rt_ok_loop/2).

start_fake_rt_bad_handshake() ->
    start_fake_rt(fun fake_rt_bad_hs_loop/2).

start_fake_rt_close_immediately() ->
    start_fake_rt(fun fake_rt_close_loop/2).

start_fake_rt(LoopFun) ->
    SockPath = "/tmp/ek_test_rt_"
             ++ integer_to_list(erlang:unique_integer([positive])),
    _ = file:delete(SockPath),
    {ok, LSock} = gen_tcp:listen(0, [binary, {packet, 4}, {active, false},
                                     {ifaddr, {local, SockPath}}]),
    Self = self(),
    ServerPid = spawn_link(fun() -> LoopFun(LSock, Self) end),
    {SockPath, LSock, ServerPid}.

fake_rt_ok_loop(LSock, TestPid) ->
    {ok, Sock} = gen_tcp:accept(LSock, 3000),
    %% Record and reply to the handshake.
    case gen_tcp:recv(Sock, 0, 2000) of
        {ok, Frame1} ->
            TestPid ! {fake_rt_frame, self(), Frame1},
            ok = gen_tcp:send(Sock, erlkoenig_proto:encode_handshake()),
            %% Record whatever comes next.
            case gen_tcp:recv(Sock, 0, 2000) of
                {ok, Frame2} ->
                    TestPid ! {fake_rt_frame, self(), Frame2};
                _ -> ok
            end;
        _ -> ok
    end,
    _ = gen_tcp:close(Sock).

fake_rt_bad_hs_loop(LSock, _TestPid) ->
    {ok, Sock} = gen_tcp:accept(LSock, 3000),
    _ = gen_tcp:recv(Sock, 0, 2000),
    %% Reply with an unsupported version byte.
    ok = gen_tcp:send(Sock, <<16#FF>>),
    _ = gen_tcp:close(Sock).

fake_rt_close_loop(LSock, _TestPid) ->
    {ok, Sock} = gen_tcp:accept(LSock, 3000),
    _ = gen_tcp:close(Sock).

recv_server_frame(ServerPid, Timeout) ->
    receive
        {fake_rt_frame, ServerPid, Frame} -> {ok, Frame}
    after Timeout ->
        {error, timeout}
    end.

cleanup(SockPath, LSock, ServerPid) ->
    _ = gen_tcp:close(LSock),
    _ = file:delete(SockPath),
    case is_process_alive(ServerPid) of
        true  -> exit(ServerPid, shutdown);
        false -> ok
    end.
