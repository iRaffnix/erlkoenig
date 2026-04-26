%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%

-module(erlkoenig_ct_rt).
-moduledoc """
Runtime socket I/O helpers extracted from `erlkoenig_ct'.

Owns the Unix-domain connection to the C runtime
(`erlkoenig_rt`) — wire-level send/recv, active-mode toggles,
socket path derivation, reconnect on recovery, and the helper
that interprets best-effort setup-reply frames.

The functions here still accept `#ct_data{}' so they can peek at
the current socket and container id — this is intentional
coupling (Choice A) to keep the refactor purely mechanical. A
later pass can replace the record argument with explicit
`(Sock, Id)' pairs once the state machine itself has been
simplified.

Path-discovery (`rt_path/0', `find_rt/0' and friends) stays in
`erlkoenig_ct' for now and will move to `erlkoenig_ct_rt_discover'
in step 3b.
""".

-include("erlkoenig_ct_state.hrl").

-export([
    send_to_rt/2,
    rt_io_handle/1,
    maybe_set_active/2,
    socket_dir/0,
    make_socket_path/1,
    wait_and_connect/2,
    wait_and_connect/3,
    connect_to_runtime/1,
    kill_os_pid/1,
    sync_rt_command/3,
    handle_setup_reply/3
]).

%% -- Communication abstraction ------------------------------------

-doc """
Send data to C runtime via socket.

Returns `ok` when the bytes are handed to gen_tcp, or
`{error, not_connected}` when the state-machine's socket is
`undefined` (briefly during tcp_closed handling, or when a caller
in a non-connected state tries to send). User-visible commands
(stop/kill/resize/input) surface this error to their caller so
the operator sees an explicit failure rather than a silent
success that the runtime never observed.
""".
-spec send_to_rt(iodata(), #ct_data{}) -> ok | {error, not_connected}.
send_to_rt(Bin, #ct_data{sock = Sock}) when Sock =/= undefined ->
    ok = gen_tcp:send(Sock, Bin),
    ok;
send_to_rt(_Bin, #ct_data{id = Id}) ->
    logger:warning("container ~s: send_to_rt dropped — socket not set",
                   [Id]),
    {error, not_connected}.

-doc "Return the I/O handle for external modules (e.g. erlkoenig_net).".
-spec rt_io_handle(#ct_data{}) -> {socket, gen_tcp:socket()} | undefined.
rt_io_handle(#ct_data{sock = Sock}) when Sock =/= undefined ->
    {socket, Sock};
rt_io_handle(_) ->
    undefined.

-doc "Temporarily toggle socket active mode. No-op for port mode.".
-spec maybe_set_active(#ct_data{}, boolean()) -> ok.
maybe_set_active(#ct_data{sock = Sock}, Active)
  when Sock =/= undefined ->
    ok = inet:setopts(Sock, [{active, Active}]);
maybe_set_active(_, _) ->
    ok.

%% -- Socket helpers -----------------------------------------------

-doc "Get the socket directory from application config.".
-spec socket_dir() -> binary().
socket_dir() ->
    case application:get_env(erlkoenig, socket_dir, "/run/erlkoenig/") of
        Path when is_list(Path) -> list_to_binary(Path);
        Path when is_binary(Path) -> Path
    end.

-doc "Generate the socket path for a container. Must match erlkoenig-rt@.service.".
-spec make_socket_path(binary()) -> binary().
make_socket_path(ContainerId) ->
    Dir = socket_dir(),
    filename:join(Dir, <<ContainerId/binary, ".sock">>).

-doc "Wait for a Unix socket to appear and connect.".
%% Polls every 50ms until the socket is connectable or timeout.
-spec wait_and_connect(binary(), non_neg_integer()) ->
    {ok, gen_tcp:socket()} | {error, term()}.
wait_and_connect(SocketPath, Timeout) ->
    wait_and_connect(SocketPath, Timeout, 50).

-spec wait_and_connect(binary(), integer(), pos_integer()) ->
    {ok, gen_tcp:socket()} | {error, term()}.
wait_and_connect(_SocketPath, Timeout, _Interval) when Timeout =< 0 ->
    {error, timeout};
wait_and_connect(SocketPath, Timeout, Interval) ->
    SockPathStr = binary_to_list(SocketPath),
    case gen_tcp:connect({local, SockPathStr}, 0,
                         [binary, {packet, 4}, {active, false}], 1000) of
        {ok, Sock} ->
            {ok, Sock};
        {error, enoent} ->
            timer:sleep(Interval),
            wait_and_connect(SocketPath, Timeout - Interval, Interval);
        {error, econnrefused} ->
            timer:sleep(Interval),
            wait_and_connect(SocketPath, Timeout - Interval, Interval);
        {error, Reason} ->
            logger:warning("wait_and_connect: ~s failed: ~p (retrying)",
                          [SockPathStr, Reason]),
            timer:sleep(Interval),
            wait_and_connect(SocketPath, Timeout - Interval, Interval)
    end.

-doc """
Reconnect to a still-running C runtime's socket AND perform the
protocol handshake, returning a socket ready for commands.

The C runtime runs `do_handshake()` immediately after every
`accept4()` — the first frame on a fresh connection MUST be the
version byte. Opening a socket and sending CMD_QUERY_STATUS (or any
other command) directly gets rejected by the runtime with
"peer version 20, we speak 1" and the socket closed. Before this
was fixed every BEAM-crash recovery reconnect got dropped at the
handshake without either side noticing, then the (broken)
REPLY_STATUS decode further masked it.

Synchronous flow:
  1. open in `{active, false}` (we need blocking recv for the
     handshake reply — subsequent state-machine messages need
     `{active, true}`)
  2. send encode_handshake (one version byte, packet-4 framed)
  3. wait up to 2s for the handshake reply
  4. verify it with check_handshake_reply
  5. flip socket to `{active, true}` and return

On any failure the socket is closed and an explicit error is
returned so callers don't accidentally hold a half-connected
socket.
""".
-spec connect_to_runtime(#ct_data{}) ->
    {ok, gen_tcp:socket()} | {error, term()}.
connect_to_runtime(#ct_data{socket_path = undefined}) ->
    {error, no_socket_path};
connect_to_runtime(#ct_data{socket_path = SocketPath}) ->
    SockPathStr = binary_to_list(SocketPath),
    case gen_tcp:connect({local, SockPathStr}, 0,
                         [binary, {packet, 4}, {active, false}], 3000) of
        {ok, Sock} ->
            case do_reconnect_handshake(Sock) of
                ok ->
                    ok = inet:setopts(Sock, [{active, true}]),
                    {ok, Sock};
                {error, _} = Err ->
                    _ = gen_tcp:close(Sock),
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

%% Sync handshake used only on the reconnect path. The first-connect
%% path (creating_do_spawn) sends encode_handshake/0 asynchronously and
%% handles the reply via creating_handle_rt_data/3 — keep those flows
%% distinct to minimise blast radius.
-spec do_reconnect_handshake(gen_tcp:socket()) -> ok | {error, term()}.
do_reconnect_handshake(Sock) ->
    case gen_tcp:send(Sock, erlkoenig_proto:encode_handshake()) of
        ok ->
            case gen_tcp:recv(Sock, 0, 2000) of
                {ok, Reply} ->
                    case erlkoenig_proto:check_handshake_reply(Reply) of
                        ok -> ok;
                        {error, Reason} -> {error, {handshake_failed, Reason}}
                    end;
                {error, Reason} ->
                    {error, {handshake_recv, Reason}}
            end;
        {error, Reason} ->
            {error, {handshake_send, Reason}}
    end.

-doc "Kill a process by OS PID (used when socket is unavailable).".
-spec kill_os_pid(non_neg_integer() | undefined) -> ok.
kill_os_pid(undefined) -> ok;
kill_os_pid(Pid) when is_integer(Pid), Pid > 0 ->
    _ = os:cmd("kill -15 " ++ integer_to_list(Pid)),
    ok;
kill_os_pid(_) -> ok.

-doc "Send a command and synchronously wait for the reply.".
-spec sync_rt_command(#ct_data{}, iodata(), non_neg_integer()) ->
    {ok, binary()} | {error, term()}.
sync_rt_command(#ct_data{sock = Sock}, Cmd, Timeout) when Sock =/= undefined ->
    ok = inet:setopts(Sock, [{active, false}]),
    ok = gen_tcp:send(Sock, Cmd),
    %% Preserve the actual error reason. Callers used to see only the
    %% literal `timeout' regardless of whether the socket closed, the
    %% recv actually timed out, or something stranger happened, which
    %% hid broken-C-runtime scenarios behind a misleading label.
    Result = case gen_tcp:recv(Sock, 0, Timeout) of
        {ok, Reply}     -> {ok, Reply};
        {error, Reason} -> {error, Reason}
    end,
    ok = inet:setopts(Sock, [{active, true}]),
    Result.

-spec handle_setup_reply(binary(), binary(), string()) -> ok.
handle_setup_reply(Reply, Id, What) ->
    case erlkoenig_proto:decode(Reply) of
        {ok, reply_ok, _} ->
            logger:debug("container ~s: ~s attached", [Id, What]);
        {ok, reply_error, #{code := Code, message := Msg}} ->
            logger:warning("container ~s: ~s failed: ~p ~s (continuing without)",
                           [Id, What, Code, Msg])
    end.
