%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_journal_local).
-moduledoc """
`:journal.local` — first service capability built on the audit
hash chain.

A Unix-domain socket that workloads (typically containers) connect
to and stream structured log entries through. Every entry is
forwarded to `erlkoenig_audit:log/1`, so it gets a SHA-256 chain
link, an Ed25519 signature when signing is enabled, and lands in
the daily seal — i.e. it inherits all the tamper-evidence work
that SPEC-AS-005 stages 1-3 already deliver.

Wire format (one entry per line, newline-terminated):

```json
{"subject":"my-app","level":"info","msg":"started","fields":{"port":5432}}
```

Fields:
  - `subject` — workload identifier; surfaces as the audit event's
    `subject`. Required (defaults to `<<"unknown">>` when missing).
  - `level`   — free-form severity tag (`debug`, `info`, ...).
  - `msg`     — human-readable message.
  - `fields`  — arbitrary structured map preserved verbatim.

The daemon is non-authenticating in v1: a tenant can claim any
`subject`. This is acceptable because the strategic deployment
model is single-tenant per node (see strategy memo
2026-04-19-node-sovereign-architecture). Multi-tenant nodes will
bind the subject to peer credentials in a follow-up.
""".

-behaviour(gen_server).

%% API
-export([start_link/0, stop/0, socket_path/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

%% Internal — exported for the connection process spawn target
-export([conn_loop/2]).

-define(DEFAULT_PATH, "/run/erlkoenig/journal.sock").

-record(state, {
    socket_path   :: string(),
    listen_socket :: gen_tcp:socket() | undefined,
    acceptor      :: pid() | undefined
}).

%%%===================================================================
%%% API
%%%===================================================================

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-doc "Stop the daemon and remove its socket file.".
-spec stop() -> ok.
stop() ->
    gen_server:stop(?MODULE).

-doc "Path of the listening Unix socket.".
-spec socket_path() -> string().
socket_path() ->
    gen_server:call(?MODULE, socket_path).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    proc_lib:set_label(erlkoenig_journal_local),
    process_flag(trap_exit, true),
    Path = application:get_env(erlkoenig, journal_local_path, ?DEFAULT_PATH),
    case open_listen(Path) of
        {ok, Listen} ->
            Self = self(),
            Acceptor = spawn_link(fun() -> accept_loop(Listen, Self) end),
            logger:info("[journal.local] Listening on ~s", [Path]),
            {ok, #state{socket_path = Path,
                        listen_socket = Listen,
                        acceptor = Acceptor}};
        {error, Reason} ->
            logger:error("[journal.local] Cannot listen on ~s: ~p",
                         [Path, Reason]),
            {stop, {listen_failed, Reason}}
    end.

handle_call(socket_path, _From, #state{socket_path = Path} = State) ->
    {reply, Path, State};
handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

%% The acceptor is link-trapped; if it dies (e.g. listen socket closed
%% during shutdown), we just exit too. Per-connection processes are
%% NOT linked here — they live as long as the client keeps the socket
%% open and clean themselves up on tcp_closed/tcp_error.
handle_info({'EXIT', Pid, Reason}, #state{acceptor = Pid} = State) ->
    {stop, {acceptor_exit, Reason}, State};
handle_info({'EXIT', _Other, _Reason}, State) ->
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{listen_socket = Listen, socket_path = Path}) ->
    case Listen of
        undefined -> ok;
        _         -> _ = gen_tcp:close(Listen), ok
    end,
    %% Best effort — Path may already be gone if the test harness
    %% wiped it.
    _ = file:delete(Path),
    ok.

%%%===================================================================
%%% Internals
%%%===================================================================

%% Bind a `SOCK_STREAM` AF_UNIX listener via `gen_tcp` with the
%% `{ifaddr, {local, Path}}` option. Line framing keeps the protocol
%% trivially debuggable with `nc` / `socat`.
-spec open_listen(string()) -> {ok, gen_tcp:socket()} | {error, term()}.
open_listen(Path) ->
    %% Stale socket from a previous (crashed) run would block the
    %% bind with `eaddrinuse`; remove it. This is safe because two
    %% running instances on the same path are nonsensical.
    _ = file:delete(Path),
    case filelib:ensure_dir(Path) of
        ok ->
            gen_tcp:listen(0,
                [binary,
                 {packet, line},
                 {active, false},
                 {reuseaddr, true},
                 {ifaddr, {local, Path}}]);
        {error, _} = Err -> Err
    end.

accept_loop(Listen, Owner) ->
    case gen_tcp:accept(Listen) of
        {ok, Sock} ->
            ConnId = erlang:unique_integer([positive, monotonic]),
            %% NOT linked: a misbehaving client must not bring down
            %% the daemon. The conn process owns the FD lifetime.
            Pid = spawn(?MODULE, conn_loop, [Sock, ConnId]),
            case gen_tcp:controlling_process(Sock, Pid) of
                ok ->
                    Pid ! go;
                {error, _} = Err ->
                    %% Race: client closed before we handed off.
                    exit(Pid, controlling_failed),
                    logger:debug("[journal.local] handoff failed: ~p", [Err])
            end,
            accept_loop(Listen, Owner);
        {error, closed} ->
            ok;
        {error, Reason} ->
            logger:warning("[journal.local] accept failed: ~p", [Reason]),
            accept_loop(Listen, Owner)
    end.

%% Per-connection loop. Reads line-framed JSON, pushes each entry
%% into the audit chain. A bad line is logged and discarded — the
%% connection stays open so a buggy client doesn't lose the entries
%% that came before.
conn_loop(Sock, ConnId) ->
    receive go -> ok end,
    _ = inet:setopts(Sock, [{active, once}]),
    conn_recv(Sock, ConnId).

conn_recv(Sock, ConnId) ->
    receive
        {tcp, Sock, Line} ->
            handle_line(Line, ConnId),
            _ = inet:setopts(Sock, [{active, once}]),
            conn_recv(Sock, ConnId);
        {tcp_closed, Sock} -> ok;
        {tcp_error, Sock, _Reason} ->
            _ = gen_tcp:close(Sock),
            ok
    end.

handle_line(<<"\n">>, _ConnId) -> ok;
handle_line(Line, ConnId) ->
    Trimmed = strip_newline(Line),
    case Trimmed of
        <<>> -> ok;
        _ ->
            try json:decode(Trimmed) of
                Map when is_map(Map) ->
                    forward_to_audit(Map, ConnId);
                _ ->
                    logger:warning(
                      "[journal.local] non-object entry from conn ~p", [ConnId])
            catch C:R ->
                logger:warning(
                  "[journal.local] decode failed conn ~p: ~p:~p",
                  [ConnId, C, R])
            end
    end.

strip_newline(B) ->
    Sz = byte_size(B),
    case Sz of
        0 -> B;
        _ ->
            case binary:last(B) of
                $\n -> binary:part(B, 0, Sz - 1);
                _   -> B
            end
    end.

forward_to_audit(Map, ConnId) ->
    Subject = maps:get(<<"subject">>, Map, <<"unknown">>),
    Level   = maps:get(<<"level">>,   Map, <<"info">>),
    Msg     = maps:get(<<"msg">>,     Map, <<>>),
    Fields  = maps:get(<<"fields">>,  Map, #{}),
    erlkoenig_audit:log(#{
        type    => journal,
        subject => Subject,
        result  => ok,
        details => #{<<"level">>   => Level,
                     <<"msg">>     => Msg,
                     <<"fields">>  => Fields,
                     <<"conn_id">> => ConnId}
    }).
