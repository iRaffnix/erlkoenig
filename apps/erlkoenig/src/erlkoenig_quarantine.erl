%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_quarantine).
-moduledoc """
Crashloop circuit breaker for container binaries.

Records crash events keyed by the SHA-256 hash of the container's
binary. When the same hash crashes `threshold` times within
`window_ms`, the hash is marked quarantined and subsequent spawn
attempts for that hash are refused before any namespace work.

The breaker is per-node and memory-resident: a restart of the
erlkoenig application clears the quarantine list. Operators lift
quarantines explicitly via the public API or, coarser, by
restarting the service after the underlying issue is fixed.

## Configuration (sys.config)

- `quarantine_enabled`   — boolean, default `true`
- `quarantine_threshold` — crashes required, default `5`
- `quarantine_window_ms` — sliding window in ms, default `60_000`

## AMQP events

- `security.<hash-prefix>.quarantined`   on entry
- `security.<hash-prefix>.unquarantined` on exit

## Integration

Two touch points in `erlkoenig_ct`:

- `check/1` is called in the `creating` state before the C-runtime
  socket is opened. A quarantined hash aborts the spawn with
  `{error, {quarantined, Hash, Since}}`.
- `record_crash/1` is called from the `failed` and `restarting`
  state entry callbacks with the container's binary path. The
  hash is computed once per call.
""".

-behaviour(gen_server).

-export([start_link/0,
         check/1,
         record_crash/1,
         is_quarantined/1,
         quarantine/2,
         unquarantine/1,
         list/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(DEFAULT_THRESHOLD, 5).
-define(DEFAULT_WINDOW_MS, 60_000).

-type hash()      :: binary().     % lowercase hex SHA-256
-type crash_log() :: [integer()].  % unix-ms timestamps, newest first

-record(state, {
    enabled      :: boolean(),
    threshold    :: pos_integer(),
    window_ms    :: pos_integer(),
    crashes      :: #{hash() => crash_log()},
    quarantined  :: #{hash() => #{reason := term(), since := integer()}}
}).

%%====================================================================
%% Public API
%%====================================================================

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-doc """
Pre-spawn check. Called by `erlkoenig_ct:creating_do_spawn/1` before
the C-runtime socket is opened. Returns `ok` to proceed, or an error
aborting the spawn and transitioning the container to `failed`.

Accepts a binary path; the hash is computed internally.
""".
-spec check(binary() | string()) ->
    ok
  | {error, {quarantined, hash(), integer()}}
  | {error, term()}.
check(BinaryPath) ->
    case hash_path(BinaryPath) of
        {ok, Hash} ->
            case is_quarantined(Hash) of
                false         -> ok;
                {true, Since} -> {error, {quarantined, Hash, Since}}
            end;
        {error, Reason} ->
            {error, {hash_failed, Reason}}
    end.

-doc """
Record that a container using `BinaryPath` has crashed. Called from
the failed/restarting state entry callbacks in `erlkoenig_ct`.
Fire-and-forget; the crash is hashed and counted, and if the
threshold is exceeded the hash is quarantined.
""".
-spec record_crash(binary() | string()) -> ok.
record_crash(BinaryPath) ->
    gen_server:cast(?SERVER, {crash, BinaryPath}).

-spec is_quarantined(hash()) -> false | {true, integer()}.
is_quarantined(Hash) when is_binary(Hash) ->
    gen_server:call(?SERVER, {is_quarantined, Hash}).

-doc "Place a hash in quarantine manually. For operator use.".
-spec quarantine(hash(), term()) -> ok.
quarantine(Hash, Reason) when is_binary(Hash) ->
    gen_server:call(?SERVER, {quarantine, Hash, Reason}).

-doc "Lift a hash from quarantine manually.".
-spec unquarantine(hash()) -> ok.
unquarantine(Hash) when is_binary(Hash) ->
    gen_server:call(?SERVER, {unquarantine, Hash}).

-doc "Snapshot of the current quarantine list.".
-spec list() -> [{hash(), #{reason := term(), since := integer()}}].
list() -> gen_server:call(?SERVER, list).

%%====================================================================
%% gen_server
%%====================================================================

init([]) ->
    State = #state{
        enabled   = application:get_env(erlkoenig, quarantine_enabled, true),
        threshold = application:get_env(erlkoenig, quarantine_threshold,
                                        ?DEFAULT_THRESHOLD),
        window_ms = application:get_env(erlkoenig, quarantine_window_ms,
                                        ?DEFAULT_WINDOW_MS),
        crashes     = #{},
        quarantined = #{}
    },
    {ok, State}.

handle_call({is_quarantined, Hash}, _From, #state{quarantined = Q} = State) ->
    Reply = case maps:find(Hash, Q) of
        {ok, #{since := Since}} -> {true, Since};
        error                    -> false
    end,
    {reply, Reply, State};

handle_call({quarantine, Hash, Reason}, _From, State) ->
    {reply, ok, do_quarantine(Hash, Reason, State)};

handle_call({unquarantine, Hash}, _From,
            #state{quarantined = Q} = State) ->
    emit_event({binary_unquarantined, Hash}),
    {reply, ok, State#state{quarantined = maps:remove(Hash, Q)}};

handle_call(list, _From, #state{quarantined = Q} = State) ->
    {reply, maps:to_list(Q), State};

handle_call(_, _From, State) ->
    {reply, {error, badarg}, State}.

handle_cast({crash, _BinaryPath}, #state{enabled = false} = State) ->
    {noreply, State};
handle_cast({crash, BinaryPath}, State) ->
    case hash_path(BinaryPath) of
        {ok, Hash} ->
            {noreply, observe_crash(Hash, State)};
        {error, _} ->
            %% Binary vanished between crash and hashing. Nothing we can
            %% attribute the crash to — drop silently.
            {noreply, State}
    end;
handle_cast(_, State) -> {noreply, State}.

handle_info(_, State) -> {noreply, State}.

terminate(_Reason, _State) -> ok.
code_change(_Old, State, _Extra) -> {ok, State}.

%%====================================================================
%% Internal
%%====================================================================

-spec hash_path(binary() | string()) -> {ok, hash()} | {error, term()}.
hash_path(Path) ->
    case erlkoenig_sig:hash_file(Path) of
        {ok, HashBin} when is_binary(HashBin) -> {ok, HashBin};
        Other -> Other
    end.

-spec observe_crash(hash(), #state{}) -> #state{}.
observe_crash(Hash, #state{crashes = Crashes,
                           threshold = Threshold,
                           window_ms = Window} = State) ->
    Now = erlang:system_time(millisecond),
    Cutoff = Now - Window,
    Prior = maps:get(Hash, Crashes, []),
    Fresh = [T || T <- Prior, T >= Cutoff],
    Updated = [Now | Fresh],
    State2 = State#state{crashes = Crashes#{Hash => Updated}},
    case length(Updated) >= Threshold of
        true  -> do_quarantine(Hash, {crashloop, length(Updated), Window},
                               State2);
        false -> State2
    end.

-spec do_quarantine(hash(), term(), #state{}) -> #state{}.
do_quarantine(Hash, Reason, #state{quarantined = Q} = State) ->
    case maps:is_key(Hash, Q) of
        true  ->
            %% Already quarantined — keep the original reason so we
            %% can see the first offence, not the latest one.
            State;
        false ->
            Now = erlang:system_time(millisecond),
            Entry = #{reason => Reason, since => Now},
            emit_event({binary_quarantined, Hash, Reason}),
            State#state{quarantined = Q#{Hash => Entry}}
    end.

emit_event(Event) ->
    try erlkoenig_events:notify(Event)
    catch _:_ -> ok
    end.
