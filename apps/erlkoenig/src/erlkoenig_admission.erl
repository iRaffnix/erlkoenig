%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_admission).
-moduledoc """
Admission control for container spawns.

A bounded-concurrency gate that sits immediately before the
expensive parts of the spawn path (Unix-socket connect and
CMD_SPAWN). Limits the number of in-flight spawns on the host, and
optionally per zone, so a burst of `erlkoenig_config:load/1` calls
can't thrash the C runtime or the kernel.

Usage from `erlkoenig_ct`:

```erlang
case erlkoenig_admission:acquire(Zone, 30_000) of
    {ok, Token}    -> do_the_spawn(Data),
                      erlkoenig_admission:release(Token);
    {error, timeout} -> fail_with(admission_timeout)
end.
```

## Configuration (sys.config)

- `admission_max_host`    — global cap, default `10`
- `admission_max_per_zone` — per-zone cap, default `0` (disabled)
- `admission_queue_limit` — max queued waiters, default `100`

## Events

- `admission.<scope>.waiting`  emitted once a caller starts waiting
- `admission.<scope>.accepted` emitted when a token is handed out
- `admission.<scope>.timeout`  emitted when a caller gives up
""".

-behaviour(gen_server).

-export([start_link/0,
         acquire/1, acquire/2,
         release/1,
         snapshot/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(DEFAULT_MAX_HOST, 10).
-define(DEFAULT_MAX_ZONE, 0).      % 0 = disabled
-define(DEFAULT_QUEUE_LIMIT, 100).
-define(DEFAULT_TIMEOUT_MS, 30_000).

-type scope() :: host | {zone, binary()} | binary() | atom().
-type token() :: reference().

-record(waiter, {
    token   :: token(),
    from    :: gen_server:from(),
    scope   :: scope(),
    timer   :: reference() | undefined,
    started :: integer()
}).

-record(state, {
    max_host       :: non_neg_integer(),
    max_per_zone   :: non_neg_integer(),
    queue_limit    :: non_neg_integer(),
    host_in_flight :: non_neg_integer(),
    zone_in_flight :: #{binary() => non_neg_integer()},
    holders        :: #{token() => scope()},
    waiters        :: [#waiter{}]
}).

%%====================================================================
%% Public API
%%====================================================================

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-doc "Acquire a token with the default timeout (30s).".
-spec acquire(scope()) -> {ok, token()} | {error, timeout | queue_full}.
acquire(Scope) -> acquire(Scope, ?DEFAULT_TIMEOUT_MS).

-doc """
Acquire a token.

`Scope` is either `host` (global count only) or a zone name — a
binary or atom. Zone-scoped calls count against both the host cap
and the per-zone cap.

Blocks until a token is available or `Timeout` milliseconds pass.
Returns `{error, timeout}` on timeout, `{error, queue_full}` if the
waiter queue is already full, or `{ok, Token}` where `Token` must be
handed back via `release/1`.
""".
-spec acquire(scope(), pos_integer()) ->
    {ok, token()} | {error, timeout | queue_full}.
acquire(Scope, Timeout) when is_integer(Timeout), Timeout > 0 ->
    Token = make_ref(),
    try gen_server:call(?SERVER,
                        {acquire, Scope, Token, Timeout},
                        Timeout + 1_000) of
        {ok, Token} -> {ok, Token};
        {error, _} = E -> E
    catch
        exit:{timeout, _} -> {error, timeout}
    end.

-doc """
Return a previously-acquired token. Idempotent — releasing a token
twice (or an unknown token) is a no-op.
""".
-spec release(token()) -> ok.
release(Token) when is_reference(Token) ->
    gen_server:cast(?SERVER, {release, Token}).

-doc "Snapshot for dashboards and eunit introspection.".
-spec snapshot() -> #{host_in_flight := non_neg_integer(),
                      zone_in_flight := #{binary() => non_neg_integer()},
                      queued := non_neg_integer()}.
snapshot() -> gen_server:call(?SERVER, snapshot).

%%====================================================================
%% gen_server
%%====================================================================

init([]) ->
    State = #state{
        max_host     = application:get_env(erlkoenig, admission_max_host,
                                           ?DEFAULT_MAX_HOST),
        max_per_zone = application:get_env(erlkoenig, admission_max_per_zone,
                                           ?DEFAULT_MAX_ZONE),
        queue_limit  = application:get_env(erlkoenig, admission_queue_limit,
                                           ?DEFAULT_QUEUE_LIMIT),
        host_in_flight = 0,
        zone_in_flight = #{},
        holders = #{},
        waiters = []
    },
    {ok, State}.

handle_call({acquire, Scope, Token, Timeout}, From, State) ->
    case can_admit(Scope, State) of
        true ->
            State2 = record_admit(Scope, Token, State),
            emit_event(accepted, Scope),
            {reply, {ok, Token}, State2};
        false ->
            case length(State#state.waiters) >= State#state.queue_limit of
                true ->
                    {reply, {error, queue_full}, State};
                false ->
                    TRef = erlang:send_after(Timeout, self(),
                                             {timeout_waiter, Token}),
                    Waiter = #waiter{token = Token, from = From,
                                     scope = Scope, timer = TRef,
                                     started = erlang:system_time(millisecond)},
                    emit_event(waiting, Scope),
                    {noreply, State#state{waiters =
                        State#state.waiters ++ [Waiter]}}
            end
    end;

handle_call(snapshot, _From,
            #state{host_in_flight = H, zone_in_flight = Z,
                   waiters = W} = State) ->
    {reply, #{host_in_flight => H,
              zone_in_flight => Z,
              queued => length(W)}, State}.

handle_cast({release, Token}, State) ->
    {noreply, drain_after_release(do_release(Token, State))};
handle_cast(_, State) -> {noreply, State}.

handle_info({timeout_waiter, Token}, State) ->
    case take_waiter(Token, State#state.waiters) of
        {ok, #waiter{from = From, scope = Scope}, Rest} ->
            gen_server:reply(From, {error, timeout}),
            emit_event(timeout, Scope),
            {noreply, State#state{waiters = Rest}};
        not_found ->
            %% Raced with admit — token already handed out, nothing to do.
            {noreply, State}
    end;
handle_info(_, State) -> {noreply, State}.

terminate(_, _) -> ok.
code_change(_, State, _) -> {ok, State}.

%%====================================================================
%% Internal
%%====================================================================

-spec can_admit(scope(), #state{}) -> boolean().
can_admit(_, #state{max_host = 0}) -> true;  % 0 = unlimited
can_admit(host, #state{host_in_flight = H, max_host = Max}) ->
    H < Max;
can_admit(Zone, #state{host_in_flight = H, max_host = MaxH,
                       zone_in_flight = ZF, max_per_zone = MaxZ})
  when Zone =/= host ->
    ZoneCount = maps:get(to_zone_key(Zone), ZF, 0),
    H < MaxH andalso (MaxZ =:= 0 orelse ZoneCount < MaxZ).

-spec record_admit(scope(), token(), #state{}) -> #state{}.
record_admit(host, Token, State) ->
    State#state{
        host_in_flight = State#state.host_in_flight + 1,
        holders = (State#state.holders)#{Token => host}
    };
record_admit(Zone, Token, State) ->
    Key = to_zone_key(Zone),
    ZF = State#state.zone_in_flight,
    State#state{
        host_in_flight = State#state.host_in_flight + 1,
        zone_in_flight = ZF#{Key => maps:get(Key, ZF, 0) + 1},
        holders = (State#state.holders)#{Token => Zone}
    }.

-spec do_release(token(), #state{}) -> #state{}.
do_release(Token, #state{holders = Holders} = State) ->
    case maps:find(Token, Holders) of
        error -> State;
        {ok, host} ->
            State#state{
                host_in_flight = max(0, State#state.host_in_flight - 1),
                holders = maps:remove(Token, Holders)
            };
        {ok, Zone} ->
            Key = to_zone_key(Zone),
            ZF = State#state.zone_in_flight,
            NewCount = max(0, maps:get(Key, ZF, 0) - 1),
            ZF2 = case NewCount of
                0 -> maps:remove(Key, ZF);
                _ -> ZF#{Key => NewCount}
            end,
            State#state{
                host_in_flight = max(0, State#state.host_in_flight - 1),
                zone_in_flight = ZF2,
                holders = maps:remove(Token, Holders)
            }
    end.

%% After a release frees capacity, walk the waiter queue and admit
%% the first waiter whose scope allows it.
-spec drain_after_release(#state{}) -> #state{}.
drain_after_release(#state{waiters = []} = State) -> State;
drain_after_release(State) ->
    case find_admissible(State#state.waiters, State, []) of
        none -> State;
        {admitted, Waiter, Rest} ->
            _ = cancel_timer(Waiter#waiter.timer),
            gen_server:reply(Waiter#waiter.from, {ok, Waiter#waiter.token}),
            emit_event(accepted, Waiter#waiter.scope),
            State2 = record_admit(Waiter#waiter.scope,
                                  Waiter#waiter.token,
                                  State#state{waiters = Rest}),
            %% Multiple waiters may now fit — keep draining.
            drain_after_release(State2)
    end.

find_admissible([], _State, _Acc) -> none;
find_admissible([W | Rest], State, Acc) ->
    case can_admit(W#waiter.scope, State) of
        true  -> {admitted, W, lists:reverse(Acc) ++ Rest};
        false -> find_admissible(Rest, State, [W | Acc])
    end.

take_waiter(Token, Waiters) ->
    case lists:keytake(Token, #waiter.token, Waiters) of
        {value, W, Rest} -> {ok, W, Rest};
        false            -> not_found
    end.

cancel_timer(undefined) -> ok;
cancel_timer(Ref) -> _ = erlang:cancel_timer(Ref), ok.

to_zone_key(Zone) when is_binary(Zone) -> Zone;
to_zone_key(Zone) when is_atom(Zone)   -> atom_to_binary(Zone, utf8);
to_zone_key(Zone)                       -> iolist_to_binary(Zone).

emit_event(accepted, Scope) ->
    try erlkoenig_events:notify({admission_accepted, scope_label(Scope)})
    catch _:_ -> ok
    end;
emit_event(waiting, Scope) ->
    try erlkoenig_events:notify({admission_waiting, scope_label(Scope)})
    catch _:_ -> ok
    end;
emit_event(timeout, Scope) ->
    try erlkoenig_events:notify({admission_timeout, scope_label(Scope)})
    catch _:_ -> ok
    end.

scope_label(host) -> <<"host">>;
scope_label(Z) when is_binary(Z) -> Z;
scope_label(Z) when is_atom(Z) -> atom_to_binary(Z, utf8);
scope_label(Z) -> iolist_to_binary(io_lib:format("~p", [Z])).
