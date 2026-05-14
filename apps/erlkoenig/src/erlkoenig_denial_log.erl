%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%

-module(erlkoenig_denial_log).
-moduledoc """
Bounded in-memory ring of recent resource-admission denials.

Stores the last `denial_log_max_entries` (default 200) denial events
keyed by monotonic insertion sequence. Lookup by container id returns
the most recent matching denial; `list_for/1` returns all denials for
that id (newest first); `all/0` returns the whole ring.

Reads go directly against ETS (no gen_server roundtrip). Writes go
through the gen_server cast so the eviction policy is serialised.

Hot path for `ek admission denial <id>`. After process restart the
ring is empty — older denials must be recovered from the audit log
via `erlkoenig_audit:query/1` filtering on
`type =:= resource_admission_denied`.

Independent of the ct registry: a denied container may never have
existed as a gen_statem, so the lookup must not require a live ct
process.
""".

-behaviour(gen_server).

-export([start_link/0,
         record_denial/1,
         lookup/1,
         list_for/1,
         all/0,
         clear/0,
         size/0]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(TABLE, ?MODULE).
-define(DEFAULT_MAX_ENTRIES, 200).

-type denial() :: #{
    container_id := binary(),
    ts_ms := integer(),
    zone => term(),
    reason => map(),
    limits => map(),
    _ => _
}.

-export_type([denial/0]).

-record(state, {max :: pos_integer()}).

%% =================================================================
%% API
%% =================================================================

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-doc """
Record a denial. Async — never blocks the spawn path.

The denial map MUST contain `container_id` (binary). `ts_ms` is added
automatically if absent. All other fields are passed through verbatim.
""".
-spec record_denial(denial()) -> ok.
record_denial(#{container_id := Id} = Denial) when is_binary(Id) ->
    gen_server:cast(?SERVER, {record, Denial}).

-doc """
Most recent denial for the given container id.

Returns `{error, not_found}` if no denial has been recorded for that
id (or after restart wiped the ring — try `erlkoenig_audit:query/1`
as the cold fallback).
""".
-spec lookup(binary()) -> {ok, denial()} | {error, not_found}.
lookup(ContainerId) when is_binary(ContainerId) ->
    case select_for(ContainerId, 1) of
        []        -> {error, not_found};
        [Denial | _] -> {ok, Denial}
    end.

-doc "All denials recorded for the given container id, newest first.".
-spec list_for(binary()) -> [denial()].
list_for(ContainerId) when is_binary(ContainerId) ->
    select_for(ContainerId, all).

-doc "All recorded denials, newest first.".
-spec all() -> [denial()].
all() ->
    case ets:info(?TABLE, name) of
        undefined -> [];
        _ ->
            [Denial || {_Seq, Denial}
                       <- ets:select_reverse(?TABLE,
                                             [{{'$1', '$2'}, [], [{{'$1', '$2'}}]}])]
    end.

-doc "Test helper: empty the ring.".
-spec clear() -> ok.
clear() ->
    gen_server:call(?SERVER, clear).

-doc "Number of denials currently in the ring.".
-spec size() -> non_neg_integer().
size() ->
    case ets:info(?TABLE, size) of
        undefined -> 0;
        N -> N
    end.

%% =================================================================
%% gen_server
%% =================================================================

init([]) ->
    process_flag(trap_exit, true),
    proc_lib:set_label(?MODULE),
    Max = application:get_env(erlkoenig, denial_log_max_entries,
                              ?DEFAULT_MAX_ENTRIES),
    true = is_integer(Max) andalso Max > 0
        orelse error({invalid_config, denial_log_max_entries, Max}),
    ?TABLE = ets:new(?TABLE,
                     [named_table, ordered_set, public,
                      {read_concurrency, true}]),
    {ok, #state{max = Max}}.

handle_call(clear, _From, State) ->
    true = ets:delete_all_objects(?TABLE),
    {reply, ok, State};
handle_call(_Req, _From, State) ->
    {reply, {error, unknown}, State}.

handle_cast({record, Denial}, #state{max = Max} = State) ->
    Seq = erlang:unique_integer([monotonic, positive]),
    Denial2 = ensure_ts(Denial),
    true = ets:insert(?TABLE, {Seq, Denial2}),
    evict_overflow(Max),
    {noreply, State};
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% =================================================================
%% Internal
%% =================================================================

-spec ensure_ts(denial()) -> denial().
ensure_ts(#{ts_ms := _} = Denial) -> Denial;
ensure_ts(Denial) -> Denial#{ts_ms => erlang:system_time(millisecond)}.

-spec select_for(binary(), pos_integer() | all) -> [denial()].
select_for(ContainerId, Limit) ->
    case ets:info(?TABLE, name) of
        undefined ->
            [];
        _ ->
            %% Match all rows, filter by container_id in the guard.
            %% Map-key-presence guards keep the spec tolerant of older
            %% rows that may lack newer fields.
            MatchSpec =
                [{{'$1', '$2'},
                  [{'andalso',
                    {'==', {'map_get', container_id, '$2'}, ContainerId},
                    {is_map, '$2'}}],
                  ['$2']}],
            case Limit of
                all ->
                    ets:select_reverse(?TABLE, MatchSpec);
                N when is_integer(N), N > 0 ->
                    case ets:select_reverse(?TABLE, MatchSpec, N) of
                        '$end_of_table' -> [];
                        {Items, _Cont}  -> Items
                    end
            end
    end.

-spec evict_overflow(pos_integer()) -> ok.
evict_overflow(Max) ->
    case ets:info(?TABLE, size) of
        Size when Size =< Max -> ok;
        _Size ->
            evict_one(),
            evict_overflow(Max)
    end.

-spec evict_one() -> ok.
evict_one() ->
    case ets:first(?TABLE) of
        '$end_of_table' -> ok;
        Key ->
            true = ets:delete(?TABLE, Key),
            ok
    end.
