%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%

-module(erlkoenig_nft_audit).
-moduledoc """
Audit log for firewall operations.

Records ban, unban, add_element, del_element, reload, and apply
operations with timestamps. Maintains a ring buffer in memory
(last 1000 entries).

## Dual-Path Ingestion

Audit receives events through two paths:

1. **Event-based (automatic):** Subscribes to `control_events` pg group.
   Facade operations are captured automatically with `op_id` for correlation.
   Delivery is best-effort (see erlkoenig_nft_events).

2. **Direct API (explicit):** `log/2` for guard-internal actions, manual
   entries, or cases where best-effort is not sufficient.

Both paths use the same ring buffer and `entries/0,1` API.

    erlkoenig_nft_audit:log(manual_action, #{note => <<"explicit">>}).
    erlkoenig_nft_audit:entries().
    erlkoenig_nft_audit:entries(50).
""".

-behaviour(gen_server).

-export([
    start_link/0,
    log/2,
    entries/0,
    entries/1
]).

-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2
]).

-define(MAX_ENTRIES, 1000).

-type entry() :: #{
    time := binary(),
    action := atom(),
    details := map()
}.

-type state() :: #{
    entries := [entry()],
    count := non_neg_integer()
}.

%% --- Public API ---

-doc "Start the audit log server.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-doc "Record an audit event.".
-spec log(atom(), map()) -> ok.
log(Action, Details) ->
    gen_server:cast(?MODULE, {log, Action, Details}).

-doc "Get all audit entries (most recent first).".
-spec entries() -> [entry()].
entries() ->
    entries(?MAX_ENTRIES).

-doc "Get the last N audit entries (most recent first).".
-spec entries(pos_integer()) -> [entry()].
entries(N) ->
    gen_server:call(?MODULE, {entries, N}).

%% --- gen_server callbacks ---

-spec init([]) -> {ok, #{count := 0, entries := []}}.
init([]) ->
    proc_lib:set_label(erlkoenig_nft_audit),
    ok = pg:join(erlkoenig_nft, control_events, self()),
    {ok, #{entries => [], count => 0}}.

-spec handle_call(term(), {pid(), term()}, state()) ->
    {reply, term(), state()}.
handle_call({entries, N}, _From, #{entries := Entries} = State) ->
    {reply, lists:sublist(Entries, N), State};
handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast({log, Action, Details}, State) ->
    %% Path 2: Direct API — for guard-internal actions, manual entries,
    %% or cases where best-effort event delivery is not sufficient.
    do_log(Action, Details, State);
handle_cast(_Msg, State) ->
    {noreply, State}.

-spec handle_info(term(), state()) -> {noreply, state()}.
%% Path 1: Event-based — automatic capture of facade operations.
%% Matches kind := op_complete to ignore future event types (e.g. op_start).
handle_info(
    {control_event, #{kind := op_complete, action := Action, details := Details, op_id := OpId}},
    State
) ->
    do_log(Action, Details#{op_id => OpId}, State);
handle_info(_Info, State) ->
    {noreply, State}.

-spec terminate(term(), state()) -> ok.
terminate(_Reason, _State) ->
    ok.

%% --- Internal ---

-spec do_log(atom(), map(), state()) -> {noreply, state()}.
do_log(Action, Details, #{entries := Entries, count := Count} = State) ->
    Entry = #{
        time => format_time(erlang:localtime()),
        action => Action,
        details => Details
    },
    logger:info("[erlkoenig_nft_audit] ~p ~p", [Action, Details]),
    NewEntries = lists:sublist([Entry | Entries], ?MAX_ENTRIES),
    {noreply, State#{entries => NewEntries, count => Count + 1}}.

-spec format_time(calendar:datetime()) -> binary().
format_time({{Y, M, D}, {H, Mi, S}}) ->
    iolist_to_binary(
        io_lib:format(
            "~4..0B-~2..0B-~2..0B ~2..0B:~2..0B:~2..0B",
            [Y, M, D, H, Mi, S]
        )
    ).
