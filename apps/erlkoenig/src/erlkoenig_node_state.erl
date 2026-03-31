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

-module(erlkoenig_node_state).
-moduledoc """
DETS-backed container state persistence.

Manages a DETS table that persists container state across BEAM
crashes. Each container record is written and fsync'd immediately
so the on-disk state is always current.

Used by erlkoenig_recovery at boot to find and reconnect to
still-running containers after a BEAM restart.
""".

-behaviour(gen_server).

%% API
-export([start_link/0, start_link/1,
         register_container/2,
         unregister_container/1,
         update_container/2,
         get_container/1,
         all_containers/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, terminate/2]).

-define(DEFAULT_PATH, "/var/lib/erlkoenig/node.dets").
-define(TABLE_NAME, erlkoenig_node_state).

%%====================================================================
%% API
%%====================================================================

-doc "Start the DETS state server with default path from app env.".
-spec start_link() -> gen_server:start_ret().
start_link() ->
    Path = application:get_env(erlkoenig, dets_path, ?DEFAULT_PATH),
    start_link(Path).

-doc "Start the DETS state server with an explicit path. Useful for testing with temporary directories.".
-spec start_link(string() | binary()) -> gen_server:start_ret().
start_link(Path) when is_binary(Path) ->
    start_link(binary_to_list(Path));
start_link(Path) when is_list(Path) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Path, []).

-doc "Register a container in DETS. Writes and fsyncs immediately.".
-spec register_container(binary(), map()) -> ok.
register_container(ContainerId, Info) ->
    gen_server:call(?MODULE, {register, ContainerId, Info}).

-doc "Remove a container from DETS. Writes and fsyncs immediately.".
-spec unregister_container(binary()) -> ok.
unregister_container(ContainerId) ->
    gen_server:call(?MODULE, {unregister, ContainerId}).

-doc "Merge updates into an existing container record.".
-spec update_container(binary(), map()) -> ok.
update_container(ContainerId, Updates) ->
    gen_server:call(?MODULE, {update, ContainerId, Updates}).

-doc "Lookup a single container.".
-spec get_container(binary()) -> {ok, map()} | {error, not_found}.
get_container(ContainerId) ->
    gen_server:call(?MODULE, {get, ContainerId}).

-doc "List all containers (for recovery).".
-spec all_containers() -> [{binary(), map()}].
all_containers() ->
    gen_server:call(?MODULE, all).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init(Path) ->
    process_flag(trap_exit, true),
    ok = filelib:ensure_dir(Path),
    case dets:open_file(?TABLE_NAME, [{file, Path}, {type, set}]) of
        {ok, Tab} ->
            logger:info("erlkoenig_node_state: opened DETS at ~s", [Path]),
            {ok, #{tab => Tab, path => Path}};
        {error, Reason} ->
            logger:error("erlkoenig_node_state: failed to open DETS ~s: ~p",
                         [Path, Reason]),
            {stop, {dets_open_failed, Reason}}
    end.

handle_call({register, Id, Info}, _From, #{tab := Tab} = State) ->
    ok = dets:insert(Tab, {Id, Info}),
    ok = dets:sync(Tab),
    {reply, ok, State};

handle_call({unregister, Id}, _From, #{tab := Tab} = State) ->
    ok = dets:delete(Tab, Id),
    ok = dets:sync(Tab),
    {reply, ok, State};

handle_call({update, Id, Updates}, _From, #{tab := Tab} = State) ->
    Reply = case dets:lookup(Tab, Id) of
        [{Id, Existing}] ->
            Merged = maps:merge(Existing, Updates),
            ok = dets:insert(Tab, {Id, Merged}),
            ok = dets:sync(Tab),
            ok;
        [] ->
            ok  %% Silently ignore updates to non-existent containers
    end,
    {reply, Reply, State};

handle_call({get, Id}, _From, #{tab := Tab} = State) ->
    Reply = case dets:lookup(Tab, Id) of
        [{Id, Info}] -> {ok, Info};
        []           -> {error, not_found}
    end,
    {reply, Reply, State};

handle_call(all, _From, #{tab := Tab} = State) ->
    Result = dets:foldl(fun({Id, Info}, Acc) -> [{Id, Info} | Acc] end, [], Tab),
    {reply, Result, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

terminate(_Reason, #{tab := Tab}) ->
    _ = dets:close(Tab),
    ok;
terminate(_Reason, _State) ->
    ok.
