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

-module(erlkoenig_artifact_store).
-moduledoc """
DETS-backed artifact metadata registry.

Stores metadata about ingested artifacts (name, manifest hash,
binary hash, tags, etc.). The actual CAS blocks live in the
erlkoenig_fuse store -- this module only tracks metadata.

Follows the same DETS pattern as erlkoenig_node_state:
immediate write + fsync on every mutation.
""".

-behaviour(gen_server).

%% API
-export([start_link/0, start_link/1,
         register/2, lookup/1, lookup_by_tag/2,
         list/0, delete/1, tag/2, untag/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, terminate/2]).

-define(DEFAULT_PATH, "/var/lib/erlkoenig/artifacts.dets").
-define(TABLE_NAME, erlkoenig_artifacts).

%%====================================================================
%% API
%%====================================================================

-doc "Start with default path from app env.".
-spec start_link() -> gen_server:start_ret().
start_link() ->
    Path = application:get_env(erlkoenig, artifacts_dets_path, ?DEFAULT_PATH),
    start_link(Path).

-doc "Start with an explicit path. Useful for testing with tmp dirs.".
-spec start_link(string() | binary()) -> gen_server:start_ret().
start_link(Path) when is_binary(Path) ->
    start_link(binary_to_list(Path));
start_link(Path) when is_list(Path) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Path, []).

-doc "Register an artifact. Info should contain at minimum: manifest_hash, binary_hash, pushed_at. Optional: seccomp_profile, elf_info, tags.".
-spec register(Name :: binary(), Info :: map()) -> ok.
register(Name, Info) ->
    gen_server:call(?MODULE, {register, Name, Info}).

-doc "Lookup an artifact by exact name.".
-spec lookup(Name :: binary()) -> {ok, map()} | {error, not_found}.
lookup(Name) ->
    gen_server:call(?MODULE, {lookup, Name}).

-doc "Find an artifact where name starts with Prefix and tags contains Tag. Linear scan over DETS (table is small).".
-spec lookup_by_tag(Prefix :: binary(), Tag :: binary()) -> {ok, map()} | {error, not_found}.
lookup_by_tag(Prefix, Tag) ->
    gen_server:call(?MODULE, {lookup_by_tag, Prefix, Tag}).

-doc "List all artifacts.".
-spec list() -> [map()].
list() ->
    gen_server:call(?MODULE, list).

-doc "Delete artifact metadata. CAS blocks are not affected (GC later).".
-spec delete(Name :: binary()) -> ok.
delete(Name) ->
    gen_server:call(?MODULE, {delete, Name}).

-doc "Add a tag to an artifact's tags list.".
-spec tag(Name :: binary(), Tag :: binary()) -> ok.
tag(Name, Tag) ->
    gen_server:call(?MODULE, {tag, Name, Tag}).

-doc "Remove a tag from an artifact's tags list.".
-spec untag(Name :: binary(), Tag :: binary()) -> ok.
untag(Name, Tag) ->
    gen_server:call(?MODULE, {untag, Name, Tag}).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init(Path) ->
    process_flag(trap_exit, true),
    ok = filelib:ensure_dir(Path),
    case dets:open_file(?TABLE_NAME, [{file, Path}, {type, set}]) of
        {ok, Tab} ->
            logger:info("erlkoenig_artifact_store: opened DETS at ~s", [Path]),
            {ok, #{tab => Tab, path => Path}};
        {error, Reason} ->
            logger:error("erlkoenig_artifact_store: failed to open DETS ~s: ~p",
                         [Path, Reason]),
            {stop, {dets_open_failed, Reason}}
    end.

handle_call({register, Name, Info}, _From, #{tab := Tab} = State) ->
    InfoWithName = Info#{name => Name},
    ok = dets:insert(Tab, {Name, InfoWithName}),
    ok = dets:sync(Tab),
    {reply, ok, State};

handle_call({lookup, Name}, _From, #{tab := Tab} = State) ->
    Reply = case dets:lookup(Tab, Name) of
        [{Name, Info}] -> {ok, Info};
        []             -> {error, not_found}
    end,
    {reply, Reply, State};

handle_call({lookup_by_tag, Prefix, Tag}, _From, #{tab := Tab} = State) ->
    PrefixSize = byte_size(Prefix),
    Result = dets:foldl(fun
        ({Name, Info}, not_found) ->
            case Name of
                <<Prefix:PrefixSize/binary, _/binary>> ->
                    Tags = maps:get(tags, Info, []),
                    case lists:member(Tag, Tags) of
                        true  -> {ok, Info};
                        false -> not_found
                    end;
                _ ->
                    not_found
            end;
        (_Entry, Found) ->
            Found
    end, not_found, Tab),
    Reply = case Result of
        not_found -> {error, not_found};
        {ok, _} = Ok -> Ok
    end,
    {reply, Reply, State};

handle_call(list, _From, #{tab := Tab} = State) ->
    Result = dets:foldl(fun({_Name, Info}, Acc) -> [Info | Acc] end, [], Tab),
    {reply, Result, State};

handle_call({delete, Name}, _From, #{tab := Tab} = State) ->
    ok = dets:delete(Tab, Name),
    ok = dets:sync(Tab),
    {reply, ok, State};

handle_call({tag, Name, Tag}, _From, #{tab := Tab} = State) ->
    Reply = case dets:lookup(Tab, Name) of
        [{Name, Info}] ->
            Tags = maps:get(tags, Info, []),
            case lists:member(Tag, Tags) of
                true ->
                    ok;  %% Already tagged
                false ->
                    NewInfo = Info#{tags => [Tag | Tags]},
                    ok = dets:insert(Tab, {Name, NewInfo}),
                    ok = dets:sync(Tab),
                    ok
            end;
        [] ->
            ok  %% Silently ignore tagging non-existent artifacts
    end,
    {reply, Reply, State};

handle_call({untag, Name, Tag}, _From, #{tab := Tab} = State) ->
    Reply = case dets:lookup(Tab, Name) of
        [{Name, Info}] ->
            Tags = maps:get(tags, Info, []),
            NewTags = lists:delete(Tag, Tags),
            NewInfo = Info#{tags => NewTags},
            ok = dets:insert(Tab, {Name, NewInfo}),
            ok = dets:sync(Tab),
            ok;
        [] ->
            ok  %% Silently ignore untagging non-existent artifacts
    end,
    {reply, Reply, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

terminate(_Reason, #{tab := Tab}) ->
    _ = dets:close(Tab),
    ok;
terminate(_Reason, _State) ->
    ok.
