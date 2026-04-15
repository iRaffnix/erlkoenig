%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_volume_stats).
-moduledoc """
Periodic disk-usage emitter for persistent volumes.

Walks every volume registered with `erlkoenig_volume_store`, computes
byte and inode counts, and emits one `{volume_stats, ...}` event per
volume to `erlkoenig_events`, which gets AMQP-routed to
`stats.volume.<container>.<persist>`.

## Tuning

`application:get_env(erlkoenig, volume_stats_interval_ms, 60000)` —
polling interval in milliseconds. First poll fires after `Interval`,
not at startup, so an overloaded boot doesn't race with container
spawns.

`application:get_env(erlkoenig, volume_stats_enabled, true)` —
master switch. When `false`, the gen_server starts but never emits
(useful for minimal deployments that don't run AMQP).

## Cost

Pure Erlang directory walk via `filelib:fold_files/5`. For each
volume that's ~1 GB with ~10k files the walk takes low-tens of
milliseconds; a cluster of 50 volumes polled every 60 s is well under
1 % of one core. No subprocess fork per poll — deliberately avoided
`du` so the emitter has no runtime dependency.

If that ever becomes load-bearing, the quota-aware fast path via
`xfs_quota report -bpN` is a direct substitution: O(1) per volume
instead of O(files). See SPEC-EK-024 §Offene Punkte.
""".

-behaviour(gen_server).

-include_lib("kernel/include/file.hrl").

-export([start_link/0,
         poll_now/0,
         usage/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(DEFAULT_INTERVAL_MS, 60_000).
-define(MIN_INTERVAL_MS, 1_000).

%%====================================================================
%% Public API
%%====================================================================

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-doc """
Force an immediate poll + emit cycle. Mostly for tests and operator
introspection via `erlkoenig eval`. Blocks until the poll completes.
""".
-spec poll_now() -> {ok, non_neg_integer()}.
poll_now() ->
    gen_server:call(?SERVER, poll_now, 30_000).

-doc """
One-shot usage computation for a host-side directory. Exported so
`erlkoenig_volume_store` can reuse it for ad-hoc introspection. Not
on the hot path.
""".
-spec usage(binary() | string()) ->
    {ok, #{bytes := non_neg_integer(), inodes := non_neg_integer()}}
    | {error, term()}.
usage(HostPath) ->
    compute_usage(HostPath).

%%====================================================================
%% gen_server
%%====================================================================

init([]) ->
    Interval = read_interval(),
    Enabled = application:get_env(erlkoenig, volume_stats_enabled, true),
    State = #{interval => Interval, enabled => Enabled},
    schedule_next(Interval),
    {ok, State}.

handle_call(poll_now, _From, State) ->
    Count = do_poll(),
    {reply, {ok, Count}, State}.

handle_cast(_, State) -> {noreply, State}.

handle_info(poll, #{interval := Interval, enabled := true} = State) ->
    _ = do_poll(),
    schedule_next(Interval),
    {noreply, State};
handle_info(poll, #{interval := Interval} = State) ->
    %% Disabled — still reschedule so an at-runtime flip to `true`
    %% picks up on the next tick without a restart.
    schedule_next(Interval),
    {noreply, State};
handle_info(_, State) -> {noreply, State}.

terminate(_Reason, _State) -> ok.
code_change(_OldVsn, State, _Extra) -> {ok, State}.

%%====================================================================
%% Internal
%%====================================================================

-spec read_interval() -> pos_integer().
read_interval() ->
    Requested = application:get_env(erlkoenig, volume_stats_interval_ms,
                                    ?DEFAULT_INTERVAL_MS),
    %% Floor the interval. A runaway config that asks for 10 ms would
    %% thrash the scheduler and block poll_now calls indefinitely.
    max(?MIN_INTERVAL_MS, Requested).

-spec schedule_next(pos_integer()) -> reference().
schedule_next(Interval) ->
    erlang:send_after(Interval, self(), poll).

-spec do_poll() -> non_neg_integer().
do_poll() ->
    case catch erlkoenig_volume_store:list() of
        Records when is_list(Records) ->
            TsMs = erlang:system_time(millisecond),
            lists:foldl(
                fun(V, Acc) ->
                    case emit_one(V, TsMs) of
                        ok -> Acc + 1;
                        skip -> Acc
                    end
                end, 0, Records);
        _Error ->
            %% Store not up (boot race, restart). Silent — the timer
            %% will try again next tick.
            0
    end.

-spec emit_one(map(), non_neg_integer()) -> ok | skip.
emit_one(#{host_path := HostPath} = V, TsMs) ->
    case compute_usage(HostPath) of
        {ok, #{bytes := Bytes, inodes := Inodes}} ->
            Event = #{uuid      => maps:get(uuid, V),
                      container => maps:get(container, V),
                      persist   => maps:get(persist, V),
                      lifecycle => maps:get(lifecycle, V),
                      bytes     => Bytes,
                      inodes    => Inodes,
                      ts_ms     => TsMs},
            erlkoenig_events:notify({volume_stats, Event}),
            ok;
        {error, Reason} ->
            %% A volume can disappear between list/0 and the walk if
            %% cleanup_ephemeral fires concurrently. Not an error,
            %% just skip.
            logger:debug("volume_stats: usage failed for ~s: ~p",
                         [HostPath, Reason]),
            skip
    end.

-spec compute_usage(binary() | string()) ->
    {ok, #{bytes := non_neg_integer(), inodes := non_neg_integer()}}
    | {error, term()}.
compute_usage(HostPath) when is_binary(HostPath) ->
    compute_usage(binary_to_list(HostPath));
compute_usage(HostPath) when is_list(HostPath) ->
    case file:read_file_info(HostPath, [raw]) of
        {ok, #file_info{type = directory}} ->
            %% fold_files traverses regular files; we add directories
            %% separately so inode counts include them (matches du -i).
            Acc0 = #{bytes => 0, inodes => 0},
            Acc1 = fold_tree(HostPath, Acc0),
            {ok, Acc1};
        {ok, #file_info{}} ->
            {error, not_a_directory};
        {error, _} = Err ->
            Err
    end.

-spec fold_tree(string(), map()) -> map().
fold_tree(Dir, Acc) ->
    case file:list_dir_all(Dir) of
        {ok, Entries} ->
            %% The dir itself is one inode, count it once.
            Acc1 = bump_inodes(Acc),
            lists:foldl(
                fun(Entry, InnerAcc) ->
                    Path = filename:join(Dir, Entry),
                    case file:read_link_info(Path, [raw]) of
                        {ok, #file_info{type = directory}} ->
                            fold_tree(Path, InnerAcc);
                        {ok, #file_info{type = regular, size = Size}} ->
                            bump(InnerAcc, Size, 1);
                        {ok, #file_info{size = Size}} ->
                            %% symlink, fifo, dev, etc. — count inode,
                            %% size is 0 or symlink length (tiny).
                            bump(InnerAcc, Size, 1);
                        {error, _} ->
                            %% Racing with cleanup — skip this entry.
                            InnerAcc
                    end
                end, Acc1, Entries);
        {error, _} ->
            %% Dir disappeared mid-walk — return what we have.
            Acc
    end.

-spec bump(map(), non_neg_integer(), non_neg_integer()) -> map().
bump(#{bytes := B, inodes := I} = M, AddBytes, AddInodes) ->
    M#{bytes := B + AddBytes, inodes := I + AddInodes}.

-spec bump_inodes(map()) -> map().
bump_inodes(#{inodes := I} = M) ->
    M#{inodes := I + 1}.
