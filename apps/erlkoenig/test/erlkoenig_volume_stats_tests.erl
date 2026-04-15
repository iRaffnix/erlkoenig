%%%-------------------------------------------------------------------
%%% @doc Unit tests for erlkoenig_volume_stats.
%%%
%%% Covers `usage/1` pure logic (directory walk, empty/missing dirs,
%%% byte/inode accounting) plus the `poll_now/0` round-trip through
%%% the store + event bus.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_volume_stats_tests).

-behaviour(gen_event).

-include_lib("eunit/include/eunit.hrl").

%% gen_event callbacks — used by poll_test_ to drain events into the
%% test process's mailbox. Declared up top so the compiler sees them
%% as behaviour exports, not stray unused functions.
-export([init/1, handle_event/2, handle_call/2, handle_info/2,
         terminate/2, code_change/3]).

%%====================================================================
%% usage/1 — pure directory walk
%%====================================================================

usage_test_() ->
    {setup, fun usage_setup/0, fun usage_cleanup/1,
     fun(Root) ->
        [{"empty dir: 0 bytes, 1 inode (the dir itself)",
          ?_test(t_usage_empty(Root))},
         {"single file contributes size + inode",
          ?_test(t_usage_single_file(Root))},
         {"nested subdir is walked recursively",
          ?_test(t_usage_nested(Root))},
         {"missing path returns {error, enoent}",
          ?_test(t_usage_missing())},
         {"non-directory input rejected",
          ?_test(t_usage_not_a_dir(Root))}]
     end}.

usage_setup() ->
    Root = iolist_to_binary(
        ["/tmp/eunit_ek_vs_usage_",
         integer_to_list(erlang:system_time(nanosecond))]),
    ok = file:make_dir(binary_to_list(Root)),
    Root.

usage_cleanup(Root) ->
    _ = file:del_dir_r(binary_to_list(Root)),
    ok.

t_usage_empty(Root) ->
    Dir = filename:join(binary_to_list(Root), "empty"),
    ok = file:make_dir(Dir),
    {ok, #{bytes := 0, inodes := 1}} = erlkoenig_volume_stats:usage(Dir).

t_usage_single_file(Root) ->
    Dir = filename:join(binary_to_list(Root), "single"),
    ok = file:make_dir(Dir),
    File = filename:join(Dir, "data.bin"),
    Payload = binary:copy(<<"x">>, 1024),
    ok = file:write_file(File, Payload),
    {ok, #{bytes := 1024, inodes := 2}} =
        erlkoenig_volume_stats:usage(Dir).

t_usage_nested(Root) ->
    Dir = filename:join(binary_to_list(Root), "nested"),
    ok = file:make_dir(Dir),
    Inner = filename:join(Dir, "a"),
    ok = file:make_dir(Inner),
    ok = file:write_file(filename:join(Dir, "top.bin"),
                          binary:copy(<<"x">>, 100)),
    ok = file:write_file(filename:join(Inner, "nested.bin"),
                          binary:copy(<<"y">>, 200)),
    {ok, #{bytes := 300, inodes := 4}} =
        erlkoenig_volume_stats:usage(Dir).

t_usage_missing() ->
    ?assertMatch({error, enoent},
                 erlkoenig_volume_stats:usage("/tmp/ek_vs_nope_42")).

t_usage_not_a_dir(Root) ->
    File = filename:join(binary_to_list(Root), "iam_a_file"),
    ok = file:write_file(File, <<"hi">>),
    ?assertMatch({error, not_a_directory},
                 erlkoenig_volume_stats:usage(File)).

%%====================================================================
%% poll_now/0 — round-trip with store + event bus
%%====================================================================

poll_test_() ->
    %% `foreach` runs setup/cleanup in each test's own process so
    %% `self()` inside the handler state is the process that will
    %% call `drain_events/2`. Using `{setup, ...}` breaks this
    %% because the instantiator runs in a different process than
    %% the generated tests.
    {foreach, fun poll_setup/0, fun poll_cleanup/1,
     [fun t_poll_empty/1,
      fun t_poll_emits/1,
      fun t_poll_payload/1]}.

poll_setup() ->
    Root = iolist_to_binary(
        ["/tmp/eunit_ek_vs_poll_",
         integer_to_list(erlang:system_time(nanosecond))]),
    ok = application:set_env(erlkoenig, volumes_root, Root),
    %% Long interval so the auto-timer never fires during the test.
    ok = application:set_env(erlkoenig, volume_stats_interval_ms, 3_600_000),
    %% Start a bare gen_event manager under the `erlkoenig_events`
    %% name. We deliberately skip `erlkoenig_events:start_link/0`
    %% because that auto-subscribes policy + metrics handlers which
    %% later try to reach `erlkoenig_pg` and `erlkoenig_nft_srv` on
    %% shutdown — processes that aren't running in a bare eunit VM,
    %% causing cascading cancellations in unrelated test modules.
    _ = case gen_event:start_link({local, erlkoenig_events}) of
            {ok, _} -> ok;
            {error, {already_started, _}} -> ok
        end,
    _ = case erlkoenig_volume_store:start_link() of
            {ok, _} -> ok;
            {error, {already_started, _}} -> ok
        end,
    _ = case erlkoenig_volume_stats:start_link() of
            {ok, _} -> ok;
            {error, {already_started, _}} -> ok
        end,
    #{root => Root}.

poll_cleanup(#{root := Root}) ->
    %% Stop all processes we started. The bare `gen_event` manager
    %% under `erlkoenig_events` has no auto-subscribed handlers
    %% (we deliberately don't call `erlkoenig_events:start_link/0`
    %% — see setup) so termination is clean: no pg:leave cascade,
    %% no nft_srv callbacks. Leaving the registered name occupied
    %% would break `erlkoenig_events_tests:setup/0` which asserts
    %% `{ok, Pid} = erlkoenig_events:start_link()`.
    lists:foreach(
        fun(Name) ->
            case whereis(Name) of
                undefined -> ok;
                Pid ->
                    %% gen_event:stop/1 for gen_event managers;
                    %% gen_server:stop/3 for our gen_servers.
                    try gen_server:stop(Pid, normal, 5_000)
                    catch _:_ ->
                        try gen_event:stop(Pid) catch _:_ -> ok end
                    end
            end
        end,
        [erlkoenig_volume_stats, erlkoenig_volume_store, erlkoenig_events]),
    _ = application:unset_env(erlkoenig, volumes_root),
    _ = application:unset_env(erlkoenig, volume_stats_interval_ms),
    _ = file:del_dir_r(binary_to_list(Root)),
    ok.

%% Subscribe from within the test process — eunit runs setup/cleanup
%% in the runner process, so self() there isn't the test process.
with_subscriber(Fn) ->
    Self = self(),
    Handler = {?MODULE, Self},
    ok = gen_event:add_handler(erlkoenig_events, Handler, [Self]),
    try
        Fn()
    after
        _ = gen_event:delete_handler(erlkoenig_events, Handler, [])
    end.

t_poll_empty(_Ctx) ->
    ?_test(with_subscriber(fun() ->
        flush_events(),
        ?assertEqual({ok, 0}, erlkoenig_volume_stats:poll_now())
    end)).

t_poll_emits(_Ctx) ->
    ?_test(with_subscriber(fun() ->
        {ok, _} = erlkoenig_volume_store:ensure(
            #{container => <<"ct-one">>, persist => <<"v">>,
              uid => 0, gid => 0}),
        {ok, _} = erlkoenig_volume_store:ensure(
            #{container => <<"ct-two">>, persist => <<"v">>,
              uid => 0, gid => 0}),
        flush_events(),
        {ok, 2} = erlkoenig_volume_stats:poll_now(),
        Events = drain_events(2, 1_000),
        ?assertEqual(2, length(Events))
    end)).

t_poll_payload(_Ctx) ->
    ?_test(with_subscriber(fun() ->
        {ok, V} = erlkoenig_volume_store:ensure(
            #{container => <<"ct-pay">>, persist => <<"payload">>,
              uid => 0, gid => 0}),
        HostPath = maps:get(host_path, V),
        File = filename:join(binary_to_list(HostPath), "marker.txt"),
        ok = file:write_file(File, <<"ABCDEFGH">>),
        flush_events(),
        {ok, _} = erlkoenig_volume_stats:poll_now(),
        Events = drain_events(5, 1_000),
        [Ev | _] =
            [E || E = {volume_stats, #{container := <<"ct-pay">>}} <- Events],
        {volume_stats, Payload} = Ev,
        ?assertEqual(<<"payload">>, maps:get(persist, Payload)),
        ?assertEqual(<<"ct-pay">>, maps:get(container, Payload)),
        ?assertEqual(persistent, maps:get(lifecycle, Payload)),
        ?assert(maps:get(bytes, Payload) >= 8),
        ?assert(maps:get(inodes, Payload) >= 2),
        ?assert(is_integer(maps:get(ts_ms, Payload)))
    end)).

%%====================================================================
%% gen_event handler — forwards events into the test's mailbox
%%====================================================================

init([Pid]) -> {ok, Pid}.
handle_event(Event, Pid) -> Pid ! Event, {ok, Pid}.
handle_call(_, S) -> {ok, ok, S}.
handle_info(_, S) -> {ok, S}.
terminate(_, _) -> ok.
code_change(_, S, _) -> {ok, S}.

flush_events() ->
    receive _ -> flush_events()
    after 0 -> ok
    end.

drain_events(N, Timeout) -> drain_events(N, Timeout, []).
drain_events(0, _, Acc) -> lists:reverse(Acc);
drain_events(N, Timeout, Acc) ->
    receive
        Ev = {volume_stats, _} ->
            drain_events(N - 1, Timeout, [Ev | Acc]);
        _Other ->
            drain_events(N, Timeout, Acc)
    after Timeout ->
        lists:reverse(Acc)
    end.
