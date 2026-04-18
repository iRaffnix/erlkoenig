%%%-------------------------------------------------------------------
%%% @doc Unit tests for erlkoenig_volume.
%%%
%%% Tests that touch `erlkoenig_volume:resolve/4` need the store
%%% gen_server running, so we set up a per-test-module tmpdir, point
%%% the store at it via app env, and shut down cleanly at the end.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_volume_tests).

-include_lib("eunit/include/eunit.hrl").

%% =================================================================
%% validate_persist_name — pure, no fixtures
%% =================================================================

validate_persist_name_valid_test_() ->
    [?_assertEqual(ok, erlkoenig_volume:validate_persist_name(<<"db">>)),
     ?_assertEqual(ok, erlkoenig_volume:validate_persist_name(<<"archive-logs">>)),
     ?_assertEqual(ok, erlkoenig_volume:validate_persist_name(<<"data_1">>)),
     ?_assertEqual(ok, erlkoenig_volume:validate_persist_name(<<"a">>)),
     ?_assertEqual(ok, erlkoenig_volume:validate_persist_name(<<"0config">>))].

validate_persist_name_invalid_test_() ->
    [?_assertEqual({error, invalid_persist_name},
                   erlkoenig_volume:validate_persist_name(<<>>)),
     ?_assertEqual({error, invalid_persist_name},
                   erlkoenig_volume:validate_persist_name(<<"-leading">>)),
     ?_assertEqual({error, invalid_persist_name},
                   erlkoenig_volume:validate_persist_name(<<"_leading">>)),
     ?_assertEqual({error, invalid_persist_name},
                   erlkoenig_volume:validate_persist_name(<<"has/slash">>)),
     ?_assertEqual({error, invalid_persist_name},
                   erlkoenig_volume:validate_persist_name(<<"has.dot">>)),
     ?_assertEqual({error, invalid_persist_name},
                   erlkoenig_volume:validate_persist_name(<<"..">>)),
     ?_assertEqual({error, invalid_persist_name},
                   erlkoenig_volume:validate_persist_name(<<".">>)),
     ?_assertEqual({error, invalid_persist_name},
                   erlkoenig_volume:validate_persist_name(<<"UpperCase">>)),
     ?_assertEqual({error, invalid_persist_name},
                   erlkoenig_volume:validate_persist_name(<<"has space">>))].

%% =================================================================
%% resolve/4 — needs the store running with a tmpdir root
%% =================================================================

resolve_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(Root) ->
         [{"empty list returns {ok, []}", ?_test(t_empty())},
          {"single volume → UUID path, correct fields",
           ?_test(t_single(Root))},
          {"read_only flows through", ?_test(t_read_only())},
          {"read_only defaults to false", ?_test(t_default_read_only())},
          {"opts string flows through", ?_test(t_opts_string())},
          {"ephemeral defaults to persistent, overridable",
           ?_test(t_ephemeral(Root))},
          {"invalid persist name rejected", ?_test(t_invalid_name())},
          {"same (container,persist) resolves to same uuid (idempotent)",
           ?_test(t_idempotent())},
          {"multiple volumes resolve in order", ?_test(t_multiple())}]
     end}.

setup() ->
    Root = iolist_to_binary(["/tmp/eunit_ek_vol_",
                             integer_to_list(erlang:system_time(nanosecond))]),
    %% The DETS index file lives inside Root; its dir is created for us
    %% by erlkoenig_volume_store:init/1 via filelib:ensure_dir/1.
    ok = application:set_env(erlkoenig, volumes_root, Root),
    case erlkoenig_volume_store:start_link() of
        {ok, _Pid} -> ok;
        {error, {already_started, _}} -> ok
    end,
    Root.

cleanup(Root) ->
    case whereis(erlkoenig_volume_store) of
        undefined -> ok;
        Pid ->
            gen_server:stop(Pid, normal, 5000)
    end,
    _ = application:unset_env(erlkoenig, volumes_root),
    _ = file:del_dir_r(binary_to_list(Root)),
    ok.

t_empty() ->
    ?assertEqual({ok, []},
                 erlkoenig_volume:resolve(<<"app">>, [], 1000, 1000)).

t_single(Root) ->
    DslVols = [#{container => <<"/data/db">>,
                 persist   => <<"db">>,
                 read_only => false}],
    {ok, [R]} = erlkoenig_volume:resolve(<<"app-single">>, DslVols, 1000, 1000),
    ?assertMatch(<<"ek_vol_", _/binary>>, maps:get(uuid, R)),
    Host = maps:get(host, R),
    ?assert(binary:match(Host, Root) =/= nomatch),
    ?assertEqual(<<"/data/db">>, maps:get(container, R)),
    ?assertEqual(<<"db">>, maps:get(persist, R)),
    ?assertEqual(false, maps:get(read_only, R)),
    ?assertEqual(persistent, maps:get(lifecycle, R)),
    %% On-disk dir exists
    ?assert(filelib:is_dir(binary_to_list(Host))).

t_read_only() ->
    DslVols = [#{container => <<"/etc/config">>,
                 persist   => <<"cfg">>,
                 read_only => true}],
    {ok, [R]} = erlkoenig_volume:resolve(<<"app-ro">>, DslVols, 1000, 1000),
    ?assertEqual(true, maps:get(read_only, R)).

t_default_read_only() ->
    DslVols = [#{container => <<"/data">>, persist => <<"ddefault">>}],
    {ok, [R]} = erlkoenig_volume:resolve(<<"app-def">>, DslVols, 1000, 1000),
    ?assertEqual(false, maps:get(read_only, R)).

t_opts_string() ->
    DslVols = [#{container => <<"/u">>, persist => <<"uploads">>,
                 opts => <<"rw,nosuid,nodev,noexec">>}],
    {ok, [R]} = erlkoenig_volume:resolve(<<"app-opts">>, DslVols, 1000, 1000),
    ?assertEqual(<<"rw,nosuid,nodev,noexec">>, maps:get(opts, R)).

t_ephemeral(_Root) ->
    Persistent = [#{container => <<"/p">>, persist => <<"persistvol">>}],
    Ephemeral  = [#{container => <<"/e">>, persist => <<"ephvol">>,
                    ephemeral => true}],
    {ok, [P]} = erlkoenig_volume:resolve(<<"app-lc">>, Persistent, 1000, 1000),
    {ok, [E]} = erlkoenig_volume:resolve(<<"app-lc">>, Ephemeral, 1000, 1000),
    ?assertEqual(persistent, maps:get(lifecycle, P)),
    ?assertEqual(ephemeral,  maps:get(lifecycle, E)).

t_invalid_name() ->
    DslVols = [#{container => <<"/data">>, persist => <<"../bad">>}],
    ?assertEqual({error, invalid_persist_name},
                 erlkoenig_volume:resolve(<<"app-bad">>, DslVols, 1000, 1000)).

t_idempotent() ->
    DslVols = [#{container => <<"/x">>, persist => <<"idem">>}],
    {ok, [R1]} = erlkoenig_volume:resolve(<<"app-idem">>, DslVols, 1000, 1000),
    {ok, [R2]} = erlkoenig_volume:resolve(<<"app-idem">>, DslVols, 1000, 1000),
    ?assertEqual(maps:get(uuid, R1), maps:get(uuid, R2)),
    ?assertEqual(maps:get(host, R1), maps:get(host, R2)).

t_multiple() ->
    DslVols = [#{container => <<"/data/db">>, persist => <<"mdb">>},
               #{container => <<"/var/log">>, persist => <<"mlogs">>}],
    {ok, Resolved} = erlkoenig_volume:resolve(<<"app-multi">>, DslVols,
                                               1000, 1000),
    ?assertEqual(2, length(Resolved)),
    [First, Second | _] = Resolved,
    ?assertEqual(<<"/data/db">>, maps:get(container, First)),
    ?assertEqual(<<"/var/log">>, maps:get(container, Second)).

resolve_quota_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_Root) ->
        [{"quota flows from DSL map through resolve into store metadata",
          ?_test(t_resolve_quota())}]
     end}.

t_resolve_quota() ->
    DslVols = [#{container => <<"/data">>, persist => <<"q1">>,
                 quota => <<"512M">>}],
    {ok, [R]} = erlkoenig_volume:resolve(<<"app-q">>, DslVols, 1000, 1000),
    ?assertEqual(<<"q1">>, maps:get(persist, R)),
    ?assertEqual(512 * 1024 * 1024, maps:get(quota_bytes, R)).
