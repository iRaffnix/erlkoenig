%%%-------------------------------------------------------------------
%%% @doc Unit tests for erlkoenig_volume.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_volume_tests).

-include_lib("eunit/include/eunit.hrl").

%% =================================================================
%% validate_persist_name tests
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
%% resolve_host_path tests
%% =================================================================

resolve_host_path_test() ->
    ?assertEqual(<<"/var/lib/erlkoenig/volumes/myapp/db">>,
                 erlkoenig_volume:resolve_host_path(<<"myapp">>, <<"db">>)).

resolve_host_path_with_dashes_test() ->
    ?assertEqual(<<"/var/lib/erlkoenig/volumes/archive/archive-logs">>,
                 erlkoenig_volume:resolve_host_path(<<"archive">>, <<"archive-logs">>)).

%% =================================================================
%% resolve tests
%% =================================================================

resolve_empty_test() ->
    ?assertEqual({ok, []}, erlkoenig_volume:resolve(<<"app">>, [])).

resolve_single_test() ->
    DslVols = [#{container => <<"/data/db">>, persist => <<"db">>, read_only => false}],
    {ok, [Resolved]} = erlkoenig_volume:resolve(<<"app">>, DslVols),
    ?assertEqual(<<"/var/lib/erlkoenig/volumes/app/db">>, maps:get(host, Resolved)),
    ?assertEqual(<<"/data/db">>, maps:get(container, Resolved)),
    ?assertEqual(<<"db">>, maps:get(persist, Resolved)),
    ?assertEqual(false, maps:get(read_only, Resolved)).

resolve_readonly_test() ->
    DslVols = [#{container => <<"/etc/config">>, persist => <<"cfg">>, read_only => true}],
    {ok, [Resolved]} = erlkoenig_volume:resolve(<<"app">>, DslVols),
    ?assertEqual(true, maps:get(read_only, Resolved)).

resolve_default_readonly_test() ->
    %% read_only defaults to false when not specified
    DslVols = [#{container => <<"/data">>, persist => <<"data">>}],
    {ok, [Resolved]} = erlkoenig_volume:resolve(<<"app">>, DslVols),
    ?assertEqual(false, maps:get(read_only, Resolved)).

resolve_invalid_name_test() ->
    DslVols = [#{container => <<"/data">>, persist => <<"../bad">>, read_only => false}],
    ?assertEqual({error, invalid_persist_name},
                 erlkoenig_volume:resolve(<<"app">>, DslVols)).

resolve_multiple_test() ->
    DslVols = [#{container => <<"/data/db">>, persist => <<"db">>},
               #{container => <<"/var/log">>, persist => <<"logs">>}],
    {ok, Resolved} = erlkoenig_volume:resolve(<<"app">>, DslVols),
    ?assertEqual(2, length(Resolved)).
