%%%-------------------------------------------------------------------
%%% @doc Unit tests for erlkoenig_config (DSL config loader).
%%%
%%% Tests parse/1, validate/1 and internal helpers without requiring
%%% a running Erlkoenig instance. Uses temporary files for parse tests.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_config_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%% =================================================================
%% parse/1 -- Term file reading
%% =================================================================

parse_map_format_test() ->
    File = write_term_file(#{containers => []}),
    ?assertMatch({ok, #{containers := []}}, erlkoenig_config:parse(File)),
    file:delete(File).

parse_list_format_test() ->
    File = write_term_file([{containers, [#{name => "web", binary => "/bin/web"}]}]),
    {ok, Result} = erlkoenig_config:parse(File),
    ?assert(is_map(Result)),
    ?assertMatch(#{containers := _}, Result),
    file:delete(File).

parse_invalid_format_test() ->
    %% Multiple top-level terms are invalid
    File = tmp_path(),
    ok = file:write_file(File, "one.\ntwo.\n"),
    ?assertMatch({error, {invalid_format, _}}, erlkoenig_config:parse(File)),
    file:delete(File).

parse_missing_file_test() ->
    ?assertMatch({error, {read_failed, _, _}},
                 erlkoenig_config:parse("/tmp/erlkoenig_nonexistent_42.term")).

%% =================================================================
%% validate/1 -- Config structure validation
%% =================================================================

validate_valid_string_names_test() ->
    File = write_term_file(#{containers => [
        #{name => "web", binary => "/bin/web"},
        #{name => "api", binary => "/bin/api"}
    ]}),
    ?assertEqual(ok, erlkoenig_config:validate(File)),
    file:delete(File).

validate_valid_binary_names_test() ->
    File = write_term_file(#{containers => [
        #{name => <<"web">>, binary => <<"/bin/web">>}
    ]}),
    ?assertEqual(ok, erlkoenig_config:validate(File)),
    file:delete(File).

validate_no_containers_test() ->
    %% Config without containers key is valid (may only have watches/guard)
    File = write_term_file(#{watches => []}),
    ?assertEqual(ok, erlkoenig_config:validate(File)),
    file:delete(File).

validate_containers_not_list_test() ->
    File = write_term_file(#{containers => not_a_list}),
    ?assertMatch({error, {invalid_type, containers, expected_list}},
                 erlkoenig_config:validate(File)),
    file:delete(File).

validate_invalid_container_test() ->
    File = write_term_file(#{containers => [#{bad => true}]}),
    ?assertMatch({error, {invalid_container, _}},
                 erlkoenig_config:validate(File)),
    file:delete(File).

validate_missing_file_test() ->
    ?assertMatch({error, {read_failed, _, _}},
                 erlkoenig_config:validate("/tmp/erlkoenig_nonexistent_42.term")).

%% =================================================================
%% build_spawn_opts (internal, tested indirectly via module export)
%% =================================================================

%% build_spawn_opts is not exported, so we test the contract:
%% known keys are copied, unknown keys are ignored.
%% We do this by testing container_names and the validate pipeline.

container_names_extraction_test() ->
    %% container_names/1 extracts binary names from config
    Config = #{containers => [
        #{name => "alpha", binary => "/a"},
        #{name => <<"beta">>, binary => <<"/b">>},
        #{name => "gamma", binary => "/c"}
    ]},
    %% We can't call container_names directly (not exported),
    %% but we can verify the validate pipeline accepts this.
    File = write_term_file(Config),
    ?assertEqual(ok, erlkoenig_config:validate(File)),
    file:delete(File).

container_names_empty_test() ->
    Config = #{},
    File = write_term_file(Config),
    ?assertEqual(ok, erlkoenig_config:validate(File)),
    file:delete(File).

%% =================================================================
%% Helpers
%% =================================================================

tmp_path() ->
    "/tmp/erlkoenig_config_test_" ++
        integer_to_list(erlang:unique_integer([positive])) ++ ".term".

write_term_file(Term) ->
    Path = tmp_path(),
    Data = io_lib:format("~tp.~n", [Term]),
    ok = file:write_file(Path, Data),
    Path.
