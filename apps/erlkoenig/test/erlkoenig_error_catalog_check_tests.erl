%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_error_catalog_check_tests).

-include_lib("eunit/include/eunit.hrl").

catalog_validates_test() ->
    ?assertEqual(ok, erlkoenig_error:validate_catalog()).

production_error_producers_are_cataloged_test() ->
    Refs = production_error_refs(),
    Missing = [format_ref(Ref) || Ref = #{code := Code} <- Refs,
                            erlkoenig_error:lookup(Code) =:= {error, not_found}],
    ?assertEqual([], Missing).

catalog_entries_are_used_soft_check_test() ->
    {ok, Entries} = erlkoenig_error:catalog(),
    Used = maps:from_list([{Code, true} || #{code := Code} <- production_error_refs()]),
    Unused = [Code || {Code, _Meta} <- Entries,
                      not maps:is_key(Code, Used)],
    case Unused of
        [] -> ok;
        _ -> ?debugFmt("Unused error catalog entries: ~p", [Unused])
    end,
    ok.

production_error_refs() ->
    Files0 = filelib:wildcard(filename:join(project_app_dir(), "src/*.erl")) ++
             filelib:wildcard(filename:join(project_app_dir(), "include/*.hrl")) ++
             ["dist/ek.escript"],
    Files = [File || File <- Files0,
                     filelib:is_regular(File),
                     filename:basename(File) =/= "erlkoenig_error.erl"],
    lists:append([file_error_refs(File) || File <- Files]).

file_error_refs(File) ->
    {ok, Bin} = file:read_file(File),
    lists:append([scan_pattern(File, Bin, Pattern, Kind) ||
                     {Kind, Pattern} <- producer_patterns()]).

producer_patterns() ->
    [{ek_error,
      <<"\\?EK_ERROR\\s*\\(\\s*([a-z][a-zA-Z0-9_]*)\\s*,\\s*"
        "([a-z][a-zA-Z0-9_]*)\\s*,">>},
     {ek_error_s,
      <<"\\?EK_ERROR_S\\s*\\(\\s*[a-z][a-zA-Z0-9_]*\\s*,\\s*"
        "([a-z][a-zA-Z0-9_]*)\\s*,\\s*([a-z][a-zA-Z0-9_]*)\\s*,">>},
     {make,
      <<"erlkoenig_error:make\\s*\\(\\s*([a-z][a-zA-Z0-9_]*)\\s*,\\s*"
        "([a-z][a-zA-Z0-9_]*)">>},
     {doctor_probe,
      <<"doctor_probe\\s*\\(\\s*[a-z][a-zA-Z0-9_]*\\s*,\\s*"
        "([a-z][a-zA-Z0-9_]*)\\s*,\\s*([a-z][a-zA-Z0-9_]*)\\s*,">>}].

scan_pattern(File, Bin, Pattern, Kind) ->
    case re:run(Bin, Pattern, [global, {capture, all, index}]) of
        nomatch ->
            [];
        {match, Matches} ->
            [match_ref(File, Bin, Kind, Match) || Match <- Matches]
    end.

match_ref(File, Bin, Kind, [{Start, _Len}, {_CStart, _CLen}, {_RStart, _RLen}] = Match) ->
    [_, ComponentMatch, ReasonMatch] = Match,
    Component = binary_atom(Bin, ComponentMatch),
    Reason = binary_atom(Bin, ReasonMatch),
    Code = erlkoenig_error:code(Component, Reason),
    #{file => File,
      line => line_number(Bin, Start),
      kind => Kind,
      component => Component,
      reason => Reason,
      code => Code}.

format_ref(#{file := File, line := Line, kind := Kind,
             component := Component, reason := Reason, code := Code}) ->
    {File, Line, Kind, Component, Reason, Code}.

binary_atom(Bin, {Start, Len}) ->
    binary_to_atom(binary:part(Bin, Start, Len), utf8).

line_number(Bin, Start) ->
    Prefix = binary:part(Bin, 0, Start),
    length(binary:split(Prefix, <<"\n">>, [global])).

project_app_dir() ->
    case filelib:is_dir("apps/erlkoenig/src") of
        true -> "apps/erlkoenig";
        false -> "."
    end.
