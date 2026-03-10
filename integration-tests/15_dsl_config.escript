#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 15: DSL Config Pipeline (erlkoenig-dsl → .term → erlkoenig_config:load)
%%
%% End-to-end: compile a DSL example with the escript, load the .term
%% file, verify containers spawn and respond.
-mode(compile).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 15: DSL Config Pipeline ===~n~n"),
    test_helper:boot(),

    Escript = filename:absname("dsl/erlkoenig-dsl"),
    Example = filename:absname("dsl/examples/live_test.exs"),
    TermFile = "/tmp/erlkoenig_integration_15.term",

    %% Step 1: Compile DSL example with escript
    test_helper:step("erlkoenig-dsl compile", fun() ->
        Cmd = Escript ++ " compile " ++ Example ++ " -o " ++ TermFile,
        case os:cmd(Cmd ++ " 2>&1") of
            Output ->
                io:format("    ~s", [Output]),
                case filelib:is_regular(TermFile) of
                    true -> ok;
                    false -> {error, {term_not_created, Output}}
                end
        end
    end),

    %% Step 2: Validate the term file
    test_helper:step("erlkoenig-dsl validate", fun() ->
        Cmd = Escript ++ " validate " ++ Example,
        Output = os:cmd(Cmd ++ " 2>&1"),
        io:format("    ~s", [Output]),
        case string:find(Output, "OK") of
            nomatch -> {error, {validation_failed, Output}};
            _ -> ok
        end
    end),

    %% Step 3: Parse the term file
    test_helper:step("erlkoenig_config:parse/1", fun() ->
        case erlkoenig_config:parse(TermFile) of
            {ok, Config} ->
                Containers = maps:get(containers, Config, []),
                io:format("    ~p container(s) in config~n", [length(Containers)]),
                case length(Containers) of
                    N when N > 0 -> ok;
                    _ -> {error, no_containers}
                end;
            {error, Reason} ->
                {error, {parse_failed, Reason}}
        end
    end),

    %% Step 4: Load config — spawns containers
    test_helper:step("erlkoenig_config:load/1", fun() ->
        case erlkoenig_config:load(TermFile) of
            {ok, Pids} ->
                io:format("    spawned ~p container(s)~n", [length(Pids)]),
                case length(Pids) of
                    N when N > 0 -> {ok, Pids};
                    _ -> {error, no_containers_spawned}
                end;
            {error, Reason} ->
                {error, {load_failed, Reason}}
        end
    end),

    timer:sleep(1500),

    %% Step 5: Verify containers are running
    test_helper:step("Containers running", fun() ->
        Pids = try pg:get_members(erlkoenig_pg, erlkoenig_cts)
               catch error:_ -> []
               end,
        Running = lists:filter(fun(Pid) ->
            try erlkoenig_core:inspect(Pid) of
                #{state := running} -> true;
                _ -> false
            catch _:_ -> false
            end
        end, Pids),
        io:format("    ~p container(s) running~n", [length(Running)]),
        case length(Running) of
            N when N > 0 -> ok;
            _ -> {error, no_running_containers}
        end
    end),

    %% Cleanup
    test_helper:step("Cleanup", fun() ->
        Pids = try pg:get_members(erlkoenig_pg, erlkoenig_cts)
               catch error:_ -> []
               end,
        test_helper:cleanup(Pids),
        file:delete(TermFile),
        ok
    end),

    io:format("~n=== Test 15 bestanden ===~n~n"),
    halt(0).
