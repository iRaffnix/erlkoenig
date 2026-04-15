#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 15: DSL Config Pipeline (.exs → .term → erlkoenig_config:load)
%%
%% End-to-end: compile an Elixir DSL example to a .term file via
%% `elixir` (avoiding the erlkoenig-dsl escript so this test doesn't
%% depend on the DSL CLI being built), patch the binary path to the
%% test echo server, then load the config and verify containers spawn.
-mode(compile).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 15: DSL Config Pipeline ===~n~n"),
    test_helper:boot(),

    Root     = test_helper:project_root(),
    Example  = filename:join(Root, "examples/simple_echo.exs"),
    TermFile = "/tmp/erlkoenig_integration_15.term",
    DemoBin  = binary_to_list(test_helper:demo("echo_server")),

    %% Step 1: Compile the .exs into a .term file via `mix run` in the
    %% DSL project directory. Mix loads the erlkoenig_dsl app (which
    %% exports `Erlkoenig.Stack`) and evaluates the snippet. This keeps
    %% the test independent of the `erlkoenig-dsl` CLI escript.
    test_helper:step("mix compile .exs -> .term", fun() ->
        DslDir = filename:join(Root, "dsl"),
        Snippet = io_lib:format(
                    "[{mod, _} | _] = Code.compile_file(~p); "
                    "mod.write!(~p)",
                    [Example, TermFile]),
        %% Assume the DSL app is already compiled (rebar3/mix run earlier
        %% in this test suite). `mix run --no-deps-check --no-compile`
        %% skips work that's expensive on memory-constrained hosts.
        Cmd = "cd " ++ DslDir ++
              " && MIX_ENV=test mix run --no-deps-check --no-compile -e " ++
              shell_quote(lists:flatten(Snippet)) ++ " 2>&1",
        Output = os:cmd(Cmd),
        io:format("    ~ts", [Output]),
        case filelib:is_regular(TermFile) of
            true -> ok;
            false -> {error, {term_not_created, Output}}
        end
    end),

    %% Step 2: Parse and patch binary paths inside pods.containers
    %% (new DSL shape: containers live under pods, not at top level).
    test_helper:step("erlkoenig_config:parse/1 + patch binaries", fun() ->
        case erlkoenig_config:parse(TermFile) of
            {ok, Config} ->
                Pods = maps:get(pods, Config, []),
                Total = lists:sum([length(maps:get(containers, P, []))
                                   || P <- Pods]),
                io:format("    ~p pod(s), ~p container(s) total~n",
                          [length(Pods), Total]),
                BinPath = list_to_binary(DemoBin),
                PatchedPods = [patch_pod_binaries(P, BinPath) || P <- Pods],
                PatchedConfig = Config#{pods => PatchedPods},
                Formatted = io_lib:format("~tp.~n", [PatchedConfig]),
                file:write_file(TermFile, Formatted),
                case Total of
                    N when N > 0 -> ok;
                    _ -> {error, no_containers}
                end;
            {error, Reason} ->
                {error, {parse_failed, Reason}}
        end
    end),

    %% Step 3: Load config — spawns containers
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

    %% Step 4: Verify containers are running
    test_helper:step("Containers running", fun() ->
        Pids = try pg:get_members(erlkoenig_pg, erlkoenig_cts)
               catch error:_ -> []
               end,
        Running = lists:filter(fun(Pid) ->
            try erlkoenig:inspect(Pid) of
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

%% Replace every container's `binary` field with the given path.
patch_pod_binaries(Pod, BinPath) ->
    Containers = maps:get(containers, Pod, []),
    Patched = [C#{binary => BinPath} || C <- Containers],
    Pod#{containers => Patched}.

%% Wrap a string in single quotes for shell, escaping any single quotes.
shell_quote(S) ->
    Escaped = lists:flatten(
                [case C of
                     $' -> "'\\''";
                     Other -> Other
                 end || C <- S]),
    "'" ++ Escaped ++ "'".
