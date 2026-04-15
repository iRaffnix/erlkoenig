-module(test_helper).
-export([boot/0,
         step/2, pass/1, fail/2, echo_test/3, cleanup/1,
         project_root/0,
         rt_binary/0,
         demo/1, demo_dir/0]).

-define(GREEN, "\e[32m").
-define(RED, "\e[31m").
-define(BOLD, "\e[1m").
-define(RESET, "\e[0m").

%% ============================================================
%% Project root discovery
%%
%% Integration tests need stable paths regardless of CWD. We find
%% the project root by walking up from the escript's own location
%% until we hit a `rebar.config' file. This works identically on
%% developer machines, CI runners, and installation hosts.
%% ============================================================

%% @doc Absolute path to the project root (directory containing
%% rebar.config). Walks up from the escript's own location (or from
%% the current working directory when called outside an escript,
%% e.g. from an `erl -eval' shell).
-spec project_root() -> string().
project_root() ->
    Start = case catch escript:script_name() of
        Name when is_list(Name), Name =/= [] ->
            filename:dirname(filename:absname(Name));
        _ ->
            {ok, Cwd} = file:get_cwd(),
            Cwd
    end,
    find_project_root(Start).

find_project_root(Dir) ->
    case filelib:is_regular(filename:join(Dir, "rebar.config")) of
        true  -> Dir;
        false ->
            Parent = filename:dirname(Dir),
            case Parent =:= Dir of
                true  -> error({project_root_not_found, Dir});
                false -> find_project_root(Parent)
            end
    end.

%% ============================================================
%% Path helpers
%% ============================================================

%% @doc Absolute path to the erlkoenig_rt binary.
%%
%% Search order:
%%   1. $ERLKOENIG_RT_PATH
%%   2. /opt/erlkoenig/rt/erlkoenig_rt (installed)
%%   3. <project>/build/release/erlkoenig_rt (dev build)
-spec rt_binary() -> string().
rt_binary() ->
    case os:getenv("ERLKOENIG_RT_PATH") of
        false ->
            first_regular(
                ["/opt/erlkoenig/rt/erlkoenig_rt",
                 filename:join(project_root(), "build/release/erlkoenig_rt")],
                rt_binary_not_found);
        Path ->
            Path
    end.

%% @doc Absolute path to a demo binary (as binary — ready for erlkoenig:spawn/2).
-spec demo(string()) -> binary().
demo(Name) ->
    list_to_binary(demo_dir() ++ "/test-erlkoenig-" ++ Name).

%% @doc Absolute path to the directory containing demo binaries.
%%
%% Search order:
%%   1. $ERLKOENIG_DEMO_DIR
%%   2. code:priv_dir(erlkoenig)/demo   (when the release is loaded)
%%   3. /opt/erlkoenig/rt/demo          (installed)
%%   4. <project>/build/release/demo    (dev build)
-spec demo_dir() -> string().
demo_dir() ->
    case os:getenv("ERLKOENIG_DEMO_DIR") of
        false ->
            first_dir(
                [priv_demo_dir(),
                 "/opt/erlkoenig/rt/demo",
                 filename:join(project_root(), "build/release/demo")],
                demo_dir_not_found);
        Dir ->
            Dir
    end.

priv_demo_dir() ->
    try code:priv_dir(erlkoenig) of
        {error, _} -> undefined;
        PrivDir    -> filename:join(PrivDir, "demo")
    catch _:_ -> undefined
    end.

first_regular(Paths, ErrReason) ->
    case [P || P <- Paths, is_list(P), filelib:is_regular(P)] of
        [First | _] -> First;
        [] -> error({ErrReason, Paths})
    end.

first_dir(Paths, ErrReason) ->
    case [P || P <- Paths, is_list(P), filelib:is_dir(P)] of
        [First | _] -> First;
        [] -> error({ErrReason, Paths})
    end.

%% ============================================================
%% Application boot
%% ============================================================

%% @doc Boot erlkoenig OTP app with sys.config from the project.
boot() ->
    Root = project_root(),
    code:add_pathsz(filelib:wildcard(
        filename:join(Root, "_build/default/lib/*/ebin"))),
    code:add_pathsz(filelib:wildcard(
        filename:join(Root, "_build/default/checkouts/*/ebin"))),
    SysConfig = filename:join(Root, "apps/erlkoenig/config/sys.config"),
    {ok, [AppEnvs]} = file:consult(SysConfig),
    lists:foreach(fun({App, Kvs}) ->
        ok = application:load(App),
        lists:foreach(fun({K, V}) ->
            application:set_env(App, K, V)
        end, Kvs)
    end, AppEnvs),
    logger:set_primary_config(level, none),
    {ok, _} = application:ensure_all_started(erlkoenig),
    ok.

%% ============================================================
%% Test step runner
%% ============================================================

%% @doc Run a test step with name and fun.
step(Name, Fun) ->
    io:format("[....] ~s", [Name]),
    try Fun() of
        ok ->
            pass(Name);
        {ok, Val} ->
            pass(Name),
            Val;
        {error, Reason} ->
            fail(Name, Reason)
    catch
        Class:Error:Stack ->
            io:format("\r[~sFAIL~s] ~s~n  ~p:~p~n  ~p~n",
                      [?RED, ?RESET, Name, Class, Error,
                       lists:sublist(Stack, 3)]),
            cleanup([]),
            halt(1)
    end.

pass(Name) ->
    io:format("\r[~sOK~s  ] ~s~n", [?GREEN, ?RESET, Name]).

fail(Name, Reason) ->
    io:format("\r[~sFAIL~s] ~s: ~p~n", [?RED, ?RESET, Name, Reason]),
    cleanup([]),
    halt(1).

%% @doc TCP echo roundtrip test.
echo_test(Ip, Port, Msg) ->
    case gen_tcp:connect(Ip, Port, [binary, {active, false}], 5000) of
        {ok, Sock} ->
            ok = gen_tcp:send(Sock, Msg),
            case gen_tcp:recv(Sock, 0, 5000) of
                {ok, Msg} ->
                    io:format("    echo: ~s~n", [Msg]),
                    gen_tcp:close(Sock),
                    ok;
                {ok, Other} ->
                    gen_tcp:close(Sock),
                    {error, {unexpected, Other}};
                {error, R} ->
                    gen_tcp:close(Sock),
                    {error, {recv, R}}
            end;
        {error, R} ->
            {error, {connect, Ip, Port, R}}
    end.

%% @doc Stop all pids and exit cleanly.
cleanup(Pids) ->
    lists:foreach(fun(Pid) ->
        catch erlkoenig:stop(Pid)
    end, Pids),
    timer:sleep(300).
