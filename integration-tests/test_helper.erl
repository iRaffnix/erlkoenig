-module(test_helper).
-export([boot/0, step/2, pass/1, fail/2, echo_test/3, cleanup/1, demo/1]).

-define(GREEN, "\e[32m").
-define(RED, "\e[31m").
-define(BOLD, "\e[1m").
-define(RESET, "\e[0m").

%% @doc Boot erlkoenig OTP app with sys.config.
boot() ->
    code:add_pathsz(filelib:wildcard("_build/default/lib/*/ebin")),
    code:add_pathsz(filelib:wildcard("_build/default/checkouts/*/ebin")),
    {ok, [AppEnvs]} = file:consult("apps/erlkoenig_core/config/sys.config"),
    lists:foreach(fun({App, Kvs}) ->
        ok = application:load(App),
        lists:foreach(fun({K, V}) ->
            application:set_env(App, K, V)
        end, Kvs)
    end, AppEnvs),
    logger:set_primary_config(level, none),
    {ok, _} = application:ensure_all_started(erlkoenig_core),
    ok.

%% @doc Path to a demo binary (as binary for erlkoenig_core:spawn/2).
%%
%% Search order:
%%   1. $ERLKOENIG_DEMO_DIR environment variable
%%   2. code:priv_dir(erlkoenig_core)/demo/
%%   3. build/demo/  (project root)
demo(Name) ->
    list_to_binary(demo_dir() ++ "/test-erlkoenig-" ++ Name).

demo_dir() ->
    case os:getenv("ERLKOENIG_DEMO_DIR") of
        false -> demo_dir_priv();
        Dir   -> Dir
    end.

demo_dir_priv() ->
    try code:priv_dir(erlkoenig_core) of
        PrivDir ->
            D = filename:join(PrivDir, "demo"),
            case filelib:is_dir(D) of
                true  -> D;
                false -> demo_dir_build()
            end
    catch _:_ ->
        demo_dir_build()
    end.

demo_dir_build() ->
    D = filename:absname(filename:join(["build", "release", "demo"])),
    case filelib:is_dir(D) of
        true  -> D;
        false -> error({demo_dir_not_found, D})
    end.

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
        catch erlkoenig_core:stop(Pid)
    end, Pids),
    timer:sleep(300).
