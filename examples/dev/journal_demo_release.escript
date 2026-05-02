#!/usr/bin/env escript
%% -*- erlang -*-
%% examples/dev/journal_demo_release.escript
%%
%% Production-side companion to examples/dev/journal_demo.exs:
%% the same end-to-end walkthrough (start audit + journal,
%% connect, send entries, verify the chain) but against an
%% INSTALLED release tarball instead of a dev checkout.
%%
%% Usage on a node where /opt/erlkoenig (or $ERLKOENIG_LIB)
%% holds the extracted release:
%%
%%   escript examples/dev/journal_demo_release.escript
%%
%% Exits 0 if the chain validated, 1 otherwise. Tutorial-friendly
%% output (no logger spam, prints headings + results).
-mode(compile).

main(_) ->
    %% --- 1. Find and load the installed BEAMs ---
    LibDir = case os:getenv("ERLKOENIG_LIB") of
        false -> "/opt/erlkoenig/lib";
        Other -> Other
    end,
    case filelib:wildcard(LibDir ++ "/*/ebin") of
        [] ->
            io:format(standard_error,
                "No release BEAMs found under ~s~n"
                "  set ERLKOENIG_LIB to the lib/ dir of your release~n",
                [LibDir]),
            halt(1);
        Ebins ->
            lists:foreach(fun(E) -> code:add_pathz(E) end, Ebins)
    end,

    %% Tutorial-friendly: silence the audit/journal :info startup lines.
    logger:set_primary_config(level, warning),

    %% --- 2. Sandbox + start daemons ---
    Tag = integer_to_list(os:system_time(microsecond)) ++ "_" ++
          integer_to_list(erlang:unique_integer([positive])),
    Sandbox  = "/tmp/ek-journal-demo-" ++ Tag,
    AuditPath = Sandbox ++ "/audit.jsonl",
    SockPath  = Sandbox ++ "/journal.sock",
    ok = filelib:ensure_dir(AuditPath),

    application:set_env(erlkoenig, audit_path, AuditPath),
    application:set_env(erlkoenig, journal_local_path, SockPath),

    {ok, AuditPid}   = erlkoenig_audit:start_link(),
    {ok, _}          = erlkoenig_journal_local:start_link(),

    io:format("~n=== daemons up ===~n"),
    io:format("audit_path : ~s~n", [AuditPath]),
    io:format("socket     : ~s~n", [SockPath]),

    %% --- 3. Workload — open the socket the env var would point at ---
    %% In a real container the runtime bind-mounts the host socket
    %% to the path JOURNAL_LOCAL_SOCK names. Here, no namespace, so
    %% we just connect to the host socket directly.
    {ok, Sock} = gen_tcp:connect({local, SockPath}, 0,
        [binary, {packet, line}, {active, false}], 2000),

    Send = fun(Map) ->
        Line = iolist_to_binary([json:encode(Map), $\n]),
        ok = gen_tcp:send(Sock, Line)
    end,
    Send(#{<<"subject">> => <<"web">>, <<"level">> => <<"info">>,
           <<"msg">> => <<"starting">>,
           <<"fields">> => #{<<"port">> => 8080}}),
    Send(#{<<"subject">> => <<"web">>, <<"level">> => <<"info">>,
           <<"msg">> => <<"ready">>}),
    Send(#{<<"subject">> => <<"web">>, <<"level">> => <<"warn">>,
           <<"msg">> => <<"slow request">>,
           <<"fields">> => #{<<"ms">> => 1234}}),
    gen_tcp:close(Sock),

    %% Synchronous flush — query/1 hits the audit gen_server, which
    %% serialises in front of the cast queue.
    timer:sleep(150),
    _ = erlkoenig_audit:query(#{limit => 0}),
    timer:sleep(50),

    %% --- 4. Verify ---
    Result = erlkoenig_audit:verify_chain(AuditPath),
    io:format("~n=== verify_chain ===~n~p~n", [Result]),

    {ok, Bin} = file:read_file(AuditPath),
    Events = [json:decode(L)
              || L <- binary:split(Bin, <<"\n">>, [global]), L =/= <<>>],
    io:format("~n=== chain content (~p events) ===~n", [length(Events)]),
    lists:foreach(fun(E) ->
        io:format("seq=~p  type=~s  subject=~s  msg=~s~n",
            [maps:get(<<"seq">>, E),
             maps:get(<<"type">>, E),
             maps:get(<<"subject">>, E),
             maps:get(<<"msg">>, E)])
    end, Events),

    %% --- Cleanup ---
    catch erlkoenig_journal_local:stop(),
    catch gen_server:stop(AuditPid),
    {ok, Files} = file:list_dir(Sandbox),
    lists:foreach(fun(F) -> file:delete(filename:join(Sandbox, F)) end, Files),
    file:del_dir(Sandbox),

    case Result of
        {ok, _} ->
            io:format("~n=== demo passed ===~n"),
            halt(0);
        _ ->
            io:format("~n=== demo FAILED ===~n"),
            halt(1)
    end.
