#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 41: `:journal.local` end-to-end.
%%
%% First service capability built on the SPEC-AS-005 audit hash chain.
%% A workload connects to a Unix socket, writes JSON-line entries,
%% and they land in the audit chain — fully tamper-evident.
%%
%% Verifies:
%%   - Daemon binds the configured socket path.
%%   - A client can connect via gen_tcp {local, Path}.
%%   - Multiple JSON entries from one connection produce one audit
%%     event each, with subject/level/msg/fields preserved.
%%   - Two concurrent clients don't interleave or corrupt entries.
%%   - Garbage lines are dropped silently — subsequent good entries
%%     still arrive (the daemon does NOT close the socket on bad
%%     input, so flaky producers stay productive).
%%   - The whole resulting audit log validates as a hash chain
%%     (`verify_chain/1` returns `{ok, N}`).
-mode(compile).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 41: journal.local ===~n~n"),

    test_helper:add_paths(),
    logger:set_primary_config(level, error),

    Tag = integer_to_list(os:system_time(microsecond)) ++ "_" ++
          integer_to_list(erlang:unique_integer([positive])),
    Dir       = "/tmp/erlkoenig_journal_int_" ++ Tag,
    SockPath  = Dir ++ "/journal.sock",
    AuditPath = Dir ++ "/audit.jsonl",
    ok = filelib:ensure_dir(SockPath),

    application:set_env(erlkoenig, audit_path, AuditPath),
    application:set_env(erlkoenig, journal_local_path, SockPath),
    _ = (catch gen_server:stop(erlkoenig_journal_local)),
    _ = (catch gen_server:stop(erlkoenig_audit)),
    {ok, _AuditPid}   = erlkoenig_audit:start_link(),
    {ok, _JournalPid} = erlkoenig_journal_local:start_link(),

    test_helper:step(
      "daemon binds the configured socket path",
      fun() ->
          SockPath = erlkoenig_journal_local:socket_path(),
          {ok, _} = file:read_file_info(SockPath),
          ok
      end),

    test_helper:step(
      "single client streams 3 entries -> 3 audit events",
      fun() ->
          Sock = connect(SockPath),
          send(Sock, #{<<"subject">> => <<"web">>,
                       <<"level">> => <<"info">>,
                       <<"msg">> => <<"start">>,
                       <<"fields">> => #{<<"port">> => 8080}}),
          send(Sock, #{<<"subject">> => <<"web">>,
                       <<"level">> => <<"info">>,
                       <<"msg">> => <<"req">>,
                       <<"fields">> => #{<<"path">> => <<"/health">>}}),
          send(Sock, #{<<"subject">> => <<"web">>,
                       <<"level">> => <<"warn">>,
                       <<"msg">> => <<"slow">>,
                       <<"fields">> => #{<<"ms">> => 1234}}),
          gen_tcp:close(Sock),
          Events = wait_for(AuditPath, 3, 1500),
          3 = length(Events),
          %% Roundtrip the field that's hardest to preserve.
          E1 = hd(Events),
          <<"web">> = maps:get(<<"subject">>, E1),
          <<"start">> = maps:get(<<"msg">>, E1),
          #{<<"port">> := 8080} = maps:get(<<"fields">>, E1),
          ok
      end),

    test_helper:step(
      "two concurrent clients stream cleanly into the chain",
      fun() ->
          Self = self(),
          Spawn = fun(Subject, Count) ->
              spawn(fun() ->
                  Sock = connect(SockPath),
                  lists:foreach(fun(I) ->
                      send(Sock, #{<<"subject">> => Subject,
                                   <<"msg">> => integer_to_binary(I)})
                  end, lists:seq(1, Count)),
                  gen_tcp:close(Sock),
                  Self ! {done, Subject}
              end)
          end,
          Spawn(<<"alice">>, 10),
          Spawn(<<"bob">>,   10),
          receive {done, <<"alice">>} -> ok after 3000 -> error(timeout_alice) end,
          receive {done, <<"bob">>}   -> ok after 3000 -> error(timeout_bob) end,
          %% 3 from the previous step + 20 from this one.
          Events = wait_for(AuditPath, 23, 3000),
          23 = length(Events),
          ok
      end),

    test_helper:step(
      "garbage lines are dropped, good lines still arrive",
      fun() ->
          Sock = connect(SockPath),
          ok = gen_tcp:send(Sock, <<"this is not json\n">>),
          ok = gen_tcp:send(Sock, <<"{ malformed\n">>),
          send(Sock, #{<<"subject">> => <<"after-garbage">>,
                       <<"msg">> => <<"survived">>}),
          gen_tcp:close(Sock),
          Events = wait_for(AuditPath, 24, 1500),
          24 = length(Events),
          E = lists:last(Events),
          <<"after-garbage">> = maps:get(<<"subject">>, E),
          ok
      end),

    test_helper:step(
      "full audit log validates as a hash chain",
      fun() ->
          {ok, 24} = erlkoenig_audit:verify_chain(AuditPath),
          ok
      end),

    %% Cleanup
    _ = gen_server:stop(erlkoenig_journal_local),
    _ = gen_server:stop(erlkoenig_audit),
    {ok, Files} = file:list_dir(Dir),
    lists:foreach(fun(F) -> file:delete(filename:join(Dir, F)) end, Files),
    file:del_dir(Dir),
    application:unset_env(erlkoenig, audit_path),
    application:unset_env(erlkoenig, journal_local_path),

    io:format("~n=== Test 41 passed ===~n"),
    halt(0).

connect(SockPath) ->
    {ok, Sock} = gen_tcp:connect({local, SockPath}, 0,
                                 [binary, {packet, line}, {active, false}],
                                 2000),
    Sock.

send(Sock, Map) ->
    Line = iolist_to_binary([json:encode(Map), <<"\n">>]),
    ok = gen_tcp:send(Sock, Line).

wait_for(Path, N, TimeoutMs) ->
    wait_for(Path, N, TimeoutMs, erlang:monotonic_time(millisecond)).
wait_for(Path, N, TimeoutMs, Start) ->
    _ = erlkoenig_audit:query(#{limit => 0}),  %% flush
    timer:sleep(20),
    Events = case file:read_file(Path) of
        {ok, B} ->
            [json:decode(L)
             || L <- binary:split(B, <<"\n">>, [global]), L =/= <<>>];
        _ -> []
    end,
    case length(Events) >= N of
        true -> Events;
        false ->
            case erlang:monotonic_time(millisecond) - Start >= TimeoutMs of
                true  -> Events;
                false -> wait_for(Path, N, TimeoutMs, Start)
            end
    end.
