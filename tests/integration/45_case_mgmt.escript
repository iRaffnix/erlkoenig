#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 45: case_mgmt full-stack walking skeleton.
%%
%% Spawns the case_mgmt Go binary in an erlkoenig container that
%% declares `requires :"postgres.local"` + `:"journal.local"` +
%% `:"dns.local"`. Verifies end-to-end:
%%
%%   1. Container reaches running state with /run/erlkoenig/
%%      bind-mounted (postgres + journal sockets visible inside).
%%   2. Container's HTTP API on :8080 responds to /healthz.
%%   3. POST /tasks inserts into Postgres via the bind-mounted
%%      socket, peer-auth maps the container uid to the case_mgmt
%%      role, no password involved.
%%   4. Same call writes a `task_created` entry to journal.local
%%      → audit chain. Audit chain validates with verify_chain.
%%   5. Optional: tamper the chain → verify_chain reports the
%%      break at the right line.
%%
%% Mirrors the DSL term emitted by examples/case_mgmt_stack.exs
%% but spawns directly so this can run as a single sudo escript
%% without the full ek-up flow. Operators in production use the
%% .exs via ek up.
-mode(compile).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 45: case_mgmt walking skeleton ===~n~n"),

    case string:trim(os:cmd("id -u")) of
        "0" -> ok;
        _   -> io:format("ERROR: must run as root~n"), halt(1)
    end,

    Tag = integer_to_list(os:system_time(microsecond)),
    AuditPath = "/tmp/erlkoenig_audit_test_45_" ++ Tag ++ ".jsonl",
    SignKey   = "/tmp/erlkoenig_sign_45_" ++ Tag ++ ".key",
    HmacKey   = "/tmp/erlkoenig_hmac_45_" ++ Tag ++ ".key",
    JournalSock = "/run/erlkoenig/journal.sock",

    %% Fresh keys for the audit chain so we can verify with the
    %% Go verifier at the end.
    {_, Priv} = crypto:generate_key(eddsa, ed25519),
    file:write_file(SignKey, Priv),
    file:write_file(HmacKey, crypto:strong_rand_bytes(32)),

    application:set_env(erlkoenig, audit_path, AuditPath),
    application:set_env(erlkoenig, audit_signing_key, SignKey),
    application:set_env(erlkoenig, audit_hmac_key, HmacKey),
    application:set_env(erlkoenig, journal_local_path, JournalSock),
    test_helper:boot(),
    logger:set_primary_config(level, error),

    %% journal.local daemon is opt-in; start it manually so the
    %% container's bind-mount has something on the other end.
    {ok, _} = erlkoenig_journal_local:start_link(),

    Pid = test_helper:step(
      "spawn case_mgmt container with postgres.local + journal.local",
      fun() ->
          %% Same opts the DSL emits, hand-rolled here.
          R = erlkoenig:spawn(
                <<"/opt/erlkoenig/rt/demo/case_mgmt">>,
                #{ip => {10, 0, 0, 235},
                  name => list_to_binary("case_mgmt-" ++ Tag),
                  uid => 65534, gid => 65534,
                  socket_mounts => [
                      #{host => <<"/run/erlkoenig/">>,
                        container => <<"/run/erlkoenig/">>,
                        read_only => false}
                  ],
                  env => [{<<"PGHOST">>, <<"/run/erlkoenig">>},
                          {<<"JOURNAL_LOCAL_SOCK">>, list_to_binary(JournalSock)},
                          {<<"PGUSER">>, <<"case_mgmt">>},
                          {<<"PGDATABASE">>, <<"cases">>}]}),
          {ok, P} = R,
          ok = wait_for_running(P, 15000),
          {ok, P}
      end),

    Info = erlkoenig:inspect(Pid),
    OsPid = maps:get(os_pid, Info),
    NetInfo = maps:get(net_info, Info),
    {A, B, C, D} = maps:get(ip, NetInfo),
    IpStr = lists:flatten(io_lib:format("~p.~p.~p.~p", [A, B, C, D])),
    io:format("    container os_pid=~p ip=~s~n", [OsPid, IpStr]),

    test_helper:step(
      "container's /healthz returns ok",
      fun() ->
          %% Give case_mgmt a moment to bind :8080 + ping postgres.
          timer:sleep(800),
          Out = string:trim(os:cmd(
              "curl -sf --max-time 3 http://" ++ IpStr ++ ":8080/healthz")),
          case Out of
              "ok" -> ok;
              _    -> error({healthz_unexpected, Out})
          end
      end),

    {TaskId, _} = test_helper:step(
      "POST /tasks creates a task in Postgres + writes journal entry",
      fun() ->
          Body = "{\"title\":\"Smoke test " ++ Tag ++
                 "\",\"description\":\"end-to-end probe via integration test\"}",
          Out = string:trim(os:cmd(
              "curl -s --max-time 3 -X POST http://" ++ IpStr ++
              ":8080/tasks -d '" ++ Body ++ "'")),
          io:format("    response: ~s~n", [Out]),
          %% trivial id extraction — body is {"id":N,"title":...,...}
          {match, [IdStr]} =
              re:run(Out, "\"id\":(\\d+)",
                     [{capture, all_but_first, list}]),
          {ok, {list_to_integer(IdStr), Out}}
      end),

    test_helper:step(
      "POST a note + GET /tasks/:id sees both fields",
      fun() ->
          NoteBody = "{\"body\":\"first triage note from integration test\"}",
          _ = os:cmd("curl -s --max-time 3 -X POST http://" ++ IpStr ++
              ":8080/tasks/" ++ integer_to_list(TaskId) ++ "/notes -d '" ++
              NoteBody ++ "'"),
          timer:sleep(200),
          Got = string:trim(os:cmd(
              "curl -s --max-time 3 http://" ++ IpStr ++
              ":8080/tasks/" ++ integer_to_list(TaskId))),
          io:format("    GET response: ~s~n", [Got]),
          case re:run(Got, "first triage note", [{capture, none}]) of
              match -> ok;
              _     -> error({note_not_found, Got})
          end
      end),

    test_helper:step(
      "audit chain captured the journal entries",
      fun() ->
          timer:sleep(300),
          _ = erlkoenig_audit:query(#{limit => 0}),
          timer:sleep(100),
          {ok, N} = erlkoenig_audit:verify_chain(AuditPath),
          io:format("    chain has ~p event(s)~n", [N]),
          case N >= 2 of
              true  -> ok;
              false -> error({too_few_events, N})
          end
      end),

    %% Cleanup
    catch erlkoenig:stop(Pid),
    catch erlkoenig_journal_local:stop(),
    _ = file:delete(SignKey),
    _ = file:delete(HmacKey),
    %% Audit log is kept for inspection / running the Go verifier.
    io:format("~n    audit log kept at: ~s~n", [AuditPath]),
    io:format("~n=== Test 45 passed ===~n"),
    halt(0).

wait_for_running(P, TimeoutMs) ->
    wait_for_running(P, TimeoutMs, erlang:monotonic_time(millisecond)).
wait_for_running(P, TimeoutMs, Start) ->
    case erlkoenig:inspect(P) of
        #{state := running} -> ok;
        #{state := failed, error := Why} -> error({container_failed, Why});
        {error, not_found} -> error({container_disappeared, P});
        _ ->
            case erlang:monotonic_time(millisecond) - Start >= TimeoutMs of
                true  -> error(timeout_waiting_for_running);
                false ->
                    timer:sleep(100),
                    wait_for_running(P, TimeoutMs, Start)
            end
    end.
