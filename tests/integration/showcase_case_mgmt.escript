#!/usr/bin/env escript
%% -*- erlang -*-
%% showcase_case_mgmt.escript — long-running demo pod.
%%
%% Spawns the 2-container case_mgmt pod (case_mgmt + deadline_worker)
%% and keeps them running until SIGINT. Prints the URL the operator
%% can curl. Audit log path is printed at the start so the Go
%% verifier can be run against it at any time.
%%
%% Run from `make showcase-up` after `make showcase` has deployed
%% the binaries + seeded the database.
-mode(compile).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== case_mgmt Showcase — long-running pod ===~n~n"),

    case string:trim(os:cmd("id -u")) of
        "0" -> ok;
        _   -> io:format("ERROR: must run as root~n"), halt(1)
    end,

    %% Start the escript's BEAM as a named distributed node so
    %% `bin/ek-ps` (or any remsh) can rpc:call into it.
    Cookie = "ek-showcase",
    _ = net_kernel:start([showcase, shortnames]),
    _ = erlang:set_cookie(node(), list_to_atom(Cookie)),
    io:format("    distributed node: ~s (cookie ~s)~n", [node(), Cookie]),

    AuditPath = "/var/log/erlkoenig/case_mgmt_audit.jsonl",
    SignKey   = "/var/lib/erlkoenig/case_mgmt_sign.key",
    HmacKey   = "/var/lib/erlkoenig/case_mgmt_hmac.key",
    JournalSock = "/run/erlkoenig/journal.sock",

    %% Generate keys if not already present (so re-runs preserve
    %% the chain across restarts).
    ok = filelib:ensure_dir(AuditPath),
    ok = filelib:ensure_dir(SignKey),
    case file:read_file(SignKey) of
        {ok, _} -> ok;
        _ ->
            {_, Priv} = crypto:generate_key(eddsa, ed25519),
            ok = file:write_file(SignKey, Priv),
            ok = file:write_file(HmacKey, crypto:strong_rand_bytes(32))
    end,

    application:set_env(erlkoenig, audit_path, AuditPath),
    application:set_env(erlkoenig, audit_signing_key, SignKey),
    application:set_env(erlkoenig, audit_hmac_key, HmacKey),
    application:set_env(erlkoenig, journal_local_path, JournalSock),
    test_helper:boot(),
    logger:set_primary_config(level, error),

    {ok, _} = erlkoenig_journal_local:start_link(),

    %% Pre-clean stale rt processes from previous runs.
    os:cmd("pkill -9 -f erlkoenig_rt 2>/dev/null"),
    timer:sleep(800),

    %% case_mgmt — exposes HTTP on :8080
    {ok, CmPid} = erlkoenig:spawn(
        <<"/opt/erlkoenig/rt/demo/case_mgmt">>,
        #{ip => {10, 0, 0, 210},
          name => list_to_binary("case_mgmt-0-agent"),
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
    ok = wait_for_running(CmPid, 15000),

    %% deadline_worker — polls case_mgmt + writes journal entries
    {ok, WorkerPid} = erlkoenig:spawn(
        <<"/opt/erlkoenig/rt/demo/deadline_worker">>,
        #{ip => {10, 0, 0, 211},
          name => list_to_binary("case_mgmt-0-worker"),
          uid => 65534, gid => 65534,
          socket_mounts => [
              #{host => <<"/run/erlkoenig/">>,
                container => <<"/run/erlkoenig/">>,
                read_only => false}
          ],
          env => [{<<"CASE_MGMT_URL">>, <<"http://10.0.0.210:8080">>},
                  {<<"SCAN_INTERVAL_SEC">>, <<"30">>},
                  {<<"DAYS_AHEAD">>, <<"14">>},
                  {<<"JOURNAL_LOCAL_SOCK">>, list_to_binary(JournalSock)}]}),
    ok = wait_for_running(WorkerPid, 15000),

    io:format("~n--------------------------------------------------------------~n"),
    io:format("  case_mgmt:        http://10.0.0.210:8080~n"),
    io:format("  deadline_worker:  polls case_mgmt every 30s~n"),
    io:format("  audit log:        ~s~n", [AuditPath]),
    io:format("  sign pubkey via:  signing_pubkey from BEAM~n"),
    io:format("  hmac key:         ~s~n", [HmacKey]),
    io:format("--------------------------------------------------------------~n~n"),
    io:format("  try it:~n"),
    io:format("    curl http://10.0.0.210:8080/tasks | jq .~n"),
    io:format("    curl http://10.0.0.210:8080/tasks/1 | jq .~n"),
    io:format("    curl http://10.0.0.210:8080/deadlines/upcoming?days=30 | jq .~n~n"),
    io:format("  Ctrl-C to stop the pod, audit-log is preserved.~n~n"),

    %% Wait forever (until SIGINT). Must NOT use `_` — a distributed
    %% handshake from a peer node (e.g. the ek-ps CLI doing net_adm:ping)
    %% would otherwise match the `nodeup` message and exit the pod.
    %% Only an explicit `stop` terminates.
    receive
        stop -> ok
    end,

    catch erlkoenig:stop(CmPid),
    catch erlkoenig:stop(WorkerPid),
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
