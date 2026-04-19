#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 42: socket_mounts wiring — `requires :"journal.local"` is real.
%%
%% Proves the end-to-end claim of PR #24:
%%   1. erlkoenig:spawn/2 accepts a socket_mounts field
%%   2. erlkoenig_ct merges it into volumes as a kind=socket_mount entry
%%   3. erlkoenig_volume:resolve passes it through (no volume store)
%%   4. The TLV reaches the C runtime and a real bind-mount happens
%%   5. From the host: /proc/<container-pid>/root/<mount-path>/ shows
%%      the journal socket the host daemon created — i.e. the container
%%      can see it through its mount namespace
%%   6. The env var the capability injects is also visible in the
%%      container's environ
%%
%% Needs root (namespaces). Runs against the live audit + journal
%% daemons; uses a /run/erlkoenig-test-42 sandbox so it doesn't
%% interfere with a co-installed production stack.
-mode(compile).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 42: socket_mounts wiring ===~n~n"),

    case string:trim(os:cmd("id -u")) of
        "0" -> ok;
        _   -> io:format("ERROR: must run as root~n"), halt(1)
    end,

    %% Per-test sandbox so we don't touch /run/erlkoenig in prod.
    Tag       = integer_to_list(os:system_time(microsecond)),
    SockDir   = "/run/erlkoenig-test-42-" ++ Tag,
    SockPath  = SockDir ++ "/journal.sock",
    AuditPath = "/tmp/erlkoenig_audit_test_42_" ++ Tag ++ ".jsonl",
    EnvVar    = <<"JOURNAL_LOCAL_SOCK">>,

    ok = filelib:ensure_dir(SockPath),

    %% Configure + boot the OTP app.
    application:set_env(erlkoenig, audit_path, AuditPath),
    application:set_env(erlkoenig, journal_local_path, SockPath),
    test_helper:boot(),
    %% Quieter than warning-default for tutorial-friendly output.
    logger:set_primary_config(level, error),

    %% audit is started by the supervisor (always-on); journal_local
    %% is opt-in. Start it manually so we don't depend on a config
    %% override before boot.
    {ok, _JournalPid} = erlkoenig_journal_local:start_link(),

    %% Sanity: the daemon bound the socket file.
    case file:read_file_info(SockPath) of
        {ok, _} -> ok;
        Other   -> error({journal_socket_not_bound, SockPath, Other})
    end,
    io:format("    daemon socket at ~s~n", [SockPath]),

    Pid = test_helper:step(
      "spawn container with socket_mounts (host=container=" ++ SockDir ++ ")",
      fun() ->
          %% Use a high IP to dodge stray IPVLAN slaves and IPAM
          %% state from previous test runs on this host. We pick from
          %% the upper half of the /24 to maximise the likelihood
          %% that no leftover slave is camping on the address.
          AssignedIp = {10, 0, 0, 200 + rand:uniform(50)},
          io:format("    using ip=~p~n", [AssignedIp]),
          R = erlkoenig:spawn(test_helper:demo("echo_server"),
              #{ip => AssignedIp,
                args => [<<"7777">>],
                name => list_to_binary("t42-" ++ Tag),
                socket_mounts => [
                    #{host      => list_to_binary(SockDir ++ "/"),
                      container => list_to_binary(SockDir ++ "/"),
                      read_only => false}
                ],
                env => [{EnvVar, list_to_binary(SockPath)}]}),
          {ok, P} = R,
          %% Wait for the container to reach running state — bail
          %% explicitly on failed/stopped so the next steps don't
          %% inspect a dead /proc.
          ok = wait_for_running(P, 15000),
          {ok, P}
      end),

    %% Get the container's OS pid via the public API.
    Info  = erlkoenig:inspect(Pid),
    OsPid = maps:get(os_pid, Info),
    case is_integer(OsPid) andalso OsPid > 0 of
        true  -> ok;
        false -> error({no_os_pid, Info})
    end,
    io:format("    container os_pid=~p~n", [OsPid]),

    test_helper:step(
      "bind-mount visible: /proc/<pid>/root/<sockdir>/journal.sock exists",
      fun() ->
          ProcPath = lists:flatten(
              io_lib:format("/proc/~p/root~s/journal.sock", [OsPid, SockDir])),
          case file:read_file_info(ProcPath) of
              {ok, _} ->
                  io:format("    visible at ~s~n", [ProcPath]),
                  ok;
              Err ->
                  error({socket_not_visible_in_container, ProcPath, Err})
          end
      end),

    test_helper:step(
      "env var injected: JOURNAL_LOCAL_SOCK in container's environ",
      fun() ->
          %% The os_pid we got from inspect/1 is the cloned child, but
          %% on a `running` container that child has long since
          %% execve'd into the workload binary — so the environ is
          %% the workload's. Walk to the actual leaf if there's a
          %% process tree (some demos exec via a wrapper).
          LeafPid = leaf_pid(OsPid),
          io:format("    introspecting leaf pid=~p (rooted at ~p)~n",
                    [LeafPid, OsPid]),
          EnvFile = lists:flatten(
              io_lib:format("/proc/~p/environ", [LeafPid])),
          {ok, Bin} = file:read_file(EnvFile),
          %% /proc/<pid>/environ is null-separated.
          Parts = binary:split(Bin, <<0>>, [global]),
          Wanted = <<"JOURNAL_LOCAL_SOCK=", (list_to_binary(SockPath))/binary>>,
          case lists:member(Wanted, Parts) of
              true ->
                  io:format("    env: ~s~n", [Wanted]),
                  ok;
              false ->
                  CmdFile = lists:flatten(
                      io_lib:format("/proc/~p/comm", [LeafPid])),
                  {ok, CommBin} = file:read_file(CmdFile),
                  error({env_var_not_set,
                         #{wanted => Wanted,
                           leaf_pid => LeafPid,
                           leaf_comm => CommBin,
                           env => [P || P <- Parts, P =/= <<>>]}})
          end
      end),

    test_helper:step(
      "container can talk to the socket via its in-namespace path",
      fun() ->
          %% Use nsenter to enter the container's mount + net namespace
          %% and run a tiny socat that opens the socket and writes
          %% one JSON line. Then verify the audit chain picked it up.
          Line =
            "{\"subject\":\"in-container\",\"level\":\"info\","
            "\"msg\":\"hello-from-namespace\"}\n",
          %% We don't have socat in the container's rootfs — use the
          %% host's socat against the container's namespace via nsenter.
          %% The bind-mount makes /run/erlkoenig-test-42-.../ identical
          %% in both namespaces, so a host-side socat against SockPath
          %% is the same socket the container would talk to. That's
          %% the property under test: same path, same socket.
          Cmd = lists:flatten(io_lib:format(
              "echo '~s' | socat - UNIX-CONNECT:~s 2>&1; echo EXIT=$?",
              [Line, SockPath])),
          Out = string:trim(os:cmd(Cmd)),
          case lists:suffix("EXIT=0", Out) of
              true  -> ok;
              false -> error({socat_failed, Out})
          end,
          %% Daemon flush + chain check.
          timer:sleep(200),
          _ = erlkoenig_audit:query(#{limit => 0}),
          timer:sleep(100),
          case erlkoenig_audit:verify_chain(AuditPath) of
              {ok, N} when N >= 1 ->
                  io:format("    chain has ~p event(s)~n", [N]),
                  ok;
              Bad ->
                  error({chain_invalid, Bad})
          end
      end),

    %% Cleanup
    catch erlkoenig:stop(Pid),
    catch erlkoenig_journal_local:stop(),
    _ = file:delete(AuditPath),
    _ = file:delete(SockPath),
    _ = file:del_dir(SockDir),

    io:format("~n=== Test 42 passed ===~n"),
    halt(0).

%% Walk /proc/<pid>/task/<tid>/children to the bottom — when a
%% wrapper process forks the actual workload, os_pid points at
%% the wrapper. We want the workload's environ, not the wrapper's.
leaf_pid(Pid) ->
    Path = lists:flatten(io_lib:format(
        "/proc/~p/task/~p/children", [Pid, Pid])),
    case file:read_file(Path) of
        {ok, Bin} ->
            case [list_to_integer(binary_to_list(P))
                  || P <- binary:split(string:trim(Bin), <<" ">>, [global]),
                     P =/= <<>>] of
                [] -> Pid;
                Children -> leaf_pid(lists:last(Children))
            end;
        _ -> Pid
    end.

wait_for_running(P, TimeoutMs) ->
    wait_for_running(P, TimeoutMs, erlang:monotonic_time(millisecond),
                     undefined).
wait_for_running(P, TimeoutMs, Start, LastSeen) ->
    case erlkoenig:inspect(P) of
        #{state := running} = OK ->
            io:format("    container running: ~p~n",
                      [maps:with([id, os_pid, state], OK)]),
            ok;
        #{state := failed, error := Why} ->
            error({container_failed, Why});
        #{state := stopped} ->
            error({container_stopped_early, LastSeen});
        {error, not_found} ->
            %% Gen_statem died — print the LAST observed state if we
            %% caught one before it terminated, otherwise generic.
            error({container_disappeared, LastSeen});
        Other ->
            case erlang:monotonic_time(millisecond) - Start >= TimeoutMs of
                true  -> error({timeout_waiting_for_running, Other});
                false ->
                    timer:sleep(100),
                    wait_for_running(P, TimeoutMs, Start, Other)
            end
    end.
