#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 32: E2E DSL pipeline for the edge primitives.
%%
%% Previous tests (31 for conn_limit, 29 for dns.allowlist) spawned
%% containers with hand-rolled Erlang-side opts. That proves the
%% runtime side but bypasses the whole DSL compile path:
%%
%%     .exs  →  Erlkoenig.Stack macro expansion  →  term
%%          →  erlkoenig_config:parse  →  load
%%          →  container spawn  →  actual kernel state
%%
%% Any refactor in the macros (like today's `conn_limit` Glasbox
%% move) could silently break the compile path without failing the
%% earlier tests. This test exercises the full chain end-to-end:
%%
%%   1. Compile examples/dsl_e2e_edge.exs via `mix run` (same
%%      pattern as test 15) — catches DSL macro regressions.
%%   2. Patch the placeholder binary path to the real echo_server.
%%   3. Load via erlkoenig_config:load/1 — catches term-shape
%%      regressions.
%%   4. Wait for the container to reach `running`.
%%   5. Assert `erlkoenig_dns_filter` knows the allowlist for the
%%      container's IP — proves `requires :"dns.allowlist"` flowed
%%      through.
%%   6. Assert the container netns shows `ct count over 7 … drop` —
%%      proves chain-level `conn_limit per_ip: 7` flowed through.
%%
%% Root required.
-mode(compile).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 32: E2E DSL pipeline (dns.allowlist + conn_limit) ===~n~n"),

    case string:trim(os:cmd("id -u")) of
        "0" -> ok;
        _   -> io:format("ERROR: must run as root~n"), halt(1)
    end,

    test_helper:boot(),
    logger:set_primary_config(level, error),

    Root     = test_helper:project_root(),
    Example  = filename:join(Root, "examples/dsl_e2e_edge.exs"),
    TermFile = "/tmp/erlkoenig_integration_32.term",
    DemoBin  = binary_to_list(test_helper:demo("echo_server")),

    test_helper:step(
      "mix compile .exs -> .term (full DSL macro expansion)",
      fun() ->
          DslDir  = filename:join(Root, "dsl"),
          Snippet = io_lib:format(
                      "[{mod, _} | _] = Code.compile_file(~p); "
                      "mod.write!(~p)",
                      [Example, TermFile]),
          %% Don't --no-compile: this test MUST re-expand the DSL
          %% from current source so macro refactors get caught.
          %% Uses --no-deps-check so an isolated run doesn't hit
          %% the network for deps.get.
          Cmd = "cd " ++ DslDir ++
                " && MIX_ENV=test mix run --no-deps-check -e " ++
                shell_quote(lists:flatten(Snippet)) ++ " 2>&1",
          Output = os:cmd(Cmd),
          case filelib:is_regular(TermFile) of
              true ->
                  io:format("    term file: ~s (~p bytes)~n",
                            [TermFile, filelib:file_size(TermFile)]),
                  ok;
              false -> {error, {term_not_created, Output}}
          end
      end),

    test_helper:step(
      "parse term + patch binary path to real echo_server",
      fun() ->
          {ok, Config} = erlkoenig_config:parse(TermFile),
          Pods = maps:get(pods, Config, []),
          BinPath = list_to_binary(DemoBin),
          PatchedPods = [patch_pod_binaries(P, BinPath) || P <- Pods],
          Patched = Config#{pods => PatchedPods},
          Formatted = io_lib:format("~tp.~n", [Patched]),
          ok = file:write_file(TermFile, Formatted),
          ok
      end),

    test_helper:step(
      "sanity: conn_limit survived DSL expansion as chain rule",
      fun() ->
          {ok, Config} = erlkoenig_config:parse(TermFile),
          [Pod | _] = maps:get(pods, Config),
          [Ct | _]  = maps:get(containers, Pod),
          Nft = maps:get(nft, Ct, undefined),
          Chains = case Nft of
              undefined -> [];
              #{chains := C} -> C
          end,
          %% Find a rule shaped like {connlimit_drop, #{max := 7}}
          %% anywhere across chain rule lists.
          HasConnLimit = lists:any(
              fun(Chain) ->
                  Rules = maps:get(rules, Chain, []),
                  lists:any(
                    fun({connlimit_drop, #{max := 7}}) -> true;
                       (_) -> false
                    end, Rules)
              end, Chains),
          case HasConnLimit of
              true  -> ok;
              false -> {error, {connlimit_rule_missing_from_term,
                                 Chains}}
          end
      end),

    test_helper:step(
      "sanity: dns_allowlist survived DSL expansion",
      fun() ->
          {ok, Config} = erlkoenig_config:parse(TermFile),
          [Pod | _] = maps:get(pods, Config),
          [Ct | _]  = maps:get(containers, Pod),
          case maps:get(dns_allowlist, Ct, undefined) of
              undefined -> {error, dns_allowlist_missing_from_term};
              Hosts when is_list(Hosts), Hosts =/= [] ->
                  io:format("    hosts: ~p~n", [Hosts]),
                  ok;
              Other -> {error, {unexpected_shape, Other}}
          end
      end),

    CtPid = test_helper:step(
      "load term → container spawns & reaches `running`",
      fun() ->
          {ok, Loaded} = erlkoenig_config:load(TermFile),
          case Loaded of
              [{_Name, Pid} | _] when is_pid(Pid) ->
                  ok = wait_running(Pid, 10_000),
                  {ok, Pid};
              [] ->
                  {error, no_containers_spawned};
              Other ->
                  {error, {unexpected_load_return, Other}}
          end
      end),

    CtIp = test_helper:step(
      "discover container IP + os_pid",
      fun() ->
          Info = erlkoenig:inspect(CtPid),
          OsPid = maps:get(os_pid, Info),
          NetInfo = maps:get(net_info, Info),
          Ip = maps:get(ip, NetInfo),
          io:format("    os_pid=~p ip=~p~n", [OsPid, Ip]),
          put(os_pid, OsPid),
          {ok, Ip}
      end),

    test_helper:step(
      "dns_filter has allowlist registered for container IP "
      "(proves `requires :\"dns.allowlist\"` flowed through DSL)",
      fun() ->
          case erlkoenig_dns_filter:check(CtIp, <<"api.example.com">>) of
              allow -> ok;
              Other -> {error, {expected_allow_for_exact, Other}}
          end
      end),

    test_helper:step(
      "dns_filter wildcard pattern works too",
      fun() ->
          case erlkoenig_dns_filter:check(CtIp, <<"foo.test.invalid">>) of
              allow -> ok;
              Other -> {error, {expected_allow_for_wildcard, Other}}
          end
      end),

    test_helper:step(
      "dns_filter denies names outside the allowlist",
      fun() ->
          case erlkoenig_dns_filter:check(CtIp, <<"evil.example.org">>) of
              {deny, not_in_allowlist} -> ok;
              Other -> {error, {expected_deny, Other}}
          end
      end),

    test_helper:step(
      "container netns has `ct count over 7 … drop` rule "
      "(proves chain-level `conn_limit per_ip: 7` flowed through DSL)",
      fun() ->
          OsPid = get(os_pid),
          Out = os:cmd("nsenter --target " ++ integer_to_list(OsPid) ++
                       " --net nft list ruleset 2>&1"),
          case re:run(Out, "ct count over 7.*drop", [{capture, none}]) of
              match -> ok;
              _ -> {error, {rule_not_found, Out}}
          end
      end),

    test_helper:step(
      "cleanup: stop container + unregister filter",
      fun() ->
          ok = erlkoenig:stop(CtPid),
          timer:sleep(300),
          case erlkoenig_dns_filter:check(CtIp, <<"api.example.com">>) of
              no_filter -> ok;
              Other -> {error, {filter_not_unregistered, Other}}
          end
      end),

    _ = file:delete(TermFile),
    io:format("~n=== Test 32 passed ===~n~n"),
    halt(0).

%% --- helpers -----------------------------------------------------

patch_pod_binaries(Pod, BinPath) ->
    Containers = maps:get(containers, Pod, []),
    Patched = [C#{binary => BinPath} || C <- Containers],
    Pod#{containers => Patched}.

shell_quote(S) ->
    Escaped = lists:flatten(
                [case C of
                     $' -> "'\\''";
                     Other -> Other
                 end || C <- S]),
    "'" ++ Escaped ++ "'".

wait_running(Pid, TimeoutMs) ->
    wait_running(Pid, TimeoutMs, erlang:monotonic_time(millisecond)).
wait_running(Pid, TimeoutMs, Start) ->
    case erlkoenig:inspect(Pid) of
        #{state := running} -> ok;
        #{state := failed, error := Why} ->
            error({container_failed, Why});
        {error, not_found} ->
            error({container_disappeared, Pid});
        _ ->
            case erlang:monotonic_time(millisecond) - Start >= TimeoutMs of
                true  -> error(timeout_waiting_for_running);
                false ->
                    timer:sleep(100),
                    wait_running(Pid, TimeoutMs, Start)
            end
    end.
