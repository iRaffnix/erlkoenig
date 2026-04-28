#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 53: operator CLI contract smoke suite.
%%
%% Exercises the scenario corpus added under tests/integration/cli_scenarios
%% through the real `ek` CLI:
%%
%%   .exs -> ek dsl compile -> patched .term -> ek config validate
%%        -> ek up -> ek --format json ct list/inspect -> ek down
%%
%% This is intentionally narrower than the full root integration suite. It
%% pins the operator-facing JSON contract for the fastest, least timing-sensitive
%% scenarios first; crash-loop, lifecycle, and volume assertions can extend the
%% same harness.
-mode(compile).

-define(PARENT, <<"ek_cli53">>).
-define(PARENT_CIDR, "10.10.0.1/24").

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 53: ek operator CLI JSON contract ===~n~n"),
    require_root(),

    Root = test_helper:project_root(),
    Ek = find_ek(Root),

    ensure_installed_daemon(Ek),
    reset_daemon(Ek),
    cleanup_all(Ek),
    ensure_dummy(?PARENT, ?PARENT_CIDR),

    %% Snapshot pre-existing volume orphans before the scenario runs.
    %% The post-run leak audit tolerates this count so only NEW
    %% orphans introduced by this test surface as leaks. The count
    %% is captured here, while the daemon is known to be reachable.
    BaselineOrphans = count_volume_orphans(Ek),

    %% NB: halt/1 inside `try' bypasses the `after' clause (immediate
    %% VM exit), so cleanup must run before we exit. Compute the exit
    %% status here, run cleanup in `after', halt last.
    Status = try
        run_happy_scenario(Ek, Root,
                           "01_smoke.exs",
                           [<<"cli-smoke-0-web">>]),

        run_happy_scenario(Ek, Root,
                           "02_names.exs",
                           [<<"edge-case-very-long-pod-name-test-0-"
                              "deeply-nested-container-name">>,
                            <<"p99-0-x1">>]),

        run_config_error_scenario(Ek, Root),

        io:format("~n=== Test 53 passed ===~n~n"),
        0
    catch
        Class:Reason:Stack ->
            io:format("~n=== Test 53 FAILED ===~n  ~p:~p~n  ~p~n",
                      [Class, Reason, lists:sublist(Stack, 5)]),
            1
    after
        cleanup_all(Ek),
        reset_daemon(Ek),
        cleanup_dummy(?PARENT),
        _ = os:cmd("nft delete table inet host 2>/dev/null"),
        _ = os:cmd("nft delete table inet erlkoenig 2>/dev/null"),
        leak_audit(Root, BaselineOrphans)
    end,
    halt(Status).

%% Defence-in-depth leak audit. Reports any unexpected leftover
%% interfaces, parent dummies, nft tables, container cgroups, or
%% volume orphans introduced by this test run. Pre-existing volume
%% orphans (from earlier sessions on the same host) are tolerated
%% via `--baseline-orphans N', counted at scenario start. Non-fatal:
%% prints findings, does not change exit status. Operator can
%% promote to strict mode in run_all.sh once the broader environment
%% is known clean.
leak_audit(Root, BaselineOrphans) ->
    Script = filename:join([Root, "tools", "leak_check.sh"]),
    case filelib:is_regular(Script) of
        false -> ok;
        true ->
            io:format("~n=== leak audit ===~n", []),
            Cmd = "bash " ++ Script ++
                  " report --baseline-orphans " ++
                  integer_to_list(BaselineOrphans) ++
                  " 2>&1",
            Out = os:cmd(Cmd),
            io:format("~ts", [Out])
    end.

%% Count of volume orphans currently visible to `ek vol orphans'.
%% Returns 0 if the call fails or output cannot be parsed — that is
%% conservative (any new orphans introduced by this run will then
%% surface, and the audit-failure indicator from leak_check.sh
%% covers tool-unreachable cases at the back end).
count_volume_orphans(Ek) ->
    case catch json_ek(Ek, "--format json vol orphans") of
        L when is_list(L) -> length(L);
        _ -> 0
    end.

%% Local step/2 — mirrors `test_helper:step/2's' surface but raises an
%% Erlang error on failure instead of `halt(1)'. The outer try/after
%% in main/1 then reaches its cleanup branch (cleanup_all, leak_audit)
%% even when a step fails. Without this, `test_helper:step' would call
%% `halt(1)' on the first bad assertion and bypass cleanup entirely,
%% leaving leftover dummies, nft tables, and cgroups on the host.
step(Name, Fun) ->
    io:format("[....] ~ts", [Name]),
    try Fun() of
        ok ->
            io:format("\r[\e[32mOK\e[0m  ] ~ts~n", [Name]),
            ok;
        {ok, Val} ->
            io:format("\r[\e[32mOK\e[0m  ] ~ts~n", [Name]),
            Val;
        {error, Reason} ->
            io:format("\r[\e[31mFAIL\e[0m] ~ts: ~p~n", [Name, Reason]),
            error({step_failed, Name, Reason})
    catch
        Class:Reason:Stack ->
            io:format("\r[\e[31mFAIL\e[0m] ~ts~n  ~p:~p~n  ~p~n",
                      [Name, Class, Reason, lists:sublist(Stack, 5)]),
            error({step_crashed, Name, Class, Reason})
    end.

%% ------------------------------------------------------------------
%% Scenarios
%% ------------------------------------------------------------------

run_happy_scenario(Ek, Root, ScenarioFile, ExpectedNames) ->
    Base = filename:rootname(filename:basename(ScenarioFile)),
    Source = scenario_path(Root, ScenarioFile),
    Term = tmp_term_path(Base),

    step("ek dsl compile " ++ ScenarioFile, fun() ->
        expect_ok(run_ek(Ek,
                         "dsl compile " ++ shell_quote(Source) ++
                         " -o " ++ shell_quote(Term)))
    end),

    step("patch " ++ ScenarioFile ++ " for this host", fun() ->
        patch_term(Term, #{binary => demo("echo_server"),
                           parent => ?PARENT})
    end),

    step("ek config validate " ++ ScenarioFile, fun() ->
        expect_ok(run_ek(Ek,
                         "config validate " ++ shell_quote(Term)))
    end),

    step("ek up " ++ ScenarioFile, fun() ->
        expect_ok(run_ek(Ek, "up " ++ shell_quote(Term)))
    end),

    Rows = step("ek --format json ct list includes expected rows",
      fun() ->
        wait_ct_list(Ek, ExpectedNames, 15_000)
    end),

    step("ct list JSON has stable summary fields", fun() ->
        lists:foreach(fun(Name) ->
            Row = require_row(Name, Rows),
            assert_string_field(<<"name">>, Name, Row),
            assert_string_field(<<"state">>, <<"running">>, Row),
            assert_string_field(<<"zone">>, <<"demo">>, Row),
            assert_integer_field(<<"restart_count">>, Row),
            assert_present(<<"ip">>, Row)
        end, ExpectedNames),
        ok
    end),

    lists:foreach(fun(Name) ->
        step("ek --format json ct inspect " ++ binary_to_list(Name),
          fun() ->
            Inspect = json_ek(Ek,
                              "--format json ct inspect " ++
                              shell_quote(binary_to_list(Name))),
            assert_string_field(<<"name">>, Name, Inspect),
            assert_string_field(<<"state">>, <<"running">>, Inspect),
            assert_string_field(<<"zone">>, <<"demo">>, Inspect),
            assert_integer_field(<<"restart_count">>, Inspect),
            assert_present(<<"net_info">>, Inspect),
            assert_present(<<"timeline">>, Inspect),
            Timeline = get_json(<<"timeline">>, Inspect),
            true = is_list(Timeline),
            true = length(Timeline) >= 5,
            ok
        end)
    end, ExpectedNames),

    step("ek down " ++ ScenarioFile, fun() ->
        expect_ok(run_ek(Ek, "down " ++ shell_quote(Term))),
        wait_terminal_or_absent(Ek, ExpectedNames, 10_000)
    end),

    _ = file:delete(Term),
    ok.

run_config_error_scenario(Ek, Root) ->
    ScenarioFile = "06_config_errors.exs",
    Source = scenario_path(Root, ScenarioFile),
    Term = tmp_term_path("06_config_errors"),
    MissingName = <<"ghost-0-missing">>,

    step("ek dsl compile " ++ ScenarioFile, fun() ->
        expect_ok(run_ek(Ek,
                         "dsl compile " ++ shell_quote(Source) ++
                         " -o " ++ shell_quote(Term)))
    end),

    step("patch " ++ ScenarioFile ++ " parent only", fun() ->
        %% Keep the intentionally missing binary path. Only the dummy parent
        %% changes so the config reaches the spawn-time error.
        patch_term(Term, #{parent => ?PARENT})
    end),

    step("ek config validate accepts opaque binary path", fun() ->
        expect_ok(run_ek(Ek,
                         "config validate " ++ shell_quote(Term)))
    end),

    step("ek up fails loud for missing binary", fun() ->
        {Status, Out} = run_ek(Ek, "up " ++ shell_quote(Term)),
        case Status of
            0 -> {error, {up_unexpectedly_succeeded, Out}};
            _ ->
                case string:find(Out, "failed") of
                    nomatch -> {error, {missing_failure_word, Out}};
                    _ -> ok
                end
        end
    end),

    step("failed container inspect is explicit", fun() ->
        case run_ek(Ek,
                    "--format json ct inspect " ++
                    shell_quote(binary_to_list(MissingName))) of
            {0, InspectOut} ->
                Inspect = decode_json_output(InspectOut),
                assert_string_field(<<"name">>, MissingName, Inspect),
                State = get_json(<<"state">>, Inspect),
                case State of
                    <<"failed">> -> ok;
                    <<"stopped">> -> ok;
                    <<"creating">> -> ok;
                    Other -> {error, {unexpected_error_state, Other, Inspect}}
                end;
            {Status, Out} when Status =:= 3; Status =:= 1 ->
                case string:find(string:lowercase(Out), "not found") of
                    nomatch -> {error, {inspect_failed_without_not_found, Status, Out}};
                    _ -> ok
                end
        end
    end),

    step("ek down " ++ ScenarioFile, fun() ->
        _ = run_ek(Ek, "down " ++ shell_quote(Term)),
        wait_terminal_or_absent(Ek, [MissingName], 10_000)
    end),

    _ = file:delete(Term),
    ok.

%% ------------------------------------------------------------------
%% CLI helpers
%% ------------------------------------------------------------------

run_ek(Ek, Args) ->
    Cmd = shell_quote(Ek) ++ " " ++ Args,
    run_cmd(Cmd).

json_ek(Ek, Args) ->
    {0, Out} = run_ek(Ek, Args),
    decode_json_output(Out).

run_cmd(Cmd) ->
    Marker = "__EK_STATUS__",
    Full = Cmd ++ " 2>&1; STATUS=$?; printf '\\n" ++ Marker ++ "%s__\\n' \"$STATUS\"",
    Out0 = os:cmd(Full),
    parse_marked_status(Out0, Marker).

parse_marked_status(Out0, Marker) ->
    case string:split(Out0, Marker, trailing) of
        [Out, Tail0] ->
            Tail = string:trim(Tail0),
            case string:split(Tail, "__", leading) of
                [StatusS, _Rest] ->
                    case catch list_to_integer(StatusS) of
                        I when is_integer(I) -> {I, trim_status_newline(Out)};
                        _ -> {255, Out0}
                    end;
                _ ->
                    {255, Out0}
            end;
        _ ->
            {255, Out0}
    end.

trim_status_newline(Out) ->
    case lists:reverse(Out) of
        [$\n | Rest] -> lists:reverse(Rest);
        _ -> Out
    end.

expect_ok({0, _Out}) -> ok;
expect_ok({Status, Out}) -> {error, {unexpected_exit_status, Status, Out}}.

decode_json_output(Out) ->
    Lines0 = string:split(Out, "\n", all),
    Lines = [string:trim(L) || L <- Lines0, string:trim(L) =/= ""],
    case [L || L <- lists:reverse(Lines), is_json_line(L)] of
        [JsonLine | _] -> json:decode(list_to_binary(JsonLine));
        [] -> error({json_not_found, Out})
    end.

is_json_line([$[ | _]) -> true;
is_json_line([${ | _]) -> true;
is_json_line(_) -> false.

wait_ct_list(Ek, ExpectedNames, TimeoutMs) ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMs,
    wait_ct_list(Ek, ExpectedNames, Deadline, undefined).

wait_ct_list(Ek, ExpectedNames, Deadline, Last) ->
    case catch json_ek(Ek, "--format json ct list") of
        Rows when is_list(Rows) ->
            case all_running(ExpectedNames, Rows) of
                true -> {ok, Rows};
                false -> maybe_wait_or_fail(Ek, ExpectedNames,
                                            Deadline, Rows)
            end;
        Other ->
            maybe_wait_or_fail(Ek, ExpectedNames, Deadline,
                                {decode_failed, Other, Last})
    end.

maybe_wait_or_fail(Ek, ExpectedNames, Deadline, Last) ->
    case erlang:monotonic_time(millisecond) >= Deadline of
        true -> {error, {timeout_waiting_for_ct_list, ExpectedNames, Last}};
        false ->
            timer:sleep(300),
            wait_ct_list(Ek, ExpectedNames, Deadline, Last)
    end.

all_running(ExpectedNames, Rows) ->
    lists:all(fun(Name) ->
        case find_row(Name, Rows) of
            {ok, Row} -> get_json(<<"state">>, Row) =:= <<"running">>;
            error -> false
        end
    end, ExpectedNames).

wait_terminal_or_absent(Ek, Names, TimeoutMs) ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMs,
    wait_terminal_or_absent_loop(Ek, Names, Deadline).

wait_terminal_or_absent_loop(Ek, Names, Deadline) ->
    Rows = case catch json_ek(Ek, "--format json ct list") of
        L when is_list(L) -> L;
        _ -> []
    end,
    Active = [N || N <- Names, active_row(N, Rows)],
    case Active of
        [] -> ok;
        _ ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true -> {error, {containers_still_active, Active, Rows}};
                false -> timer:sleep(300),
                         wait_terminal_or_absent_loop(Ek, Names, Deadline)
            end
    end.

active_row(Name, Rows) ->
    case find_row(Name, Rows) of
        error ->
            false;
        {ok, Row} ->
            case get_json(<<"state">>, Row) of
                <<"stopped">> -> false;
                <<"failed">> -> false;
                _ -> true
            end
    end.

%% ------------------------------------------------------------------
%% Term patching
%% ------------------------------------------------------------------

patch_term(TermFile, Patch) ->
    {ok, [Config0]} = file:consult(TermFile),
    Pods0 = maps:get(pods, Config0, []),
    Pods1 = [patch_pod(P, Patch) || P <- Pods0],
    Host1 = patch_parent(maps:get(host, Config0, #{}), Patch),
    Zones1 = [patch_parent(Z, Patch) || Z <- maps:get(zones, Config0, [])],
    Config1 = Config0#{pods => Pods1, host => Host1, zones => Zones1},
    ok = file:write_file(TermFile, io_lib:format("~tp.~n", [Config1])),
    ok.

patch_pod(Pod, Patch) ->
    Containers0 = maps:get(containers, Pod, []),
    Containers1 = [patch_container(C, Patch) || C <- Containers0],
    Pod#{containers => Containers1}.

patch_container(C, #{binary := Bin}) ->
    C#{binary => Bin};
patch_container(C, _Patch) ->
    C.

patch_parent(#{network := #{parent := _Old} = Net} = M, #{parent := Parent}) ->
    M#{network => Net#{parent => Parent}};
patch_parent(M, _Patch) ->
    M.

%% ------------------------------------------------------------------
%% Assertions
%% ------------------------------------------------------------------

require_row(Name, Rows) ->
    case find_row(Name, Rows) of
        {ok, Row} -> Row;
        error -> error({row_not_found, Name, Rows})
    end.

find_row(Name, Rows) ->
    case [R || R <- Rows, get_json(<<"name">>, R) =:= Name] of
        [R | _] -> {ok, R};
        [] -> error
    end.

assert_string_field(Key, Expected, Map) ->
    case get_json(Key, Map) of
        Expected -> ok;
        Other -> error({unexpected_json_field, Key, Expected, Other, Map})
    end.

assert_integer_field(Key, Map) ->
    case get_json(Key, Map) of
        I when is_integer(I), I >= 0 -> ok;
        Other -> error({expected_non_neg_integer, Key, Other, Map})
    end.

assert_present(Key, Map) ->
    case get_json(Key, Map) of
        undefined -> error({missing_json_field, Key, Map});
        _ -> ok
    end.

get_json(Key, Map) when is_binary(Key), is_map(Map) ->
    case maps:find(Key, Map) of
        {ok, V} -> V;
        error ->
            ListKey = binary_to_list(Key),
            case maps:find(ListKey, Map) of
                {ok, V} -> V;
                error -> maps:get(binary_to_atom(Key, utf8), Map, undefined)
            end
    end.

%% ------------------------------------------------------------------
%% Environment setup
%% ------------------------------------------------------------------

require_root() ->
    case string:trim(os:cmd("id -u")) of
        "0" -> ok;
        _ -> io:format("ERROR: must run as root~n"), halt(1)
    end.

ensure_dummy(Name, Cidr) ->
    cleanup_dummy(Name),
    _ = os:cmd("ip link add " ++ binary_to_list(Name) ++ " type dummy"),
    _ = os:cmd("ip addr add " ++ Cidr ++ " dev " ++ binary_to_list(Name)),
    _ = os:cmd("ip link set " ++ binary_to_list(Name) ++ " up"),
    ok.

cleanup_dummy(Name) ->
    _ = os:cmd("ip link del " ++ binary_to_list(Name) ++ " 2>/dev/null"),
    _ = os:cmd("ip link del h." ++ binary_to_list(Name) ++ " 2>/dev/null"),
    ok.

ensure_installed_daemon(Ek) ->
    case run_ek(Ek, "node ping") of
        {0, Out} ->
            case string:find(Out, "pong") of
                nomatch -> {error, {unexpected_ping_output, Out}};
                _ -> ok
            end;
        {Status, Out} ->
            error({daemon_not_reachable, Status, Out})
    end.

reset_daemon(Ek) ->
    _ = os:cmd("systemctl restart erlkoenig 2>&1"),
    wait_ping(Ek, 15_000).

wait_ping(Ek, TimeoutMs) ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMs,
    wait_ping_loop(Ek, Deadline).

wait_ping_loop(Ek, Deadline) ->
    case run_ek(Ek, "node ping") of
        {0, Out} ->
            case string:find(Out, "pong") of
                nomatch -> wait_ping_again(Ek, Deadline, Out);
                _ -> ok
            end;
        {_Status, Out} ->
            wait_ping_again(Ek, Deadline, Out)
    end.

wait_ping_again(Ek, Deadline, Last) ->
    case erlang:monotonic_time(millisecond) >= Deadline of
        true -> error({daemon_not_reachable_after_restart, Last});
        false ->
            timer:sleep(500),
            wait_ping_loop(Ek, Deadline)
    end.

cleanup_all(Ek) ->
    _ = run_ek(Ek, "down --all"),
    timer:sleep(500),
    _ = os:cmd("for l in $(ip -o link show | awk -F': ' '/ipv\\./ {print $2}'); do "
               "ip link del $l 2>/dev/null; done"),
    ok.

find_ek(Root) ->
    Candidates = [
        "/opt/erlkoenig/bin/ek",
        "/opt/erlkoenig/release/bin/ek",
        filename:join(Root, "dist/ek")
    ],
    case [P || P <- Candidates, filelib:is_regular(P)] of
        [P | _] -> P;
        [] -> error(ek_binary_not_found)
    end.

scenario_path(Root, File) ->
    filename:join([Root, "tests", "integration", "cli_scenarios", File]).

tmp_term_path(Base) ->
    filename:join("/tmp", "erlkoenig_cli53_" ++ Base ++ ".term").

demo(Name) ->
    list_to_binary("/opt/erlkoenig/rt/demo/test-erlkoenig-" ++ Name).

shell_quote(S) when is_binary(S) ->
    shell_quote(binary_to_list(S));
shell_quote(S) ->
    Escaped = lists:flatten(
                [case C of
                     $' -> "'\\''";
                     Other -> Other
                 end || C <- S]),
    "'" ++ Escaped ++ "'".
