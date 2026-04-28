#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 55: operator CLI lifecycle / restart-policy contract.
%%
%% Pins the operator-observable lifecycle contract for the
%% 09_lifecycle scenario, exercised through the real `ek` CLI:
%%
%%   * permanent + sleeper       — must reach running
%%   * transient + clean exit    — must reach a terminal-or-absent state
%%   * transient + crasher       — must show restart_count evidence
%%                                 OR end up failed/quarantined
%%   * temporary + crasher       — must reach terminal AND stop advancing
%%   * ct inspect JSON           — name/state/restart/restart_count/timeline
%%   * manual `ek ct stop`       — must keep a running permanent container
%%                                 from coming back
%%   * `ek down`                 — must leave no active scenario rows
%%
%% Timing-wise this test asserts observable properties only — it does
%% NOT pin exact restart_count values or exact timing windows, so it
%% remains stable under supervisor backoff and quarantine variability.
-mode(compile).

-define(PARENT, <<"ek_cli55">>).
-define(PARENT_CIDR, "10.10.0.1/24").

-define(NAME_PERM,        <<"perm-0-sleeper">>).
-define(NAME_TRANSCLEAN,  <<"transclean-0-hello">>).
-define(NAME_TRANSCRASH,  <<"transcrash-0-boom">>).
-define(NAME_TEMPCRASH,   <<"tempcrash-0-once">>).

-define(ALL_NAMES, [?NAME_PERM, ?NAME_TRANSCLEAN, ?NAME_TRANSCRASH, ?NAME_TEMPCRASH]).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 55: ek lifecycle / restart-policy contract ===~n~n"),
    require_root(),

    Root = test_helper:project_root(),
    Ek = find_ek(Root),

    ensure_installed_daemon(Ek),
    reset_daemon(Ek),
    cleanup_all(Ek),
    ensure_dummy(?PARENT, ?PARENT_CIDR),

    %% Snapshot pre-existing volume orphans before the scenario runs.
    %% The post-run leak audit tolerates this count so only NEW
    %% orphans introduced by this test surface as leaks.
    BaselineOrphans = count_volume_orphans(Ek),

    %% NB: halt/1 inside `try' bypasses the `after' clause (immediate
    %% VM exit), so cleanup must run before we exit. Compute the exit
    %% status here, run cleanup in `after', halt last.
    Status = try
        run_lifecycle_contract(Ek, Root),
        io:format("~n=== Test 55 passed ===~n~n"),
        0
    catch
        Class:Reason:Stack ->
            io:format("~n=== Test 55 FAILED ===~n  ~p:~p~n  ~p~n",
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
%% orphans are tolerated via `--baseline-orphans N'. Non-fatal:
%% prints findings, does not change exit status.
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
%% Returns 0 on parse failure (conservative — leaks are still
%% surfaced; tool-unreachable separately reported by leak_check.sh).
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
%% Scenario
%% ------------------------------------------------------------------

run_lifecycle_contract(Ek, Root) ->
    ScenarioFile = "09_lifecycle.exs",
    Source = scenario_path(Root, ScenarioFile),
    Term = tmp_term_path("09_lifecycle"),

    step("ek dsl compile " ++ ScenarioFile, fun() ->
        expect_ok(run_ek(Ek,
                         "dsl compile " ++ shell_quote(Source) ++
                         " -o " ++ shell_quote(Term)))
    end),

    step("patch " ++ ScenarioFile ++ " for this host", fun() ->
        %% The clean-exit and crasher binaries are scenario-specific
        %% (different demo binaries per pod), so we only patch the
        %% network parent here.
        patch_term(Term, #{parent => ?PARENT})
    end),

    %% `ek up` is expected to return 0 on this scenario: with the
    %% policy-aware `classify_post_up` in dist/ek.escript, a
    %% `:temporary` container that already reached terminal `failed`
    %% state at settle time is reported as completed, not failed.
    %% Earlier `classify_post_up` versions had a too-narrow tolerance
    %% (only `gone` / `stopped`) and returned exit 1 for that case;
    %% we keep a tolerant branch here as defence-in-depth so this
    %% test never flaps on a single timing variant, but the normal
    %% expectation is exit 0.
    step("ek up " ++ ScenarioFile, fun() ->
        case run_ek(Ek, "up " ++ shell_quote(Term)) of
            {0, _} -> ok;
            {1, Out} ->
                case string:find(Out, "tempcrash-0-once") of
                    nomatch ->
                        {error, {unexpected_up_failure_set, Out}};
                    _ ->
                        ok
                end;
            {Status, Out} ->
                {error, {unexpected_up_status, Status, Out}}
        end
    end),

    %% --- (1) permanent + sleeper reaches running -----------------
    step("permanent + sleeper reaches running", fun() ->
        wait_state(Ek, ?NAME_PERM,
                   fun(State, _Row) -> State =:= <<"running">> end,
                   15_000)
    end),

    %% --- (5) ct inspect JSON contract ----------------------------
    step("ct inspect JSON has the contract fields", fun() ->
        Inspect = json_ek(Ek,
                          "--format json ct inspect " ++
                          shell_quote(binary_to_list(?NAME_PERM))),
        assert_lifecycle_inspect_shape(?NAME_PERM, Inspect)
    end),

    %% --- (2) transient + clean exit reaches terminal-or-absent ---
    step("transient + clean exit reaches terminal or absent",
      fun() ->
        wait_terminal_or_gone(Ek, ?NAME_TRANSCLEAN, 15_000)
    end),

    %% --- (3) transient + crasher shows restart_count evidence ----
    %%
    %% Acceptable observable outcomes:
    %%   - state running, restart_count >= 1   (mid-cycle)
    %%   - state restarting, restart_count >= 1
    %%   - state failed, with restart_count >= 1 or quarantined error
    %%   - state stopped, with restart_count >= 1 or quarantined error
    %%
    %% We deliberately do NOT pin an exact count or a specific state.
    step("transient + crasher shows restart evidence", fun() ->
        wait_state(Ek, ?NAME_TRANSCRASH,
                   fun(State, Row) ->
                        Count = num_or_zero(get_json(<<"restart_count">>, Row)),
                        Quarantined = inspect_is_quarantined(Ek, ?NAME_TRANSCRASH),
                        Count >= 1
                        orelse Quarantined
                        orelse State =:= <<"restarting">>
                   end,
                   30_000)
    end),

    %% --- (4) temporary + crasher reaches terminal AND stops ------
    %% advancing restart_count.
    step("temporary + crasher reaches terminal", fun() ->
        wait_terminal_or_gone(Ek, ?NAME_TEMPCRASH, 15_000)
    end),

    step("temporary + crasher does not keep restarting", fun() ->
        Count1 = sample_restart_count(Ek, ?NAME_TEMPCRASH),
        timer:sleep(3_000),
        Count2 = sample_restart_count(Ek, ?NAME_TEMPCRASH),
        case {Count1, Count2} of
            {gone, gone} -> ok;
            {C1, C2} when is_integer(C1), is_integer(C2), C2 =:= C1 -> ok;
            {gone, C2}   -> {error, {temporary_came_back_after_gone, C2}};
            {C1, gone}   -> {error, {temporary_disappeared_after_visible, C1}};
            {C1, C2}     -> {error, {temporary_advanced_restart_count, C1, C2}}
        end
    end),

    %% --- (5 cont.) inspect contract for the other names ----------
    %% Containers may have auto_shutdown'd by now; only inspect those
    %% the daemon still knows about.
    step("ct inspect JSON contract for visible names", fun() ->
        check_inspect_contract_for_visible(Ek,
            [?NAME_TRANSCLEAN, ?NAME_TRANSCRASH, ?NAME_TEMPCRASH])
    end),

    %% --- (6) manual stop on running permanent container ----------
    step("ek ct stop on permanent stops it cleanly", fun() ->
        expect_ok(run_ek(Ek,
                         "ct stop " ++
                         shell_quote(binary_to_list(?NAME_PERM))))
    end),

    step("permanent reaches terminal after manual stop", fun() ->
        wait_terminal_or_gone(Ek, ?NAME_PERM, 10_000)
    end),

    step("permanent stays terminal — does not auto-respawn",
      fun() ->
        State1 = sample_state(Ek, ?NAME_PERM),
        Count1 = sample_restart_count(Ek, ?NAME_PERM),
        timer:sleep(3_000),
        State2 = sample_state(Ek, ?NAME_PERM),
        Count2 = sample_restart_count(Ek, ?NAME_PERM),
        case is_terminal_or_gone(State1)
             andalso is_terminal_or_gone(State2)
             andalso restart_count_steady(Count1, Count2) of
            true -> ok;
            false ->
                {error, {permanent_revived,
                         #{state1 => State1, state2 => State2,
                           count1 => Count1, count2 => Count2}}}
        end
    end),

    %% --- (7) ek down leaves no active scenario rows --------------
    step("ek down " ++ ScenarioFile, fun() ->
        expect_ok(run_ek(Ek, "down " ++ shell_quote(Term)))
    end),

    step("ek down leaves no active scenario rows", fun() ->
        wait_all_terminal_or_gone(Ek, ?ALL_NAMES, 10_000)
    end),

    _ = file:delete(Term),
    ok.

%% ------------------------------------------------------------------
%% Lifecycle inspection helpers
%% ------------------------------------------------------------------

assert_lifecycle_inspect_shape(Name, Inspect) ->
    assert_string_field(<<"name">>, Name, Inspect),
    assert_present(<<"state">>, Inspect),
    assert_string_or_null(<<"state">>, Inspect),
    assert_present(<<"restart">>, Inspect),
    assert_string_or_null(<<"restart">>, Inspect),
    assert_present(<<"restart_count">>, Inspect),
    assert_int_or_null(<<"restart_count">>, Inspect),
    assert_present(<<"timeline">>, Inspect),
    Timeline = get_json(<<"timeline">>, Inspect),
    case Timeline of
        L when is_list(L), length(L) >= 5 -> ok;
        Other -> {error, {timeline_too_short_or_wrong_shape, Other, Inspect}}
    end.

check_inspect_contract_for_visible(_Ek, []) -> ok;
check_inspect_contract_for_visible(Ek, [Name | Rest]) ->
    case run_ek(Ek,
                "--format json ct inspect " ++
                shell_quote(binary_to_list(Name))) of
        {0, Out} ->
            Inspect = decode_json_output(Out),
            case assert_lifecycle_inspect_shape(Name, Inspect) of
                ok -> check_inspect_contract_for_visible(Ek, Rest);
                {error, _} = Err -> Err
            end;
        {3, _Out} ->
            %% Container is gone (auto_shutdown'd or never reached
            %% the running registry). That's acceptable for transient
            %% clean-exit and temporary crasher under :one_for_one
            %% with auto_shutdown=all_significant.
            check_inspect_contract_for_visible(Ek, Rest);
        {Status, Out} ->
            {error, {unexpected_inspect_status, Name, Status, Out}}
    end.

inspect_is_quarantined(Ek, Name) ->
    case run_ek(Ek,
                "--format json ct inspect " ++
                shell_quote(binary_to_list(Name))) of
        {0, Out} ->
            try
                Inspect = decode_json_output(Out),
                case get_json(<<"error">>, Inspect) of
                    Err when is_map(Err) ->
                        get_json(<<"code">>, Err) =:=
                            <<"EK_RUNTIME_BINARY_QUARANTINED">>;
                    _ -> false
                end
            catch _:_ -> false
            end;
        _ -> false
    end.

%% Returns:
%%   integer  — current restart_count
%%   gone     — container is not visible to ek ct inspect
sample_restart_count(Ek, Name) ->
    case run_ek(Ek,
                "--format json ct inspect " ++
                shell_quote(binary_to_list(Name))) of
        {0, Out} ->
            Inspect = decode_json_output(Out),
            num_or_zero(get_json(<<"restart_count">>, Inspect));
        {3, _Out} -> gone;
        _Other -> gone
    end.

%% Returns: binary state, or `gone` if not visible.
sample_state(Ek, Name) ->
    case run_ek(Ek,
                "--format json ct inspect " ++
                shell_quote(binary_to_list(Name))) of
        {0, Out} ->
            Inspect = decode_json_output(Out),
            case get_json(<<"state">>, Inspect) of
                S when is_binary(S) -> S;
                _ -> unknown
            end;
        {3, _Out} -> gone;
        _Other -> gone
    end.

is_terminal_or_gone(gone) -> true;
is_terminal_or_gone(<<"stopped">>) -> true;
is_terminal_or_gone(<<"failed">>) -> true;
is_terminal_or_gone(_) -> false.

restart_count_steady(C1, C1) -> true;
restart_count_steady(_, _) -> false.

num_or_zero(N) when is_integer(N) -> N;
num_or_zero(_) -> 0.

%% ------------------------------------------------------------------
%% Wait helpers
%% ------------------------------------------------------------------

wait_state(Ek, Name, Pred, TimeoutMs) ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMs,
    wait_state_loop(Ek, Name, Pred, Deadline, undefined).

wait_state_loop(Ek, Name, Pred, Deadline, Last) ->
    case lookup_row(Ek, Name) of
        {ok, Row} ->
            State = get_json(<<"state">>, Row),
            case Pred(State, Row) of
                true  -> ok;
                false -> wait_state_again(Ek, Name, Pred, Deadline, {seen, Row})
            end;
        gone ->
            wait_state_again(Ek, Name, Pred, Deadline, {gone, Last})
    end.

wait_state_again(Ek, Name, Pred, Deadline, Last) ->
    case erlang:monotonic_time(millisecond) >= Deadline of
        true -> {error, {timeout_waiting_for_state, Name, Last}};
        false ->
            timer:sleep(300),
            wait_state_loop(Ek, Name, Pred, Deadline, Last)
    end.

wait_terminal_or_gone(Ek, Name, TimeoutMs) ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMs,
    wait_terminal_or_gone_loop(Ek, Name, Deadline).

wait_terminal_or_gone_loop(Ek, Name, Deadline) ->
    case lookup_row(Ek, Name) of
        {ok, Row} ->
            case is_terminal_state(get_json(<<"state">>, Row)) of
                true  -> ok;
                false ->
                    case erlang:monotonic_time(millisecond) >= Deadline of
                        true -> {error, {timeout_waiting_for_terminal, Name, Row}};
                        false ->
                            timer:sleep(300),
                            wait_terminal_or_gone_loop(Ek, Name, Deadline)
                    end
            end;
        gone ->
            ok
    end.

wait_all_terminal_or_gone(Ek, Names, TimeoutMs) ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMs,
    wait_all_terminal_or_gone_loop(Ek, Names, Deadline).

wait_all_terminal_or_gone_loop(Ek, Names, Deadline) ->
    Rows = case catch json_ek(Ek, "--format json ct list") of
        L when is_list(L) -> L;
        _ -> []
    end,
    Active = [N || N <- Names, active_in_rows(N, Rows)],
    case Active of
        [] -> ok;
        _ ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true -> {error, {still_active_after_down, Active, Rows}};
                false ->
                    timer:sleep(300),
                    wait_all_terminal_or_gone_loop(Ek, Names, Deadline)
            end
    end.

is_terminal_state(<<"stopped">>) -> true;
is_terminal_state(<<"failed">>) -> true;
is_terminal_state(_) -> false.

active_in_rows(Name, Rows) ->
    case [R || R <- Rows, get_json(<<"name">>, R) =:= Name] of
        [Row | _] ->
            not is_terminal_state(get_json(<<"state">>, Row));
        [] ->
            false
    end.

%% Returns {ok, Row} or `gone` (container not in ct list).
lookup_row(Ek, Name) ->
    case catch json_ek(Ek, "--format json ct list") of
        Rows when is_list(Rows) ->
            case [R || R <- Rows, get_json(<<"name">>, R) =:= Name] of
                [Row | _] -> {ok, Row};
                [] -> gone
            end;
        _ ->
            gone
    end.

%% ------------------------------------------------------------------
%% Term patching (parent only — binaries are scenario-specific)
%% ------------------------------------------------------------------

patch_term(TermFile, Patch) ->
    {ok, [Config0]} = file:consult(TermFile),
    Host1 = patch_parent(maps:get(host, Config0, #{}), Patch),
    Zones1 = [patch_parent(Z, Patch) || Z <- maps:get(zones, Config0, [])],
    Config1 = Config0#{host => Host1, zones => Zones1},
    ok = file:write_file(TermFile, io_lib:format("~tp.~n", [Config1])),
    ok.

patch_parent(#{network := #{parent := _Old} = Net} = M, #{parent := Parent}) ->
    M#{network => Net#{parent => Parent}};
patch_parent(M, _Patch) ->
    M.

%% ------------------------------------------------------------------
%% CLI helpers (kept structurally identical to 53/54)
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

%% ------------------------------------------------------------------
%% Field assertions
%% ------------------------------------------------------------------

assert_string_field(Key, Expected, Map) ->
    case get_json(Key, Map) of
        Expected -> ok;
        Other -> error({unexpected_json_field, Key, Expected, Other, Map})
    end.

assert_present(Key, Map) ->
    case maps:is_key(Key, Map) of
        true -> ok;
        false -> error({missing_json_field, Key, Map})
    end.

assert_string_or_null(Key, Map) ->
    case get_json(Key, Map) of
        null -> ok;
        S when is_binary(S) -> ok;
        Other -> error({expected_string_or_null, Key, Other, Map})
    end.

assert_int_or_null(Key, Map) ->
    case get_json(Key, Map) of
        null -> ok;
        I when is_integer(I) -> ok;
        Other -> error({expected_integer_or_null, Key, Other, Map})
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
%% Environment setup (kept structurally identical to 53/54)
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
    filename:join("/tmp", "erlkoenig_cli55_" ++ Base ++ ".term").

shell_quote(S) when is_binary(S) ->
    shell_quote(binary_to_list(S));
shell_quote(S) ->
    Escaped = lists:flatten(
                [case C of
                     $' -> "'\\''";
                     Other -> Other
                 end || C <- S]),
    "'" ++ Escaped ++ "'".
