#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 54: operator CLI volume contract.
%%
%% Pins the operator-facing JSON and behavioural contracts for the
%% `ek vol' command surface against the 05_volumes scenario:
%%
%%   * vol list             — both global and --container <name>
%%   * vol inspect          — by UUID and by persist name
%%   * vol set-quota        — round-trip changes via inspect
%%   * vol orphans          — empty under steady state
%%   * vol gc-orphans       — dry-run + confirm deletes synthetic orphan
%%   * ephemeral cleanup    — gone after `ek down'
%%   * persistent reattach  — same UUID after `ek down' + `ek up'
%%
%% Mirrors the helper layout of 53_cli_operator_contract.escript so the
%% two suites can share patterns without sharing code yet.
-mode(compile).

-define(PARENT, <<"ek_cli54">>).
-define(PARENT_CIDR, "10.10.0.1/24").
-define(POD_CT, <<"store-0-data">>).
-define(PERSIST_PRIMARY, <<"primary">>).
-define(PERSIST_SCRATCH, <<"scratch">>).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 54: ek vol JSON + behavioural contract ===~n~n"),
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
        run_volume_contract(Ek, Root),
        io:format("~n=== Test 54 passed ===~n~n"),
        0
    catch
        Class:Reason:Stack ->
            io:format("~n=== Test 54 FAILED ===~n  ~p:~p~n  ~p~n",
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

run_volume_contract(Ek, Root) ->
    ScenarioFile = "05_volumes.exs",
    Source = scenario_path(Root, ScenarioFile),
    Term = tmp_term_path("05_volumes"),

    step("ek dsl compile " ++ ScenarioFile, fun() ->
        expect_ok(run_ek(Ek,
                         "dsl compile " ++ shell_quote(Source) ++
                         " -o " ++ shell_quote(Term)))
    end),

    step("patch " ++ ScenarioFile ++ " for this host", fun() ->
        patch_term(Term, #{binary => demo("echo_server"),
                           parent => ?PARENT})
    end),

    step("ek up " ++ ScenarioFile, fun() ->
        expect_ok(run_ek(Ek, "up " ++ shell_quote(Term)))
    end),

    _Rows = step("container reaches running",
        fun() -> wait_ct_list(Ek, [?POD_CT], 15_000) end),

    %% Snapshot pre-existing orphan UUIDs once. The test asserts that
    %% the scenario itself does not introduce new orphans; pre-existing
    %% disk-orphans from prior runs are tolerated.
    BaselineOrphans = step("ek vol orphans baseline", fun() ->
        Os = json_ek(Ek, "--format json vol orphans"),
        true = is_list(Os),
        {ok, [get_json(<<"uuid">>, O) || O <- Os,
                                          get_json(<<"uuid">>, O) =/= undefined]}
    end),

    %% --- vol list (global) ----------------------------------------
    AllVols = step(
        "ek --format json vol list returns a list of volume objects",
        fun() ->
            Vs = json_ek(Ek, "--format json vol list"),
            true = is_list(Vs),
            lists:foreach(fun assert_volume_shape/1, Vs),
            {ok, Vs}
        end),

    Primary = require_persist(?PERSIST_PRIMARY, AllVols),
    Scratch = require_persist(?PERSIST_SCRATCH, AllVols),
    Uuid = get_json(<<"uuid">>, Primary),
    VolRoot = filename:dirname(binary_to_list(
                                 get_json(<<"host_path">>, Primary))),
    true = is_binary(Uuid),
    true = byte_size(Uuid) > 0,

    step("primary volume metadata is well-formed", fun() ->
        assert_string_field(<<"container">>, ?POD_CT, Primary),
        assert_string_field(<<"lifecycle">>, <<"persistent">>, Primary),
        assert_string_field_present(<<"host_path">>, Primary),
        assert_present(<<"quota_bytes">>, Primary),
        ok
    end),

    step("scratch volume is ephemeral", fun() ->
        assert_string_field(<<"container">>, ?POD_CT, Scratch),
        assert_string_field(<<"lifecycle">>, <<"ephemeral">>, Scratch),
        ok
    end),

    %% --- vol list --container -------------------------------------
    step("ek --format json vol list --container returns the same set",
      fun() ->
        ByCt = json_ek(Ek,
                       "--format json vol list --container " ++
                       shell_quote(binary_to_list(?POD_CT))),
        true = is_list(ByCt),
        lists:foreach(fun assert_volume_shape/1, ByCt),
        Names = lists:sort([get_json(<<"persist">>, V) || V <- ByCt]),
        Expected = lists:sort([?PERSIST_PRIMARY, ?PERSIST_SCRATCH]),
        case Names of
            Expected -> ok;
            Other -> {error, {persist_set_mismatch, Other, Expected}}
        end
    end),

    %% --- vol inspect by UUID and by persist -----------------------
    step("ek vol inspect by UUID matches list entry", fun() ->
        ByUuid = json_ek(Ek,
                         "--format json vol inspect " ++
                         shell_quote(binary_to_list(Uuid))),
        assert_string_field(<<"uuid">>, Uuid, ByUuid),
        assert_string_field(<<"persist">>, ?PERSIST_PRIMARY, ByUuid),
        ok
    end),

    step("ek vol inspect by persist name resolves", fun() ->
        ByPersist = json_ek(Ek,
                            "--format json vol inspect " ++
                            shell_quote(binary_to_list(?PERSIST_PRIMARY))),
        assert_string_field(<<"persist">>, ?PERSIST_PRIMARY, ByPersist),
        case get_json(<<"uuid">>, ByPersist) of
            Uuid -> ok;
            Other -> {error, {uuid_mismatch_via_persist, Uuid, Other}}
        end
    end),

    %% --- vol set-quota --------------------------------------------
    NewQuotaBytes = 32 * 1024 * 1024,
    step("ek vol set-quota changes quota_bytes", fun() ->
        expect_ok(run_ek(Ek,
                         "vol set-quota " ++
                         shell_quote(binary_to_list(Uuid)) ++ " 32M")),
        After = json_ek(Ek,
                        "--format json vol inspect " ++
                        shell_quote(binary_to_list(Uuid))),
        case get_json(<<"quota_bytes">>, After) of
            NewQuotaBytes -> ok;
            Other -> {error, {quota_not_persisted, NewQuotaBytes, Other, After}}
        end
    end),

    %% --- vol orphans (no new orphans from this scenario) ----------
    step("ek vol orphans introduces no new entries", fun() ->
        Os = json_ek(Ek, "--format json vol orphans"),
        Uuids = [get_json(<<"uuid">>, O) || O <- Os,
                                            get_json(<<"uuid">>, O) =/= undefined],
        case Uuids -- BaselineOrphans of
            [] -> ok;
            New -> {error, {new_orphans_introduced, New,
                            #{current => Uuids, baseline => BaselineOrphans}}}
        end
    end),

    %% --- vol gc-orphans -------------------------------------------
    run_gc_orphans_contract(Ek, VolRoot, BaselineOrphans),

    %% --- ek down: ephemeral gone, persistent kept -----------------
    step("ek down " ++ ScenarioFile, fun() ->
        expect_ok(run_ek(Ek, "down " ++ shell_quote(Term))),
        wait_terminal_or_absent(Ek, [?POD_CT], 10_000)
    end),

    step("after down: scratch (ephemeral) is gone, primary kept",
      fun() ->
        AllAfter = json_ek(Ek, "--format json vol list"),
        true = is_list(AllAfter),
        PrimaryCheck = case find_persist(?PERSIST_PRIMARY, AllAfter) of
            {ok, P2} ->
                case get_json(<<"uuid">>, P2) of
                    Uuid -> ok;
                    Other -> {error, {persistent_uuid_changed, Uuid, Other}}
                end;
            error ->
                {error, {persistent_volume_disappeared, AllAfter}}
        end,
        case PrimaryCheck of
            ok ->
                case find_persist(?PERSIST_SCRATCH, AllAfter) of
                    error -> ok;
                    {ok, S2} -> {error, {ephemeral_volume_survived, S2}}
                end;
            Err -> Err
        end
    end),

    %% --- ek up again: persistent reattaches with the same UUID ----
    step("ek up again: persistent volume reattaches", fun() ->
        expect_ok(run_ek(Ek, "up " ++ shell_quote(Term))),
        {ok, _} = wait_ct_list(Ek, [?POD_CT], 15_000),
        After = json_ek(Ek,
                        "--format json vol inspect " ++
                        shell_quote(binary_to_list(?PERSIST_PRIMARY))),
        case get_json(<<"uuid">>, After) of
            Uuid -> ok;
            Other -> {error, {reattach_uuid_changed, Uuid, Other, After}}
        end
    end),

    step("ek down " ++ ScenarioFile ++ " (final)", fun() ->
        expect_ok(run_ek(Ek, "down " ++ shell_quote(Term))),
        wait_terminal_or_absent(Ek, [?POD_CT], 10_000)
    end),

    _ = file:delete(Term),
    ok.

%% ------------------------------------------------------------------
%% Volume-shape assertion (the JSON contract being pinned)
%% ------------------------------------------------------------------

assert_volume_shape(V) when is_map(V) ->
    %% Required keys and their permitted shapes. `null` is permitted
    %% wherever an underlying value may be undefined; missing keys are not.
    Required = [<<"uuid">>, <<"container">>, <<"persist">>, <<"host_path">>,
                <<"lifecycle">>, <<"quota_bytes">>],
    lists:foreach(fun(K) -> assert_present(K, V) end, Required),
    assert_string_or_null(<<"uuid">>, V),
    assert_string_or_null(<<"container">>, V),
    assert_string_or_null(<<"persist">>, V),
    assert_string_or_null(<<"host_path">>, V),
    assert_string_or_null(<<"lifecycle">>, V),
    assert_int_or_null(<<"quota_bytes">>, V),
    ok;
assert_volume_shape(Other) ->
    error({volume_not_a_map, Other}).

%% ------------------------------------------------------------------
%% CLI helpers (kept structurally identical to 53)
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
%% Wait / list helpers
%% ------------------------------------------------------------------

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

find_row(Name, Rows) ->
    case [R || R <- Rows, get_json(<<"name">>, R) =:= Name] of
        [R | _] -> {ok, R};
        [] -> error
    end.

%% ------------------------------------------------------------------
%% Volume-list lookup helpers
%% ------------------------------------------------------------------

require_persist(Persist, Vs) ->
    case find_persist(Persist, Vs) of
        {ok, V} -> V;
        error -> error({persist_not_found, Persist, Vs})
    end.

find_persist(Persist, Vs) ->
    case [V || V <- Vs, get_json(<<"persist">>, V) =:= Persist,
               get_json(<<"container">>, V) =:= ?POD_CT] of
        [V | _] -> {ok, V};
        [] -> error
    end.

%% ------------------------------------------------------------------
%% gc-orphans contract
%% ------------------------------------------------------------------

run_gc_orphans_contract(Ek, VolRoot, BaselineOrphans) ->
    step("ek vol gc-orphans precondition: no pre-existing orphans", fun() ->
        case BaselineOrphans of
            [] -> ok;
            _ -> {error, {preexisting_orphans_block_gc_contract,
                          BaselineOrphans}}
        end
    end),

    Uuid = synthetic_orphan_uuid(),
    Path = filename:join(VolRoot, binary_to_list(Uuid)),

    step("create synthetic disk orphan for gc-orphans", fun() ->
        expect_ok(run_cmd("mkdir -p " ++ shell_quote(Path))),
        ok
    end),

    step("ek vol gc-orphans --dry-run reports synthetic orphan", fun() ->
        Rows = json_ek(Ek, "--format json vol gc-orphans --dry-run"),
        Row = require_gc_uuid(Uuid, Rows),
        assert_string_field(<<"uuid">>, Uuid, Row),
        assert_string_field(<<"mode">>, <<"dry_run">>, Row),
        assert_string_field(<<"status">>, <<"pending">>, Row),
        ok
    end),

    step("ek vol gc-orphans --yes deletes synthetic orphan", fun() ->
        Rows = json_ek(Ek, "--format json vol gc-orphans --yes"),
        Row = require_gc_uuid(Uuid, Rows),
        assert_string_field(<<"uuid">>, Uuid, Row),
        assert_string_field(<<"mode">>, <<"confirm">>, Row),
        assert_string_field(<<"status">>, <<"deleted">>, Row),
        ok
    end),

    step("synthetic orphan no longer appears in vol orphans", fun() ->
        Os = json_ek(Ek, "--format json vol orphans"),
        Uuids = [get_json(<<"uuid">>, O) || O <- Os,
                                            get_json(<<"uuid">>, O) =/= undefined],
        case lists:member(Uuid, Uuids) of
            false -> ok;
            true -> {error, {synthetic_orphan_survived_gc, Uuid, Uuids}}
        end
    end).

synthetic_orphan_uuid() ->
    Suffix = integer_to_list(erlang:unique_integer([positive]), 16),
    list_to_binary("ek_vol_cli54_gc_" ++ string:lowercase(Suffix)).

require_gc_uuid(Uuid, Rows) when is_list(Rows) ->
    case [R || R <- Rows, get_json(<<"uuid">>, R) =:= Uuid] of
        [R | _] -> R;
        [] -> error({gc_uuid_not_found, Uuid, Rows})
    end.

%% ------------------------------------------------------------------
%% Term patching (kept structurally identical to 53)
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
%% Field assertions
%% ------------------------------------------------------------------

assert_string_field(Key, Expected, Map) ->
    case get_json(Key, Map) of
        Expected -> ok;
        Other -> error({unexpected_json_field, Key, Expected, Other, Map})
    end.

assert_string_field_present(Key, Map) ->
    case get_json(Key, Map) of
        S when is_binary(S), byte_size(S) > 0 -> ok;
        Other -> error({expected_non_empty_string, Key, Other, Map})
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
%% Environment setup (kept structurally identical to 53)
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
    filename:join("/tmp", "erlkoenig_cli54_" ++ Base ++ ".term").

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
