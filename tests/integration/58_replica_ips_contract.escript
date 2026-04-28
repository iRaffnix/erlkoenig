#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 58: replica_ips host-firewall expansion contract.
%%
%% Pins down the exact-rule-count + concrete-IP semantics of
%% `{:replica_ips, Pod, Container}` host-firewall references that
%% test 51 only loosely verifies. Two scenarios:
%%
%%   (A) two_tier.exs                 — happy path
%%       2 frontend replicas × 3 backend replicas = exactly 6
%%       expanded `tcp dport 4000' rules in `inet/host/forward',
%%       each with concrete saddr + daddr (no `__unresolved__'),
%%       collectively forming the full cross-product.
%%
%%   (B) container_local_replica_ips.exs — fail-loud
%%       Container-local nft referencing replica_ips MUST be
%%       rejected at apply time with the documented hint
%%       (unresolvable_replica_ips_in_container_nft).
%%
%% Mirrors 53/54/55 patterns: local step/2 (so step-failures still
%% reach the after-clause), Status-variable + halt(Status), and a
%% baseline-aware leak audit at the end.
-mode(compile).

-define(PARENT, <<"ek_cli58">>).
-define(PARENT_CIDR, "10.10.0.1/24").

-define(NAME_FRONT_0, <<"frontend-0-app">>).
-define(NAME_FRONT_1, <<"frontend-1-app">>).
-define(NAME_BACK_0,  <<"backend-0-app">>).
-define(NAME_BACK_1,  <<"backend-1-app">>).
-define(NAME_BACK_2,  <<"backend-2-app">>).

-define(FRONT_NAMES, [?NAME_FRONT_0, ?NAME_FRONT_1]).
-define(BACK_NAMES,  [?NAME_BACK_0,  ?NAME_BACK_1, ?NAME_BACK_2]).
-define(ALL_NAMES,   ?FRONT_NAMES ++ ?BACK_NAMES).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 58: replica_ips host-firewall contract ===~n~n"),
    require_root(),

    Root = test_helper:project_root(),
    Ek = find_ek(Root),

    ensure_installed_daemon(Ek),
    reset_daemon(Ek),
    cleanup_all(Ek),
    ensure_dummy(?PARENT, ?PARENT_CIDR),

    BaselineOrphans = count_volume_orphans(Ek),

    Status = try
        run_two_tier_scenario(Ek, Root),
        run_container_local_rejection(Ek, Root),
        io:format("~n=== Test 58 passed ===~n~n"),
        0
    catch
        Class:Reason:Stack ->
            io:format("~n=== Test 58 FAILED ===~n  ~p:~p~n  ~p~n",
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

%% ------------------------------------------------------------------
%% Scenario A — exact cross-product expansion
%% ------------------------------------------------------------------

run_two_tier_scenario(Ek, Root) ->
    ScenarioFile = "58_replica_ips/two_tier.exs",
    Source = scenario_path(Root, ScenarioFile),
    Term = tmp_term_path("58_two_tier"),

    step("ek dsl compile " ++ ScenarioFile, fun() ->
        expect_ok(run_ek(Ek,
                         "dsl compile " ++ shell_quote(Source) ++
                         " -o " ++ shell_quote(Term)))
    end),

    step("patch " ++ ScenarioFile ++ " for this host", fun() ->
        patch_term(Term, #{parent => ?PARENT})
    end),

    step("ek up " ++ ScenarioFile, fun() ->
        expect_ok(run_ek(Ek, "up " ++ shell_quote(Term)))
    end),

    %% Wait for ALL 5 containers running and IP-assigned. Replica IPs
    %% are populated only when each replica reaches running, so we
    %% must not query nft until that finishes.
    Rows = step("all 5 replicas reach running with IPs",
        fun() -> wait_all_running(Ek, ?ALL_NAMES, 30_000) end),
    Ips = collect_ips(Rows),

    FrontIps = sort_ips([fetch_ip(N, Ips) || N <- ?FRONT_NAMES]),
    BackIps  = sort_ips([fetch_ip(N, Ips) || N <- ?BACK_NAMES]),
    Expected = sort_pairs([{F, B} || F <- FrontIps, B <- BackIps]),
    ExpectedCount = length(Expected),
    case ExpectedCount of
        6 -> ok;
        Other -> error({expected_6_pairs, Other, FrontIps, BackIps})
    end,

    %% --- core assertion: exact rule count after expansion ---------
    step("nft has exactly 6 rules for tcp dport 4000",
      fun() ->
        Lines = nft_table_lines("inet host"),
        Matching = [L || L <- Lines, contains(L, "tcp dport 4000")],
        case length(Matching) of
            6 -> ok;
            N -> {error, {expected_6_rules, N, Matching}}
        end
    end),

    %% --- assertion: no `__unresolved__' placeholders --------------
    step("no __unresolved__ in expanded rules", fun() ->
        Lines = nft_table_lines("inet host"),
        Bad = [L || L <- Lines, contains(L, "__unresolved__")],
        case Bad of
            [] -> ok;
            _ -> {error, {unresolved_placeholders_present, Bad}}
        end
    end),

    %% --- assertion: each rule's (saddr,daddr) is in the expected
    %% cross-product, and collectively they form the FULL set ------
    step("expanded rules cover the full frontend×backend cross-product",
      fun() ->
        Lines = nft_table_lines("inet host"),
        Rules = [parse_saddr_daddr(L)
                 || L <- Lines, contains(L, "tcp dport 4000")],
        Got = sort_pairs([P || {ok, P} <- Rules]),
        case Got of
            Expected -> ok;
            _ -> {error,
                  {pair_set_mismatch,
                   #{expected => Expected, got => Got,
                     unparsed => [L || L <- Lines,
                                       contains(L, "tcp dport 4000"),
                                       not is_parseable_rule(L)]}}}
        end
    end),

    step("ek down " ++ ScenarioFile, fun() ->
        expect_ok(run_ek(Ek, "down " ++ shell_quote(Term))),
        wait_all_terminal_or_gone(Ek, ?ALL_NAMES, 15_000)
    end),

    %% NB: `ek down' intentionally does NOT tear down the host
    %% nft table — host-side firewall is by-design persistent
    %% across container lifecycle (it protects the host even when
    %% no containers are running). The 6 expanded `tcp dport 4000'
    %% rules legitimately stay until the next `ek up' replaces
    %% the table or until the operator runs `nft delete table'.
    %% No assertion here on purpose; the `cleanup_all' / nft
    %% delete in main()'s after-block is the actual cleanup path.

    _ = file:delete(Term),
    ok.

%% ------------------------------------------------------------------
%% Scenario B — container-local replica_ips must fail loud
%% ------------------------------------------------------------------

run_container_local_rejection(Ek, Root) ->
    ScenarioFile = "58_replica_ips/container_local_replica_ips.exs",
    Source = scenario_path(Root, ScenarioFile),
    Term = tmp_term_path("58_container_local"),

    step("ek dsl compile " ++ ScenarioFile, fun() ->
        expect_ok(run_ek(Ek,
                         "dsl compile " ++ shell_quote(Source) ++
                         " -o " ++ shell_quote(Term)))
    end),

    step("patch " ++ ScenarioFile ++ " for this host", fun() ->
        patch_term(Term, #{parent => ?PARENT})
    end),

    %% Two-part contract here:
    %%   1. `ek up` must NOT succeed — exit non-zero, the offending
    %%      container shows up as failed/gone.
    %%   2. The documented marker `unresolvable_replica_ips_in_container_nft'
    %%      must be visible in the CLI output. It used to land only in
    %%      journalctl because the post-up summary kept just the failed
    %%      state and discarded `Info.error'. This pins the operator UX:
    %%      a failed spawn must carry the actionable internal reason.
    Marker = "unresolvable_replica_ips_in_container_nft",
    step("ek up rejects container-local replica_ips with actionable marker",
      fun() ->
        case run_ek(Ek, "up " ++ shell_quote(Term)) of
            {0, Out} ->
                {error, {up_unexpectedly_succeeded, Out}};
            {_Status, Out} ->
                Missing = [Needle || Needle <- ["frontend-0-app", Marker],
                                     string:find(Out, Needle) =:= nomatch],
                case Missing of
                    [] -> ok;
                    _ -> {error, {up_output_missing, Missing, Out}}
                end
        end
    end),

    %% Make sure no half-spawned containers are still around. The
    %% rejection should be at compile time (before spawn) for at
    %% least the offending container. If anything DID spawn, ek down
    %% will reach it.
    step("ek down (best-effort cleanup)", fun() ->
        _ = run_ek(Ek, "down " ++ shell_quote(Term)),
        ok
    end),

    _ = file:delete(Term),
    ok.

%% ------------------------------------------------------------------
%% Per-test step/2 — raises instead of halt(1) so the outer
%% try/after still runs cleanup + leak audit on failures.
%% ------------------------------------------------------------------

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
%% Defence-in-depth leak audit at the end of the test run.
%% ------------------------------------------------------------------

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
            io:format("~ts", [os:cmd(Cmd)])
    end.

count_volume_orphans(Ek) ->
    case catch json_ek(Ek, "--format json vol orphans") of
        L when is_list(L) -> length(L);
        _ -> 0
    end.

%% ------------------------------------------------------------------
%% nft helpers (the actual contract evidence)
%% ------------------------------------------------------------------

nft_table_lines(TableSpec) ->
    %% TableSpec is e.g. "inet host"
    Out = os:cmd("nft list table " ++ TableSpec ++ " 2>&1"),
    [string:trim(L) || L <- string:split(Out, "\n", all),
                       string:trim(L) =/= ""].

%% Parse a rule line into {ok, {Saddr, Daddr}} when both are present.
parse_saddr_daddr(Line) ->
    case extract_after("ip saddr ", Line) of
        nomatch -> error;
        {ok, AfterSaddr} ->
            Saddr = list_to_binary(first_token(AfterSaddr)),
            case extract_after("ip daddr ", Line) of
                nomatch -> error;
                {ok, AfterDaddr} ->
                    Daddr = list_to_binary(first_token(AfterDaddr)),
                    {ok, {Saddr, Daddr}}
            end
    end.

is_parseable_rule(Line) ->
    parse_saddr_daddr(Line) =/= error.

extract_after(Needle, Hay) ->
    case string:find(Hay, Needle) of
        nomatch -> nomatch;
        Match -> {ok, lists:nthtail(length(Needle), Match)}
    end.

first_token(S) ->
    %% Strip everything from the first space/end onwards.
    case string:split(S, " ", leading) of
        [Tok | _] -> Tok
    end.

contains(Hay, Needle) ->
    string:find(Hay, Needle) =/= nomatch.

sort_ips(L) -> lists:sort(L).
sort_pairs(L) -> lists:sort(L).

%% ------------------------------------------------------------------
%% Container/IP discovery via the operator JSON contract
%% ------------------------------------------------------------------

wait_all_running(Ek, Names, TimeoutMs) ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMs,
    wait_all_running_loop(Ek, Names, Deadline, undefined).

wait_all_running_loop(Ek, Names, Deadline, Last) ->
    Rows = case catch json_ek(Ek, "--format json ct list") of
        L when is_list(L) -> L;
        _ -> []
    end,
    Ready = lists:all(fun(N) -> running_with_ip(N, Rows) end, Names),
    case Ready of
        true ->
            {ok, Rows};
        false ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true ->
                    {error, {timeout_waiting_for_replicas,
                             #{names => Names, last_rows => Last,
                               current_rows => Rows}}};
                false ->
                    timer:sleep(300),
                    wait_all_running_loop(Ek, Names, Deadline, Rows)
            end
    end.

running_with_ip(Name, Rows) ->
    case [R || R <- Rows, get_json(<<"name">>, R) =:= Name] of
        [Row | _] ->
            get_json(<<"state">>, Row) =:= <<"running">>
            andalso is_binary(get_json(<<"ip">>, Row))
            andalso get_json(<<"ip">>, Row) =/= <<"-">>;
        [] -> false
    end.

collect_ips(Rows) ->
    maps:from_list(
      [{get_json(<<"name">>, R), get_json(<<"ip">>, R)}
       || R <- Rows,
          is_binary(get_json(<<"name">>, R)),
          is_binary(get_json(<<"ip">>, R))]).

fetch_ip(Key, Map) ->
    case maps:find(Key, Map) of
        {ok, V} -> V;
        error -> error({missing_ip_for, Key, Map})
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

active_in_rows(Name, Rows) ->
    case [R || R <- Rows, get_json(<<"name">>, R) =:= Name] of
        [Row | _] ->
            S = get_json(<<"state">>, Row),
            S =/= <<"stopped">> andalso S =/= <<"failed">>;
        [] -> false
    end.

%% ------------------------------------------------------------------
%% CLI helpers (kept structurally identical to 53/54/55)
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
%% Term patching
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
%% Field assertions (small subset — the heavy lifting is parse_saddr_daddr)
%% ------------------------------------------------------------------

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
    EnvCandidate = case os:getenv("EK_BINARY") of
        false -> [];
        Path  -> [Path]
    end,
    Candidates = EnvCandidate ++
        ["/opt/erlkoenig/bin/ek",
         "/opt/erlkoenig/release/bin/ek",
         filename:join(Root, "dist/ek")],
    case [P || P <- Candidates, filelib:is_regular(P)] of
        [P | _] -> P;
        [] -> error(ek_binary_not_found)
    end.

scenario_path(Root, File) ->
    filename:join([Root, "tests", "integration", "cli_scenarios", File]).

tmp_term_path(Base) ->
    filename:join("/tmp", "erlkoenig_cli58_" ++ Base ++ ".term").

shell_quote(S) when is_binary(S) ->
    shell_quote(binary_to_list(S));
shell_quote(S) ->
    Escaped = lists:flatten(
                [case C of
                     $' -> "'\\''";
                     Other -> Other
                 end || C <- S]),
    "'" ++ Escaped ++ "'".
