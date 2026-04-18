%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%

-module(erlkoenig_nft_firewall).
-moduledoc """
Firewall configuration owner and lifecycle manager.

A gen_server that reads the declarative firewall config from
etc/firewall.term, applies it via the shared erlkoenig_nft_srv Netlink
server, and starts per-counter watchers in erlkoenig_nft_watch_sup.

On termination, the nf_tables table is deleted so the firewall
is cleanly removed.

Rules are built as semantic terms (nft_expr_ir) that can be tested
in the nft_vm simulator, then encoded to Netlink via nft_encode.

The config format is documented in etc/firewall.term.

Runtime operations (ban, unban, status) are exposed via
gen_server calls. Use the erlkoenig_nft facade module instead of
calling this module directly.
""".

-behaviour(gen_server).

-export([
    start_link/0,
    start_link/1,
    ban/1,
    unban/1,
    rates/0,
    status/0,
    reload/0,
    list_chains/0,
    list_sets/0,
    list_set/1,
    list_counters/0,
    add_element/2,
    del_element/2,
    diff_live/0
]).

-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2
]).

%% --- Constants ---

-define(INET, 1).

%% --- Types ---

-type state() :: #{
    config := map(),
    table := binary(),
    mode := active | degraded,
    degraded_reason => {apply_failed, term()}
                     | {diagnostic_error, term()}
                     | {apply_failed, tuple(), term()}
}.

%% --- Public API ---

-doc "Start the firewall with config from etc/firewall.term, or a default empty table.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    case config_path() of
        {ok, Path} ->
            case file:consult(Path) of
                {ok, [Config]} when is_map(Config) ->
                    start_link(Config);
                {ok, [_NotAMap]} ->
                    {error, {bad_config, {not_a_map, Path}}};
                {ok, _Multiple} ->
                    {error, {bad_config, {expected_single_term, Path}}};
                {error, Reason} ->
                    {error, {bad_config, {Reason, Path}}}
            end;
        {error, not_found} ->
            logger:notice("[erlkoenig_nft] No config found, starting with empty table"),
            start_link(default_config())
    end.

-doc "Start the firewall with an explicit config map.".
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Config) when is_map(Config) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Config, []).

-doc "Add an IP address to the blocklist (IPv4 or IPv6).".
-spec ban(inet:ip_address() | binary() | string()) -> ok | {error, term()}.
ban(IP) ->
    case erlkoenig_nft_ip:normalize(IP) of
        {ok, Bin} -> gen_server:call(?MODULE, {ban, Bin});
        Err -> Err
    end.

-doc "Remove an IP address from the blocklist (IPv4 or IPv6).".
-spec unban(inet:ip_address() | binary() | string()) -> ok | {error, term()}.
unban(IP) ->
    case erlkoenig_nft_ip:normalize(IP) of
        {ok, Bin} -> gen_server:call(?MODULE, {unban, Bin});
        Err -> Err
    end.

-doc "Get current rates for all watched counters.".
-spec rates() -> #{binary() => map()}.
rates() ->
    gen_server:call(?MODULE, rates).

-doc "Get firewall status.".
-spec status() -> map().
status() ->
    gen_server:call(?MODULE, status).

-doc """
Reload the firewall config from etc/firewall.term.

Stops all counter workers, re-applies the full config (clean slate),
and restarts counters. Existing connections are preserved (conntrack
state lives in the kernel).
""".
-spec reload() -> ok | {error, term()}.
reload() ->
    gen_server:call(?MODULE, reload, 10000).

-doc "List chains with hook, type, policy, and rule count.".
-spec list_chains() -> [map()].
list_chains() ->
    gen_server:call(?MODULE, list_chains).

-doc "List named sets with their types.".
-spec list_sets() -> [map()].
list_sets() ->
    gen_server:call(?MODULE, list_sets).

-doc "Show elements of a named set.".
-spec list_set(binary() | string()) -> {ok, map()} | {error, term()}.
list_set(Name) ->
    gen_server:call(?MODULE, {list_set, ensure_binary(Name)}).

-doc "List counters with current rate values.".
-spec list_counters() -> [map()].
list_counters() ->
    gen_server:call(?MODULE, list_counters).

-doc "Add an element to a named set.".
-spec add_element(binary() | string(), binary() | string()) -> ok | {error, term()}.
add_element(SetName, Value) ->
    gen_server:call(?MODULE, {add_element, ensure_binary(SetName), Value}).

-doc "Delete an element from a named set.".
-spec del_element(binary() | string(), binary() | string()) -> ok | {error, term()}.
del_element(SetName, Value) ->
    gen_server:call(?MODULE, {del_element, ensure_binary(SetName), Value}).

-doc "Compare running kernel state against config. Returns a list of diffs.".
-spec diff_live() -> [map()].
diff_live() ->
    gen_server:call(?MODULE, diff_live, 10000).

%% --- gen_server callbacks ---

-spec init(map()) -> {ok, state()}.
init(Config) ->
    proc_lib:set_label(erlkoenig_nft_firewall),
    Table = maps:get(table, Config),
    case apply_config(Config) of
        ok ->
            start_counters(Config),
            logger:notice("[erlkoenig_nft] Firewall applied: table=~s", [Table]),
            {ok, #{config => Config, table => Table, mode => active}};
        {error, Reason} ->
            %% Degraded mode: service stays up, control plane reachable.
            %% No firewall rules in kernel — host is unprotected.
            DiagReason = diagnose_and_report(Config, Reason),
            logger:warning(
                "[erlkoenig_nft] DEGRADED: Firewall not applied. "
                "Fix firewall.term and call erlkoenig_nft:reload()."
            ),
            erlkoenig_nft_events:notify_control(
                apply_failed, {error, DiagReason}, #{table => Table}
            ),
            {ok, #{
                config => Config,
                table => Table,
                mode => degraded,
                degraded_reason => DiagReason
            }}
    end.

-spec handle_call(term(), {pid(), term()}, state()) ->
    {reply, term(), state()}.
handle_call({ban, _IPBin}, _From, #{mode := degraded} = State) ->
    {reply, {error, degraded}, State};
handle_call({ban, IPBin}, _From, #{config := Config} = State) ->
    BanDurationSec = get_ban_duration(Config),
    TimeoutMs = BanDurationSec * 1000,
    Result = apply_set_op(
        Config,
        IPBin,
        fun blocklist_name/2,
        fun(T, S) -> nft_rules:ban_ip(T, S, IPBin, TimeoutMs) end,
        "Banned ~s (~ps)",
        [erlkoenig_nft_ip:format(IPBin), BanDurationSec]
    ),
    {reply, Result, State};
handle_call({unban, _IPBin}, _From, #{mode := degraded} = State) ->
    {reply, {error, degraded}, State};
handle_call({unban, IPBin}, _From, #{config := Config} = State) ->
    Result = apply_set_op(
        Config,
        IPBin,
        fun blocklist_name/2,
        fun(T, S) -> nft_rules:unban_ip(T, S, IPBin) end,
        "Unbanned ~s",
        [erlkoenig_nft_ip:format(IPBin)]
    ),
    {reply, Result, State};
handle_call(rates, _From, State) ->
    Rates = collect_rates(),
    {reply, Rates, State};
handle_call(status, _From, #{mode := degraded, degraded_reason := Reason, table := Table} = State) ->
    Status = #{
        table => Table,
        running => false,
        mode => degraded,
        reason => Reason,
        hint => <<"Fix firewall.term and call erlkoenig_nft:reload()">>
    },
    {reply, Status, State};
handle_call(status, _From, #{config := Config, table := Table} = State) ->
    Status = #{
        table => Table,
        running => true,
        mode => active,
        config => Config,
        counters => counter_count()
    },
    {reply, Status, State};
handle_call(reload, _From, #{table := OldTable} = State) ->
    Result =
        maybe
            {ok, Path} ?= config_path(),
            {ok, [NewConfig]} ?=
                case file:consult(Path) of
                    {ok, [_] = OK} -> {ok, OK};
                    {ok, _} -> {error, {bad_config, {expected_single_term, Path}}};
                    {error, Reason} -> {error, {bad_config, Reason}}
                end,
            erlkoenig_nft_watch_sup:stop_counters(),
            ok ?= apply_config(NewConfig),
            NewTable = maps:get(table, NewConfig),
            maybe_delete_old_table(NewTable, OldTable),
            start_counters(NewConfig),
            logger:notice("[erlkoenig_nft] Config reloaded: table=~s", [NewTable]),
            {ok, NewConfig, NewTable}
        else
            {error, _} = Err -> Err
        end,
    case Result of
        {ok, NewCfg, NewTbl} ->
            %% Success — enter or re-enter active mode
            {reply, ok, State#{
                config => NewCfg,
                table => NewTbl,
                mode => active,
                degraded_reason => undefined
            }};
        {error, _} = ApplyErr ->
            case maps:get(mode, State, active) of
                degraded ->
                    %% Already degraded — stay degraded, just report the new error
                    DiagReason = diagnose_and_report(
                        maps:get(config, State), element(2, ApplyErr)
                    ),
                    logger:error("[erlkoenig_nft] Reload failed (still degraded): ~p", [DiagReason]),
                    {reply, ApplyErr, State#{degraded_reason => DiagReason}};
                active ->
                    %% Was active — try to roll back to old config
                    _ = apply_config(maps:get(config, State)),
                    start_counters(maps:get(config, State)),
                    logger:error("[erlkoenig_nft] Reload failed: ~p, rolled back", [ApplyErr]),
                    {reply, ApplyErr, State}
            end
    end;
handle_call(list_chains, _From, #{config := Config} = State) ->
    Chains = maps:get(chains, Config, []),
    Result = [
        case maps:is_key(hook, C) of
            true ->
                #{
                    name => maps:get(name, C),
                    hook => maps:get(hook, C),
                    type => maps:get(type, C, filter),
                    priority => maps:get(priority, C, 0),
                    policy => maps:get(policy, C, accept),
                    rules => length(maps:get(rules, C, []))
                };
            false ->
                #{
                    name => maps:get(name, C),
                    type => regular,
                    rules => length(maps:get(rules, C, []))
                }
        end
     || C <- Chains
    ],
    {reply, Result, State};
handle_call(list_sets, _From, #{config := Config} = State) ->
    Sets = maps:get(sets, Config, []),
    Result = [format_set_info(S) || S <- Sets],
    {reply, Result, State};
handle_call({list_set, Name}, _From, #{config := Config} = State) ->
    Sets = maps:get(sets, Config, []),
    Table = maps:get(table, Config),
    case find_set_by_name(Sets, Name) of
        {ok, SetSpec} ->
            Info = format_set_info(SetSpec),
            %% Try to get live kernel elements via netlink GET
            LiveElems =
                case
                    nfnl_server:list_set_elems(
                        erlkoenig_nft_srv, ?INET, Table, Name
                    )
                of
                    {ok, Elems} -> Elems;
                    {error, _} -> []
                end,
            ConfigElems =
                case SetSpec of
                    {_, _, #{elements := CE}} -> CE;
                    _ -> []
                end,
            {reply,
                {ok, Info#{
                    elements => LiveElems,
                    config_elements => ConfigElems
                }},
                State};
        error ->
            {reply, {error, {no_such_set, Name}}, State}
    end;
handle_call(list_counters, _From, #{config := Config} = State) ->
    Counters = maps:get(counters, Config, []),
    Rates = collect_rates(),
    Result = [
        begin
            CName = counter_name(C),
            Rate = maps:get(CName, Rates, #{}),
            #{
                name => CName,
                packets => maps:get(packets, Rate, 0),
                bytes => maps:get(bytes, Rate, 0),
                pps => maps:get(pps, Rate, 0)
            }
        end
     || C <- Counters
    ],
    {reply, Result, State};
handle_call({add_element, _, _}, _From, #{mode := degraded} = State) ->
    {reply, {error, degraded}, State};
handle_call({add_element, SetName, Value}, _From, #{config := Config} = State) ->
    Result = do_set_elem_op(Config, SetName, Value, add),
    {reply, Result, State};
handle_call({del_element, _, _}, _From, #{mode := degraded} = State) ->
    {reply, {error, degraded}, State};
handle_call({del_element, SetName, Value}, _From, #{config := Config} = State) ->
    Result = do_set_elem_op(Config, SetName, Value, del),
    {reply, Result, State};
handle_call(diff_live, _From, #{config := Config} = State) ->
    Result = compute_diff(Config),
    {reply, Result, State};
handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast(_Msg, State) ->
    {noreply, State}.

-spec handle_info(term(), state()) -> {noreply, state()}.
handle_info(_Info, State) ->
    {noreply, State}.

-spec terminate(term(), state()) -> ok.
terminate(_Reason, #{table := Table}) ->
    logger:notice("[erlkoenig_nft] Tearing down firewall: table=~s", [Table]),
    erlkoenig_nft_watch_sup:stop_counters(),
    _ = nfnl_server:apply_msgs(erlkoenig_nft_srv, [
        fun(S) -> nft_delete:table(?INET, Table, S) end
    ]),
    ok.

%% --- Internal: Table cleanup on reload ---

-spec maybe_delete_old_table(binary(), binary()) -> ok.
maybe_delete_old_table(NewTable, OldTable) when NewTable =/= OldTable ->
    case
        nfnl_server:apply_msgs(erlkoenig_nft_srv, [
            fun(S) -> nft_delete:table(?INET, OldTable, S) end
        ])
    of
        ok ->
            ok;
        {error, DelErr} ->
            logger:warning(
                "[erlkoenig_nft] Failed to delete old table ~s: ~p",
                [OldTable, DelErr]
            )
    end,
    ok;
maybe_delete_old_table(_NewTable, _OldTable) ->
    ok.

%% --- Internal: Set operations (ban/unban/authorize/deauthorize) ---

-spec apply_set_op(
    map(),
    <<_:32, _:_*96>>,
    fun((map(), binary()) -> {ok, binary()} | {error, no_matching_set}),
    fun((binary(), binary()) -> fun((non_neg_integer()) -> <<_:64, _:_*8>>)),
    string(),
    [any()]
) ->
    ok | {error, term()}.
apply_set_op(Config, IPBin, LookupFun, RuleFun, LogFmt, LogArgs) ->
    Table = maps:get(table, Config),
    case LookupFun(Config, IPBin) of
        {ok, SetName} ->
            Result = nfnl_server:apply_msgs(erlkoenig_nft_srv, [RuleFun(Table, SetName)]),
            case Result of
                ok -> logger:notice("[erlkoenig_nft] " ++ LogFmt, LogArgs);
                {error, OpErr} -> logger:warning("[erlkoenig_nft] set op failed: ~p", [OpErr])
            end,
            Result;
        {error, _} = Err ->
            Err
    end.

%% --- Internal: Apply Config ---

-spec apply_config(map()) -> ok | {error, term()}.
apply_config(Config) ->
    try
        apply_config_unsafe(Config)
    catch
        error:{function_clause, [{Mod, Fun, Args, _} | _]} ->
            %% Unknown rule type, set type, or config shape
            {error, {config_error, Mod, Fun, length(Args)}};
        Class:Reason:Stack ->
            logger:error("[erlkoenig_nft] apply_config crashed: ~p:~p~n  ~p",
                         [Class, Reason, Stack]),
            {error, {apply_crash, Class, Reason}}
    end.

apply_config_unsafe(Config) ->
    Table = maps:get(table, Config),
    Sets = maps:get(sets, Config, []),
    Vmaps = maps:get(vmaps, Config, []),
    Counters = maps:get(counters, Config, []),
    Quotas = maps:get(quotas, Config, []),
    Chains = maps:get(chains, Config, []),

    %% Atomic replace in a single Netlink batch: ensure-exists, delete, recreate.
    %%
    %% The leading `add table` makes the subsequent `delete table` succeed even
    %% if no previous table existed (NLM_F_CREATE without NLM_F_EXCL = idempotent
    %% upsert in nftables). The `delete` then drops the table together with all
    %% its children, and the second `add` plus children installs the new state.
    %%
    %% Kernel commits the whole batch as one transaction: between old state and
    %% new state, no hook ever sees a half-installed ruleset and no policy gap
    %% exists. This matters because reload is the path used to push/remove ban-
    %% list entries during active traffic — a gap would mean dropped packets
    %% slip through.
    Msgs = lists:flatten([
        %% 0. Idempotent upsert so the next DELETE always finds something.
        [fun(S) -> nft_table:add(?INET, Table, S) end],

        %% 1. Drop the (now guaranteed) table and everything inside it.
        [fun(S) -> nft_delete:table(?INET, Table, S) end],

        %% 2. Re-create it, fresh.
        [fun(S) -> nft_table:add(?INET, Table, S) end],

        %% Named counters
        [
            fun(S) -> nft_object:add_counter(?INET, Table, counter_name(C), S) end
         || C <- Counters
        ],

        %% Named quotas
        [
            fun(S) ->
                nft_quota:add(
                    ?INET,
                    Table,
                    quota_name(Q),
                    #{bytes => maps:get(bytes, Q), flags => maps:get(flags, Q, 0)},
                    S
                )
            end
         || Q <- Quotas
        ],

        %% Sets (create + optional initial elements)
        lists:flatten([
            [
                fun(S) ->
                    build_set_msg(Table, SetSpec, Idx, S)
                end
                | build_set_elems(Table, SetSpec)
            ]
         || {Idx, SetSpec} <- with_index(Sets)
        ]),

        %% Chains: create ALL chains first — before vmaps and rules.
        %% Vmap entries with jump verdicts need the target chain to exist.
        [build_chain_create(Table, Chain) || Chain <- Chains],

        %% Verdict maps (create + entries) — after chains, before rules.
        lists:flatten([
            build_vmap(Table, Vmap, Idx)
         || {Idx, Vmap} <- with_index(Vmaps)
        ]),

        %% Rules last — all jump targets, sets, vmaps exist by now.
        lists:flatten([build_chain_rules(Table, Chain, Config) || Chain <- Chains])
    ]),

    nfnl_server:apply_msgs(erlkoenig_nft_srv, Msgs).

%% --- Internal: Diagnostic Error Localization ---
%%
%% When the atomic batch fails, this function tries to locate the exact
%% failing component by applying config pieces one at a time in a
%% throwaway table. The diagnostic table is always cleaned up at the end,
%% so the kernel is left clean regardless of outcome.

-spec diagnose_and_report(map(), term()) -> term().
diagnose_and_report(Config, OriginalReason) ->
    Table = maps:get(table, Config),
    DiagTable = <<Table/binary, "__diag">>,
    logger:error(
        "[erlkoenig_nft] Batch apply failed: ~p — running diagnostics",
        [OriginalReason]
    ),
    DiagResult =
        try
            diagnose_config(Config, DiagTable)
        catch
            Class:Error:Stack ->
                logger:error(
                    "[erlkoenig_nft] Diagnostics crashed: ~p:~p~n  ~p",
                    [Class, Error, Stack]
                ),
                {diagnostic_error, OriginalReason}
        after
            %% Always clean up the diagnostic table
            nfnl_server:apply_msgs(erlkoenig_nft_srv, [
                fun(S) -> nft_delete:table(?INET, DiagTable, S) end
            ])
        end,
    case DiagResult of
        ok ->
            %% Diagnostics couldn't reproduce the failure
            logger:error(
                "[erlkoenig_nft] Diagnostics could not reproduce failure. "
                "Original error: ~p",
                [OriginalReason]
            ),
            {apply_failed, OriginalReason};
        {failed, Component, Detail} ->
            logger:error(
                "[erlkoenig_nft] DIAGNOSTIC: ~p~n"
                "  Component: ~p~n"
                "  Detail: ~p~n"
                "  Hint: Check if this feature is supported by your kernel/nft version",
                [Component, Component, Detail]
            ),
            {apply_failed, Component, Detail};
        {diagnostic_error, _} ->
            DiagResult
    end.

diagnose_config(Config, DiagTable) ->
    Counters = maps:get(counters, Config, []),
    Sets = maps:get(sets, Config, []),
    Vmaps = maps:get(vmaps, Config, []),
    Chains = maps:get(chains, Config, []),

    %% Step 1: Create table
    case
        nfnl_server:apply_msgs(erlkoenig_nft_srv, [
            fun(S) -> nft_table:add(?INET, DiagTable, S) end
        ])
    of
        {error, R} ->
            {failed, {table, DiagTable}, R};
        ok ->
            %% Step 2: Counters
            case
                diagnose_list(
                    Counters,
                    fun(C) ->
                        [fun(S) -> nft_object:add_counter(?INET, DiagTable, counter_name(C), S) end]
                    end,
                    fun(C) -> {counter, counter_name(C)} end
                )
            of
                {failed, _, _} = F ->
                    F;
                ok ->
                    %% Step 3: Sets
                    case
                        diagnose_list(
                            with_index(Sets),
                            fun({Idx, SetSpec}) ->
                                [
                                    fun(S) -> build_set_msg(DiagTable, SetSpec, Idx, S) end
                                    | build_set_elems(DiagTable, SetSpec)
                                ]
                            end,
                            fun({_, SetSpec}) -> {set, element(1, SetSpec)} end
                        )
                    of
                        {failed, _, _} = F ->
                            F;
                        ok ->
                            %% Step 4: Create all chains (needed for jump targets)
                            case
                                nfnl_server:apply_msgs(
                                    erlkoenig_nft_srv,
                                    [build_chain_create(DiagTable, Ch) || Ch <- Chains]
                                )
                            of
                                {error, R} ->
                                    {failed, {chains_create}, R};
                                ok ->
                                    %% Step 5: Vmaps
                                    case
                                        diagnose_list(
                                            with_index(Vmaps),
                                            fun({Idx, Vmap}) ->
                                                build_vmap(DiagTable, Vmap, Idx)
                                            end,
                                            fun({_, V}) -> {vmap, maps:get(name, V)} end
                                        )
                                    of
                                        {failed, _, _} = F ->
                                            F;
                                        ok ->
                                            %% Step 6: Rules per chain
                                            diagnose_chain_rules(DiagTable, Chains, Config)
                                    end
                            end
                    end
            end
    end.

diagnose_list([], _MsgFun, _NameFun) ->
    ok;
diagnose_list([Item | Rest], MsgFun, NameFun) ->
    Msgs = MsgFun(Item),
    case nfnl_server:apply_msgs(erlkoenig_nft_srv, Msgs) of
        ok -> diagnose_list(Rest, MsgFun, NameFun);
        {error, R} -> {failed, NameFun(Item), R}
    end.

diagnose_chain_rules(_, [], _) ->
    ok;
diagnose_chain_rules(DiagTable, [Chain | Rest], Config) ->
    Rules = maps:get(rules, Chain, []),
    case diagnose_rules(DiagTable, Chain, Rules, Config, 1) of
        ok -> diagnose_chain_rules(DiagTable, Rest, Config);
        {failed, _, _} = F -> F
    end.

diagnose_rules(_, _, [], _, _) ->
    ok;
diagnose_rules(DiagTable, Chain, [Rule | Rest], Config, Idx) ->
    ChainName = maps:get(name, Chain),
    try
        Msg = build_rule(DiagTable, ChainName, Rule, Config),
        case nfnl_server:apply_msgs(erlkoenig_nft_srv, [Msg]) of
            ok ->
                diagnose_rules(DiagTable, Chain, Rest, Config, Idx + 1);
            {error, R} ->
                {failed, {rule, ChainName, Idx, Rule}, R}
        end
    catch
        _:Err ->
            {failed, {rule, ChainName, Idx, Rule}, {build_error, Err}}
    end.

%% --- Internal: Start Counters ---

-spec start_counters(map()) -> ok.
start_counters(Config) ->
    Table = maps:get(table, Config),
    Counters = maps:get(counters, Config, []),
    Watch = maps:get(watch, Config, undefined),

    case Watch of
        undefined ->
            ok;
        WatchConfig ->
            Interval = maps:get(interval, WatchConfig, 2000),
            Thresholds = maps:get(thresholds, WatchConfig, []),

            lists:foreach(
                fun(Counter) ->
                    Name = counter_name(Counter),
                    CounterThresholds = build_thresholds(Name, Thresholds),
                    erlkoenig_nft_watch_sup:start_counter(#{
                        name => Name,
                        family => ?INET,
                        table => Table,
                        interval => Interval,
                        thresholds => CounterThresholds
                    })
                end,
                Counters
            )
    end.

%% --- Internal: Build chain messages ---
%%
%% Chain creation and rule insertion are separated so that ALL chains
%% are created before ANY rules are inserted. This ensures that jump
%% targets (regular chains) exist when rules reference them.

-spec build_chain_create(binary(), map()) -> fun().
build_chain_create(Table, ChainConfig) ->
    Name = maps:get(name, ChainConfig),
    case maps:is_key(hook, ChainConfig) of
        true ->
            Hook = maps:get(hook, ChainConfig),
            Type = maps:get(type, ChainConfig, filter),
            Priority = maps:get(priority, ChainConfig, 0),
            Policy = maps:get(policy, ChainConfig, accept),
            fun(S) ->
                nft_chain:add(
                    ?INET,
                    #{
                        table => Table,
                        name => Name,
                        hook => Hook,
                        type => Type,
                        priority => Priority,
                        policy => Policy
                    },
                    S
                )
            end;
        false ->
            fun(S) ->
                nft_chain:add_regular(
                    ?INET,
                    #{
                        table => Table, name => Name
                    },
                    S
                )
            end
    end.

-spec build_chain_rules(binary(), map(), map()) -> [fun()].
build_chain_rules(Table, ChainConfig, Config) ->
    Name = maps:get(name, ChainConfig),
    Rules = maps:get(rules, ChainConfig, []),
    lists:flatten([build_rule(Table, Name, Rule, Config) || Rule <- Rules]).

%% --- Internal: Build rule → semantic terms → msg_fun ---

-spec build_rule(binary(), binary(), term(), map()) -> fun() | [fun()].

%% Generic rule from DSL
build_rule(Table, Chain, {rule, Verdict, Opts}, _Config) ->
    Exprs = erlkoenig_firewall_nft:compile_generic_rule(Verdict, Opts),
    encode_rule(Table, Chain, Exprs);

%% Simple rules → single term list → single msg_fun
build_rule(Table, Chain, ct_established_accept, _Config) ->
    encode_rule(Table, Chain, nft_rules:ct_established_accept());
build_rule(Table, Chain, iif_accept, _Config) ->
    encode_rule(Table, Chain, nft_rules:iif_accept());
build_rule(Table, Chain, icmp_accept, _Config) ->
    encode_rule(Table, Chain, nft_rules:icmp_accept());
build_rule(Table, Chain, {icmp_accept_named, Counter}, _Config) ->
    encode_rule(Table, Chain, nft_rules:icmp_accept_named(counter_name(Counter)));
build_rule(Table, Chain, icmpv6_accept, _Config) ->
    encode_rule(Table, Chain, nft_rules:icmpv6_accept());
build_rule(Table, Chain, accept, _Config) ->
    encode_rule(Table, Chain, [nft_expr_ir:accept()]);
%% TCP/UDP with named counter
build_rule(Table, Chain, {tcp_accept, Port, Counter}, _Config) ->
    encode_rule(Table, Chain, nft_rules:tcp_accept_named(Port, counter_name(Counter)));
build_rule(Table, Chain, {udp_accept, Port, Counter}, _Config) ->
    encode_rule(Table, Chain, nft_rules:udp_accept_named(Port, counter_name(Counter)));
%% TCP with rate limit → returns list of two rules → list of msg_funs
build_rule(Table, Chain, {tcp_accept_limited, Port, Counter, LimitOpts}, _Config) ->
    RuleTerms = nft_rules:tcp_accept_limited(Port, counter_name(Counter), LimitOpts),
    [encode_rule(Table, Chain, R) || R <- RuleTerms];
%% TCP/UDP without counter
build_rule(Table, Chain, {tcp_accept, Port}, _Config) ->
    encode_rule(Table, Chain, nft_rules:tcp_accept(Port));
build_rule(Table, Chain, {udp_accept, Port}, _Config) ->
    encode_rule(Table, Chain, nft_rules:udp_accept(Port));
%% Protocol accept
build_rule(Table, Chain, {protocol_accept, Proto}, _Config) ->
    encode_rule(Table, Chain, nft_rules:protocol_accept(Proto));
%% Set lookup with named counter — resolve set type from config
build_rule(Table, Chain, {set_lookup_drop, SetName, Counter}, Config) ->
    SetType = set_type_from_config(Config, SetName),
    encode_rule(
        Table,
        Chain,
        nft_rules:set_lookup_drop_named(SetName, counter_name(Counter), SetType)
    );
%% Set lookup without counter — resolve set type from config
build_rule(Table, Chain, {set_lookup_drop, SetName}, Config) ->
    SetType = set_type_from_config(Config, SetName),
    encode_rule(Table, Chain, nft_rules:set_lookup_drop(SetName, SetType));
%% Set lookup accept — accept if source IP is in set
build_rule(Table, Chain, {set_lookup_accept, SetName}, Config) ->
    SetType = set_type_from_config(Config, SetName),
    encode_rule(Table, Chain, nft_rules:set_lookup_accept(SetName, SetType));
%% Set lookup TCP accept — accept if TCP dport is in set (inet_service)
build_rule(Table, Chain, {set_lookup_accept_tcp, SetName}, _Config) ->
    encode_rule(Table, Chain, nft_rules:set_lookup_tcp_accept(SetName));
%% Set lookup UDP accept (WireGuard SPA allowlist)
build_rule(Table, Chain, {set_lookup_udp_accept, SetName, Port}, Config) ->
    SetType = set_type_from_config(Config, SetName),
    encode_rule(Table, Chain, nft_rules:set_lookup_udp_accept(SetName, Port, SetType));
%% NFLOG capture + drop (SPA packet capture)
build_rule(Table, Chain, {nflog_capture_udp, Port, Prefix, Group}, _Config) ->
    encode_rule(Table, Chain, nft_rules:nflog_capture_udp(Port, Prefix, Group));
%% Log drop with named counter
build_rule(Table, Chain, {log_drop, Prefix, Counter}, _Config) ->
    encode_rule(Table, Chain, nft_rules:log_drop_named(Prefix, counter_name(Counter)));
build_rule(Table, Chain, {log_drop_nflog, Prefix, Group, Counter}, _Config) ->
    encode_rule(Table, Chain, nft_rules:log_drop_nflog(Prefix, Group, counter_name(Counter)));
%% Log drop without counter
build_rule(Table, Chain, {log_drop, Prefix}, _Config) ->
    encode_rule(Table, Chain, nft_rules:log_drop(Prefix));
%% Accept on named interface (e.g. <<"wg0">>, <<"eth0">>)
build_rule(Table, Chain, {iifname_accept, Name}, _Config) ->
    encode_rule(Table, Chain, nft_rules:iifname_accept(Name));
%% TCP reject with RST
build_rule(Table, Chain, {tcp_reject, Port}, _Config) ->
    encode_rule(Table, Chain, nft_rules:tcp_reject(Port));
%% TCP/UDP port range accept
build_rule(Table, Chain, {tcp_port_range_accept, From, To}, _Config) ->
    encode_rule(Table, Chain, nft_rules:tcp_port_range_accept(From, To));
build_rule(Table, Chain, {udp_port_range_accept, From, To}, _Config) ->
    encode_rule(Table, Chain, nft_rules:udp_port_range_accept(From, To));
%% Rate-limited UDP accept
build_rule(Table, Chain, {udp_accept_limited, Port, Counter, LimitOpts}, _Config) ->
    RuleTerms = nft_rules:udp_accept_limited(Port, counter_name(Counter), LimitOpts),
    [encode_rule(Table, Chain, R) || R <- RuleTerms];
%% Accept/drop from specific source IP
build_rule(Table, Chain, {ip_saddr_accept, IP}, _Config) ->
    {ok, Bin} = erlkoenig_nft_ip:normalize(IP),
    encode_rule(Table, Chain, nft_rules:ip_saddr_accept(Bin));
build_rule(Table, Chain, {ip_saddr_drop, IP}, _Config) ->
    {ok, Bin} = erlkoenig_nft_ip:normalize(IP),
    encode_rule(Table, Chain, nft_rules:ip_saddr_drop(Bin));
%% Connection limit per IP
build_rule(Table, Chain, {connlimit_drop, Count, Flags}, _Config) ->
    encode_rule(Table, Chain, nft_rules:connlimit_drop(Count, Flags));
%% Log and reject (ICMP unreachable instead of silent drop)
build_rule(Table, Chain, {log_reject, Prefix}, _Config) ->
    encode_rule(Table, Chain, nft_rules:log_reject(Prefix));
%% Forward chain: accept established/related
build_rule(Table, Chain, forward_established, _Config) ->
    encode_rule(Table, Chain, nft_rules:forward_established());
%% NAT: masquerade outgoing traffic
build_rule(Table, Chain, masq, _Config) ->
    encode_rule(Table, Chain, nft_rules:masq_rule());
%% Unconditional jump to regular chain
build_rule(Table, Chain, {jump, Target}, _Config) ->
    encode_rule(Table, Chain, [nft_expr_ir:jump(ensure_binary(Target))]);
%% Jump to chain on input interface
build_rule(Table, Chain, {iifname_jump, Name, Target}, _Config) ->
    encode_rule(
        Table,
        Chain,
        nft_rules:iifname_jump(
            ensure_binary(Name), ensure_binary(Target)
        )
    );
%% Accept on output interface
build_rule(Table, Chain, {oifname_accept, Name}, _Config) ->
    encode_rule(Table, Chain, nft_rules:oifname_accept(ensure_binary(Name)));
%% Masquerade on output interface != Name
build_rule(Table, Chain, {oifname_neq_masq, Name}, _Config) ->
    encode_rule(Table, Chain, nft_rules:oifname_neq_masq(ensure_binary(Name)));
%% Jump on input+output interface pair
build_rule(Table, Chain, {iifname_oifname_jump, InIf, OutIf, Target}, _Config) ->
    encode_rule(
        Table,
        Chain,
        nft_rules:iifname_oifname_jump(
            ensure_binary(InIf), ensure_binary(OutIf), ensure_binary(Target)
        )
    );
%% Masquerade on input+output interface pair
build_rule(Table, Chain, {iifname_oifname_masq, InIf, OutIf}, _Config) ->
    encode_rule(
        Table,
        Chain,
        nft_rules:iifname_oifname_masq(
            ensure_binary(InIf), ensure_binary(OutIf)
        )
    );
%% Verdict map dispatch
build_rule(Table, Chain, {vmap_dispatch, Proto, VmapName}, _Config) ->
    encode_rule(Table, Chain, nft_rules:vmap_dispatch(Proto, ensure_binary(VmapName)));
%% NAT: destination NAT to internal IP:Port
build_rule(Table, Chain, {dnat, IP, Port}, _Config) ->
    {ok, Bin} = erlkoenig_nft_ip:normalize(IP),
    encode_rule(Table, Chain, nft_rules:dnat_rule(Bin, Port));
%% NAT: DNAT TCP traffic on MatchPort to DstIp:DstPort
build_rule(Table, Chain, {tcp_dnat, MatchPort, DstIp, DstPort}, _Config) ->
    {ok, Bin} = erlkoenig_nft_ip:normalize(DstIp),
    encode_rule(Table, Chain, nft_rules:tcp_dnat(MatchPort, Bin, DstPort));
%% NAT: SNAT (rewrite source address)
build_rule(Table, Chain, {snat, IP, Port}, _Config) ->
    {ok, Bin} = erlkoenig_nft_ip:normalize(IP),
    encode_rule(Table, Chain, nft_rules:snat_rule(Bin, Port));
%% Conntrack mark: set ct mark on matching packets
build_rule(Table, Chain, {ct_mark_set, Value}, _Config) ->
    encode_rule(Table, Chain, nft_rules:ct_mark_set(Value));
%% Conntrack mark: match ct mark and apply verdict
build_rule(Table, Chain, {ct_mark_match, Value, Verdict}, _Config) ->
    encode_rule(Table, Chain, nft_rules:ct_mark_match(Value, Verdict));
%% Notrack: skip conntrack for specific port/proto (used in raw chains)
build_rule(Table, Chain, {notrack, Port, Proto}, _Config) ->
    encode_rule(Table, Chain, nft_rules:notrack_rule(Port, Proto));
%% Meter limit: per-source rate limiting via named set
build_rule(Table, Chain, {meter_limit, SetName, Port, Proto, Opts}, _Config) ->
    OptsMap = maps:from_list(Opts),
    encode_rule(Table, Chain, nft_rules:meter_limit(ensure_binary(SetName), Port, Proto, OptsMap));
%% Flow offload: hardware acceleration for established flows
build_rule(Table, Chain, {flow_offload, FlowtableName}, _Config) ->
    encode_rule(Table, Chain, nft_rules:flow_offload(ensure_binary(FlowtableName)));
%% OS fingerprint match
build_rule(Table, Chain, {osf_match, OsName, Verdict}, _Config) ->
    encode_rule(Table, Chain, nft_rules:osf_match(ensure_binary(OsName), Verdict));
%% SYN proxy: filter rule for synproxy (matches ct state invalid|untracked)
build_rule(Table, Chain, {synproxy, Port, MSS, WScale, _Flags}, _Config) ->
    encode_rule(
        Table, Chain, nft_rules:synproxy_filter_rule(Port, #{mss => MSS, wscale => WScale})
    );
%% FIB reverse-path filter (anti-spoofing)
build_rule(Table, Chain, fib_rpf_drop, _Config) ->
    encode_rule(Table, Chain, nft_rules:fib_rpf_drop());
%% NFQUEUE: send matching packets to userspace
build_rule(Table, Chain, {queue_rule, Port, Proto, Opts}, _Config) ->
    OptsMap = maps:from_list(Opts),
    encode_rule(Table, Chain, nft_rules:queue_rule(Port, Proto, OptsMap));
%% Concatenated set lookup (multi-field match)
build_rule(Table, Chain, {concat_set_lookup, SetName, Fields, Verdict}, _Config) ->
    encode_rule(Table, Chain, nft_rules:concat_set_lookup(ensure_binary(SetName), Fields, Verdict)).

%% --- Internal: Encode a semantic rule to a msg_fun ---

-spec encode_rule(binary(), binary(), [{atom(), map()}, ...]) ->
    fun((non_neg_integer()) -> <<_:64, _:_*8>>).
encode_rule(Table, Chain, ExprTerms) ->
    nft_encode:rule_fun(inet, Table, Chain, ExprTerms).

%% --- Internal: Thresholds ---

-spec build_thresholds(binary(), [tuple()]) -> [map()].
build_thresholds(CounterName, Thresholds) ->
    lists:filtermap(
        fun({Id, Counter, Metric, Op, Value}) ->
            case counter_name(Counter) of
                CounterName ->
                    {true, #{
                        id => Id,
                        metric => Metric,
                        op => Op,
                        value => Value,
                        action => default_action(Id)
                    }};
                _ ->
                    false
            end
        end,
        Thresholds
    ).

%% --- Internal: Diff live ---

-spec compute_diff(map()) ->
    [
        #{
            type := extra_chain | missing_chain | missing_set | set_elements,
            chain => term(),
            config_count => non_neg_integer(),
            detail => <<_:184, _:_*32>>,
            kernel_count => integer(),
            set => binary()
        }
    ].
compute_diff(Config) ->
    Table = maps:get(table, Config),
    ConfigChains = [maps:get(name, C) || C <- maps:get(chains, Config, [])],
    ConfigSets = [
        set_name(S)
     || S <- maps:get(sets, Config, []),
        set_name(S) =/= undefined
    ],

    %% Query kernel for chains
    KernelChains =
        case nfnl_server:list_chains(erlkoenig_nft_srv, ?INET, Table) of
            {ok, KC} -> [maps:get(name, C, undefined) || C <- KC];
            {error, _} -> []
        end,

    %% Chain diffs
    ChainDiffs = chain_diffs(ConfigChains, KernelChains),

    %% Set element diffs
    SetDiffs = lists:flatmap(
        fun(SetName) ->
            ConfigCount =
                case
                    lists:keyfind(
                        SetName,
                        1,
                        [{set_name(S), S} || S <- maps:get(sets, Config, [])]
                    )
                of
                    {_, {_, _, #{elements := Elems}}} -> length(Elems);
                    _ -> 0
                end,
            KernelCount =
                case
                    nfnl_server:list_set_elems(
                        erlkoenig_nft_srv, ?INET, Table, SetName
                    )
                of
                    {ok, KE} -> length(KE);
                    {error, _} -> -1
                end,
            if
                KernelCount =:= -1 ->
                    [
                        #{
                            type => missing_set,
                            set => SetName,
                            detail => <<"set not found in kernel">>
                        }
                    ];
                KernelCount =/= ConfigCount ->
                    [
                        #{
                            type => set_elements,
                            set => SetName,
                            config_count => ConfigCount,
                            kernel_count => KernelCount
                        }
                    ];
                true ->
                    []
            end
        end,
        ConfigSets
    ),

    ChainDiffs ++ SetDiffs.

-spec chain_diffs([binary()], [binary()]) -> [map()].
chain_diffs(ConfigChains, KernelChains) ->
    Missing = [
        #{
            type => missing_chain,
            chain => C,
            detail => <<"in config but not in kernel">>
        }
     || C <- ConfigChains, not lists:member(C, KernelChains)
    ],
    Extra = [
        #{
            type => extra_chain,
            chain => C,
            detail => <<"in kernel but not in config">>
        }
     || C <- KernelChains, not lists:member(C, ConfigChains)
    ],
    Missing ++ Extra.

%% --- Internal: Set element operations ---

-spec do_set_elem_op(map(), binary(), binary() | string(), add | del) ->
    ok | {error, term()}.
do_set_elem_op(Config, SetName, Value, Op) ->
    Sets = maps:get(sets, Config, []),
    maybe
        {ok, SetSpec} ?=
            case find_set_by_name(Sets, SetName) of
                {ok, _} = OK -> OK;
                error -> {error, {no_such_set, SetName}}
            end,
        Type = set_type(SetSpec),
        {ok, Bin} ?= normalize_value(Value, Type),
        Table = maps:get(table, Config),
        MsgFun =
            case Op of
                add -> fun(S) -> nft_set_elem:add(?INET, Table, SetName, Bin, S) end;
                del -> fun(S) -> nft_set_elem:del(?INET, Table, SetName, Bin, S) end
            end,
        nfnl_server:apply_msgs(erlkoenig_nft_srv, [MsgFun])
    else
        {error, _} = Err -> Err
    end.

-spec find_set_by_name([tuple()], binary()) -> {ok, tuple()} | error.
find_set_by_name([], _Name) ->
    error;
find_set_by_name([S | Rest], Name) ->
    case set_name(S) of
        Name -> {ok, S};
        _ -> find_set_by_name(Rest, Name)
    end.

-spec format_set_info({term(), term()} | {term(), term(), map()}) ->
    #{name := term(), type := term(), flags => term()}.
format_set_info({Name, Type}) ->
    #{name => Name, type => Type};
format_set_info({Name, Type, Opts}) ->
    Base = #{name => Name, type => Type},
    case maps:get(flags, Opts, undefined) of
        undefined -> Base;
        Flags -> Base#{flags => Flags}
    end.

-spec normalize_value(binary() | string(), atom()) -> {ok, binary()} | {error, term()}.
normalize_value(Value, ipv4_addr) ->
    erlkoenig_nft_ip:normalize(Value);
normalize_value(Value, ipv6_addr) ->
    erlkoenig_nft_ip:normalize(Value);
normalize_value(Value, inet_service) ->
    try
        Port =
            case Value of
                V when is_binary(V) -> binary_to_integer(V);
                V when is_list(V) -> list_to_integer(V);
                V when is_integer(V) -> V
            end,
        case Port >= 0 andalso Port =< 65535 of
            true -> {ok, <<Port:16/big>>};
            false -> {error, {invalid_port, Value}}
        end
    catch
        _:_ ->
            {error, {invalid_port, Value}}
    end;
normalize_value(Value, _Type) when is_binary(Value) ->
    {ok, Value};
normalize_value(Value, _Type) when is_list(Value) ->
    {ok, list_to_binary(Value)};
normalize_value(Value, _Type) ->
    {error, {cannot_normalize, Value}}.

%% --- Internal: Helpers ---

-spec counter_name(atom() | binary()) -> binary().
counter_name(Name) when is_binary(Name) -> Name;
counter_name(Name) when is_atom(Name) -> atom_to_binary(Name).

-spec quota_name(#{name := atom() | binary(), _ => _}) -> binary().
quota_name(#{name := Name}) when is_binary(Name) -> Name;
quota_name(#{name := Name}) when is_atom(Name) -> atom_to_binary(Name).

-spec with_index([T]) -> [{pos_integer(), T}].
with_index(List) ->
    lists:zip(lists:seq(1, length(List)), List).

-spec get_ban_duration(map()) -> non_neg_integer().
get_ban_duration(Config) ->
    CtGuard = maps:get(ct_guard, Config, #{}),
    maps:get(ban_duration, CtGuard, 3600).

-spec blocklist_name(map(), binary()) -> {ok, binary()} | {error, no_matching_set}.
blocklist_name(Config, IPBin) ->
    Sets = maps:get(sets, Config, []),
    TargetType =
        case erlkoenig_nft_ip:version(IPBin) of
            v4 -> ipv4_addr;
            v6 -> ipv6_addr
        end,
    case
        [
            Name
         || S <- Sets,
            set_name(S) =/= undefined,
            set_type(S) =:= TargetType,
            Name <- [set_name(S)],
            not is_allowlist(Name)
        ]
    of
        [First | _] -> {ok, First};
        [] -> {error, no_matching_set}
    end.

-spec set_type_from_config(map(), binary()) -> ipv4_addr | ipv6_addr.
set_type_from_config(Config, SetName) ->
    Sets = maps:get(sets, Config, []),
    case lists:keyfind(SetName, 1, Sets) of
        {_, Type} -> Type;
        {_, Type, _} -> Type;
        false -> ipv4_addr
    end.

%% Extract name/type from 2-tuple or 3-tuple set specs
-spec set_name(tuple()) -> binary() | undefined.
set_name({Name, _Type}) -> Name;
set_name({Name, _Type, _Opts}) -> Name;
set_name(_) -> undefined.

-spec set_type(tuple()) -> atom().
set_type({_Name, Type}) -> Type;
set_type({_Name, Type, _Opts}) -> Type;
set_type(_) -> undefined.

-spec is_allowlist(binary()) -> boolean().
is_allowlist(Name) ->
    binary:match(Name, <<"allow">>) =/= nomatch.

%% --- Internal: Build initial set elements ---

-spec build_set_elems(binary(), tuple()) -> [fun()].
build_set_elems(Table, {SetName, SetType, #{elements := Elements}}) when
    is_list(Elements), Elements =/= []
->
    Keys = normalize_set_elements(Elements, SetType),
    [fun(S) -> nft_set_elem:add_elems(?INET, Table, ensure_binary(SetName), Keys, S) end];
build_set_elems(_Table, _SetSpec) ->
    [].

-spec normalize_set_elements([term()], atom()) -> [binary()].
normalize_set_elements(Elements, ipv4_addr) ->
    [
        begin
            {ok, Bin} = erlkoenig_nft_ip:normalize(E),
            Bin
        end
     || E <- Elements
    ];
normalize_set_elements(Elements, ipv6_addr) ->
    [
        begin
            {ok, Bin} = erlkoenig_nft_ip:normalize(E),
            Bin
        end
     || E <- Elements
    ];
normalize_set_elements(Elements, inet_service) ->
    [<<Port:16/big>> || Port <- Elements];
normalize_set_elements(Elements, _Type) ->
    Elements.

%% --- Internal: Build verdict map ---

-spec build_vmap(binary(), map(), pos_integer()) -> [fun()].
build_vmap(Table, VmapConfig, Idx) ->
    Name = ensure_binary(maps:get(name, VmapConfig)),
    Type = maps:get(type, VmapConfig),
    Entries = maps:get(entries, VmapConfig, []),

    CreateMsg = fun(S) ->
        nft_set:add_vmap(
            ?INET,
            #{table => Table, name => Name, type => Type},
            Idx,
            S
        )
    end,

    case Entries of
        [] ->
            [CreateMsg];
        _ ->
            NlEntries = [normalize_vmap_entry(E, Type) || E <- Entries],
            ElemMsg = fun(S) ->
                nft_set_elem:add_vmap_elems(
                    ?INET, Table, Name, NlEntries, S
                )
            end,
            [CreateMsg, ElemMsg]
    end.

-spec normalize_vmap_entry(tuple(), atom()) -> {binary(), atom() | {atom(), binary()}}.
normalize_vmap_entry({Key, Verdict}, inet_service) when is_integer(Key) ->
    {<<Key:16/big>>, normalize_verdict(Verdict)};
normalize_vmap_entry({Key, Verdict}, ipv4_addr) ->
    {ok, Bin} = erlkoenig_nft_ip:normalize(Key),
    {Bin, normalize_verdict(Verdict)};
normalize_vmap_entry({Key, Verdict}, ipv6_addr) ->
    {ok, Bin} = erlkoenig_nft_ip:normalize(Key),
    {Bin, normalize_verdict(Verdict)};
normalize_vmap_entry({Key, Verdict}, _Type) when is_binary(Key) ->
    {Key, normalize_verdict(Verdict)}.

-spec normalize_verdict(
    accept | drop | {jump, atom() | binary() | string()} | {goto, atom() | binary() | string()}
) -> accept | drop | {jump, binary()} | {goto, binary()}.
normalize_verdict(accept) -> accept;
normalize_verdict(drop) -> drop;
normalize_verdict({jump, Chain}) -> {jump, ensure_binary(Chain)};
normalize_verdict({goto, Chain}) -> {goto, ensure_binary(Chain)}.

-spec ensure_binary(binary() | list() | atom()) -> binary().
ensure_binary(B) when is_binary(B) -> B;
ensure_binary(L) when is_list(L) -> list_to_binary(L);
ensure_binary(A) when is_atom(A) -> atom_to_binary(A).

build_set_msg(Table, {SetName, concat, Extra}, Idx, Seq) ->
    Opts = maps:merge(
        #{table => Table, name => SetName, id => Idx}, maps:without([elements], Extra)
    ),
    nft_set:add_concat(?INET, Opts, Seq);
build_set_msg(Table, SetSpec, Idx, Seq) ->
    nft_set:add(?INET, set_opts(Table, SetSpec, Idx), Seq).

-spec set_opts(binary(), tuple(), pos_integer()) -> nft_set:set_opts().
set_opts(Table, {SetName, SetType}, Idx) ->
    #{table => Table, name => SetName, type => SetType, id => Idx};
set_opts(Table, {SetName, SetType, Extra}, Idx) ->
    Base = #{table => Table, name => SetName, type => SetType, id => Idx},
    maps:merge(Base, maps:without([elements], Extra)).

config_path() ->
    erlkoenig_nft_config:config_path().

-spec default_config() ->
    #{
        chains := [
            #{
                hook := forward | input | output | prerouting,
                name := <<_:40, _:_*8>>,
                policy := accept,
                priority := -300 | 0,
                rules := [any()],
                type := filter
            },
            ...
        ],
        counters := [banned | dropped | forward | input | output, ...],
        sets := [{<<_:64, _:_*8>>, ipv4_addr | ipv6_addr, map()}, ...],
        table := <<_:72>>
    }.
default_config() ->
    #{
        table => <<"erlkoenig">>,
        sets => [
            {<<"blocklist">>, ipv4_addr, #{flags => [timeout]}},
            {<<"blocklist6">>, ipv6_addr, #{flags => [timeout]}}
        ],
        counters => [input, forward, output, dropped, banned],
        chains => [
            #{
                name => <<"prerouting_ban">>,
                hook => prerouting,
                type => filter,
                priority => -300,
                policy => accept,
                rules => [
                    {set_lookup_drop, <<"blocklist">>, banned},
                    {set_lookup_drop, <<"blocklist6">>, banned}
                ]
            },
            #{
                name => <<"input">>,
                hook => input,
                type => filter,
                priority => 0,
                policy => accept,
                rules => []
            },
            #{
                name => <<"forward">>,
                hook => forward,
                type => filter,
                priority => 0,
                policy => accept,
                rules => []
            },
            #{
                name => <<"output">>,
                hook => output,
                type => filter,
                priority => 0,
                policy => accept,
                rules => []
            }
        ]
    }.

-spec collect_rates() -> #{binary() => map()}.
collect_rates() ->
    Children = supervisor:which_children(erlkoenig_nft_watch_sup),
    lists:foldl(
        fun
            ({_, Pid, _, _}, Acc) when is_pid(Pid) ->
                try gen_server:call(Pid, get_rates, 1000) of
                    Rate when is_map(Rate) ->
                        Name = maps:get(name, Rate, undefined),
                        case Name of
                            undefined -> Acc;
                            _ -> Acc#{Name => Rate}
                        end;
                    _ ->
                        Acc
                catch
                    _:_ -> Acc
                end;
            (_, Acc) ->
                Acc
        end,
        #{},
        Children
    ).

-spec counter_count() -> non_neg_integer().
counter_count() ->
    length(supervisor:which_children(erlkoenig_nft_watch_sup)).

-spec default_action(term()) -> fun((term(), term(), term(), term()) -> ok).
default_action(Id) ->
    fun(Name, Metric, Val, Thresh) ->
        logger:warning(
            "[erlkoenig_nft:~p] ~s ~p=~.1f exceeds ~.1f",
            [Id, Name, Metric, Val, Thresh]
        )
    end.
