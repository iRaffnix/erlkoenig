#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% Bug #2 bisect: narrow down WHICH primitive combination in
%% tutorial 03 makes the nft-batch fail with {-2, enoent}.
%%
%% Strategy: load tutorial 03, then iteratively strip ONE
%% primitive at a time and observe whether the batch
%% apply succeeds.  The first variant that passes reveals
%% the offending primitive.  The minimal-failing subset
%% reveals the root cause.
%%
%% Run: sudo ./tests/integration/bisect_tut03.escript

-mode(compile).

-define(PARENT, <<"ek_bisect">>).
-define(GW_CIDR, "10.30.0.1/24").

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Bug #2 Bisect: Tutorial 03 batch-ENOENT ===~n~n"),

    case string:trim(os:cmd("id -u")) of
        "0" -> ok;
        _   -> io:format("ERROR: must run as root~n"), halt(1)
    end,

    test_helper:boot(),
    logger:set_primary_config(level, notice),

    Root     = test_helper:project_root(),
    Example  = filename:join(Root, "examples/tutorial/03_firewall.exs"),
    TermFile = "/tmp/bisect_tut03.term",
    DemoBin  = test_helper:demo("echo_server"),

    tutorial_helper:cleanup_all(),
    tutorial_helper:cleanup_dummy(?PARENT),
    tutorial_helper:ensure_dummy(?PARENT, ?GW_CIDR),

    %% Compile once, load the term for mutation
    ok = tutorial_helper:compile_dsl(Root, Example, TermFile),
    {ok, BaseConfig} = erlkoenig_config:parse(TermFile),

    io:format("Base primitives present:~n"),
    [Table] = maps:get(nft_tables, BaseConfig),
    dump_primitives(Table),

    %% Variants to try — each removes ONE class of primitives
    Variants = [
        {"Z_BASELINE_(as-declared)", fun(T) -> T end},
        {"a_no_flowtables",    fun(T) -> T#{flowtables => []} end},
        {"b_no_vmaps",         fun(T) -> T#{vmaps => []} end},
        {"c_no_maps",          fun(T) -> T#{maps => []} end},
        {"d_no_sets",          fun(T) -> T#{sets => []} end},
        {"e_no_counters",      fun(T) -> T#{counters => []} end},
        %% finer: keep all but remove vmap_dispatch rule from input chain
        {"f_no_vmap_rule",     fun strip_vmap_dispatch_rule/1},
        %% finer: remove flow_offload rule from forward chain
        {"g_no_flow_offload",  fun strip_flow_offload_rule/1},
        %% finer: remove CIDR set (keep basic ban set)
        {"h_no_cidr_set",      fun strip_cidr_set/1},
        %% finer: remove log_prefix from drop rules
        {"i_no_log_prefix",    fun strip_log_prefix/1},
        %% finer: keep ONLY sets+counters+empty chains (no rules)
        {"j_only_containers",  fun keep_shell_only/1}
    ],

    patch_pods(BaseConfig, iolist_to_binary(DemoBin), ?PARENT, TermFile),
    {ok, BaseAfterPatch} = erlkoenig_config:parse(TermFile),

    lists:foreach(fun({Label, Fun}) ->
        io:format("~n---- variant: ~s ----~n", [Label]),
        tutorial_helper:cleanup_all(),
        flush_ruleset(),

        %% Apply the variant to the base config's first table
        [T | _Rest] = maps:get(nft_tables, BaseAfterPatch),
        T2 = Fun(T),
        Mutated = BaseAfterPatch#{nft_tables => [T2]},
        ok = file:write_file(TermFile, io_lib:format("~tp.~n", [Mutated])),

        Outcome = try_load(TermFile),
        HostTable = os:cmd("nft list table inet host 2>&1"),
        KernelOk =
            re:run(HostTable, "error:", [{capture, none}]) =/= match andalso
            not is_table_empty(HostTable),

        io:format("  load outcome  : ~p~n", [Outcome]),
        io:format("  kernel table  : ~s~n",
                  [if KernelOk -> "populated"; true -> "EMPTY" end]),
        count_kernel_primitives(HostTable)
    end, Variants),

    tutorial_helper:cleanup_all(),
    tutorial_helper:cleanup_dummy(?PARENT),
    file:delete(TermFile),
    io:format("~n=== bisect done ===~n"),
    halt(0).

%% ─── variant transformers ───────────────────────────────────────

strip_vmap_dispatch_rule(Table) ->
    Chains = maps:get(chains, Table, []),
    NewChains = [strip_rule_kind(C, vmap_dispatch) || C <- Chains],
    Table#{chains => NewChains}.

strip_flow_offload_rule(Table) ->
    Chains = maps:get(chains, Table, []),
    NewChains = [strip_rule_kind(C, flow_offload) || C <- Chains],
    Table#{chains => NewChains}.

strip_cidr_set(Table) ->
    Sets = maps:get(sets, Table, []),
    NewSets = [S || S <- Sets, not is_cidr_set(S)],
    Table#{sets => NewSets}.

is_cidr_set({_Name, _Type, #{flags := Flags}}) ->
    lists:member(interval, Flags);
is_cidr_set(_) ->
    false.

strip_log_prefix(Table) ->
    Chains = maps:get(chains, Table, []),
    NewChains = [strip_opt(C, log_prefix) || C <- Chains],
    Table#{chains => NewChains}.

keep_shell_only(Table) ->
    Chains = maps:get(chains, Table, []),
    NewChains = [C#{rules => []} || C <- Chains],
    Table#{chains => NewChains}.

strip_rule_kind(Chain, Kind) ->
    Rules = maps:get(rules, Chain, []),
    NewRules = [R || {Verdict, _} = R <- Rules, Verdict =/= Kind],
    Chain#{rules => NewRules}.

strip_opt(Chain, OptKey) ->
    Rules = maps:get(rules, Chain, []),
    NewRules = [{V, maps:without([OptKey], O)} || {V, O} <- Rules],
    Chain#{rules => NewRules}.

%% ─── helpers ────────────────────────────────────────────────────

patch_pods(Config, BinPath, Parent, TermFile) ->
    Pods = maps:get(pods, Config, []),
    NewPods = [patch_pod(P, BinPath) || P <- Pods],
    Host = maps:get(host, Config, #{}),
    Zones = maps:get(zones, Config, []),
    Remap = fun(#{network := #{parent := _} = Net} = M) ->
        M#{network => Net#{parent => Parent}};
        (M) -> M
    end,
    Patched = Config#{pods => NewPods,
                      host => Remap(Host),
                      zones => [Remap(Z) || Z <- Zones]},
    file:write_file(TermFile, io_lib:format("~tp.~n", [Patched])),
    ok.

patch_pod(Pod, BinPath) ->
    Cts = maps:get(containers, Pod, []),
    Pod#{containers => [C#{binary => BinPath} || C <- Cts]}.

try_load(TermFile) ->
    case catch erlkoenig_config:load(TermFile) of
        {ok, _} -> ok;
        {'EXIT', Reason} -> {exit, Reason};
        Other -> Other
    end.

flush_ruleset() ->
    os:cmd("nft flush ruleset 2>/dev/null"),
    timer:sleep(100),
    ok.

is_table_empty(Out) ->
    case re:run(Out, "table inet host \\{\\s*\\}", [{capture, none}]) of
        match -> true;
        _ -> false
    end.

count_kernel_primitives(Out) ->
    C = count_matches(Out, "counter [a-z_]+"),
    S = count_matches(Out, "set [a-z_]+"),
    M = count_matches(Out, "map [a-z_]+"),
    F = count_matches(Out, "flowtable [a-z_]+"),
    Ch = count_matches(Out, "chain [a-z_]+"),
    io:format("  counters=~p sets=~p maps=~p flowtables=~p chains=~p~n",
              [C, S, M, F, Ch]).

count_matches(Str, Pat) ->
    case re:run(Str, Pat, [global, {capture, none}]) of
        {match, L} -> length(L);
        _ -> 0
    end.

dump_primitives(T) ->
    Counters = maps:get(counters, T, []),
    Sets = maps:get(sets, T, []),
    Maps_ = maps:get(maps, T, []),
    VMaps = maps:get(vmaps, T, []),
    FTs = maps:get(flowtables, T, []),
    Chains = maps:get(chains, T, []),
    io:format("  counters  : ~p~n", [Counters]),
    io:format("  sets      : ~p~n", [[set_label(S) || S <- Sets]]),
    io:format("  maps      : ~p~n", [[M || #{name := M} <- Maps_]]),
    io:format("  vmaps     : ~p~n", [[M || #{name := M} <- VMaps]]),
    io:format("  flowtables: ~p~n", [[M || #{name := M} <- FTs]]),
    io:format("  chains    : ~p~n",
              [[{maps:get(name, C), length(maps:get(rules, C, []))}
                || C <- Chains]]).

set_label({Name, _Type}) -> Name;
set_label({Name, _Type, _Meta}) -> {Name, cidr}.
