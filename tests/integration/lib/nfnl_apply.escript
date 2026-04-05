#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% Apply a .term config via nfnl_server + nft modules.
%% Supports two formats:
%%   - Legacy: #{table => ..., chains => [...]}
%%   - New (ADR-0015): #{nft_tables => [...]}
%%
%% Usage: escript nfnl_apply.escript <rootdir> <config.term>

main([RootDir, TermFile]) ->
    %% Add all ebin paths from the release
    Paths = filelib:wildcard(RootDir ++ "/lib/*/ebin"),
    [code:add_pathz(P) || P <- Paths],

    %% Pre-load all nft_expr_*_gen modules (used via list_to_existing_atom)
    [code:load_file(list_to_atom(filename:basename(F, ".beam")))
     || P <- Paths, F <- filelib:wildcard(P ++ "/nft_expr_*_gen.beam")],

    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = pg:start_link(erlkoenig_nft),
    {ok, [Config]} = file:consult(TermFile),
    {ok, Srv} = nfnl_server:start_link(),
    register(erlkoenig_nft_srv, Srv),

    case maps:find(nft_tables, Config) of
        {ok, NftTables} -> apply_nft_tables(NftTables);
        error           -> apply_legacy(Config)
    end;

main(_) ->
    io:format(standard_error, "Usage: nfnl_apply.escript <rootdir> <config.term>~n", []),
    halt(1).

%% ═══════════════════════════════════════════════════════════════
%% New format: nft_tables (ADR-0015)
%% ═══════════════════════════════════════════════════════════════

apply_nft_tables(Tables) ->
    lists:foreach(fun(TableDef) ->
        Table = iolist_to_binary(maps:get(name, TableDef, <<"fw">>)),
        Chains = maps:get(chains, TableDef, []),
        Counters = maps:get(counters, TableDef, []),

        ok = nfnl_server:apply_msgs(erlkoenig_nft_srv, [
            fun(S) -> nft_table:add(1, Table, S) end
        ]),

        %% Counters
        case Counters of
            [] -> ok;
            _ -> nfnl_server:apply_msgs(erlkoenig_nft_srv, [fun(S) ->
                    nft_object:add_counter(1, Table, iolist_to_binary(N), S)
                 end || N <- Counters])
        end,

        %% Sets (new format: list of {Name, Type} | {Name, Type, Opts})
        Sets = maps:get(sets, TableDef, []),
        SetTypes = lists:foldl(fun
            ({Name, Type}, Acc) -> Acc#{iolist_to_binary(Name) => Type};
            ({Name, Type, _}, Acc) -> Acc#{iolist_to_binary(Name) => Type};
            (_, Acc) -> Acc
        end, #{}, Sets),
        lists:foreach(fun(Spec) -> apply_set(Table, Spec) end, Sets),

        %% Chains: regular first, then base
        Sorted = lists:sort(fun(A, _) -> not maps:is_key(hook, A) end, Chains),
        lists:foreach(fun(C) -> create_chain(Table, C) end, Sorted),

        %% VMaps (after chains for jump targets)
        Vmaps = maps:get(vmaps, TableDef, []),
        lists:foreach(fun(V) -> apply_vmap(Table, V) end, Vmaps),

        %% Rules
        lists:foreach(fun(C) ->
            ChainName = iolist_to_binary(maps:get(name, C)),
            Rules = maps:get(rules, C, []),
            RuleMsgs = lists:flatmap(fun({Action, Opts}) ->
                Rule = enrich_set_rule_generic(Action, Opts, SetTypes),
                compile_and_encode(1, Table, ChainName, Rule)
            end, Rules),
            apply_rule_msgs(RuleMsgs)
        end, Sorted)
    end, Tables),
    halt(0).

%% Enrich generic rules that reference sets with set type info
enrich_set_rule_generic(drop, #{set := SetName} = Opts, SetTypes) ->
    case maps:find(iolist_to_binary(SetName), SetTypes) of
        {ok, ipv6_addr} -> {rule, drop, Opts#{set_type => ipv6_addr}};
        _ -> {rule, drop, Opts}
    end;
enrich_set_rule_generic(Action, Opts, _) ->
    {rule, Action, Opts}.

%% ═══════════════════════════════════════════════════════════════
%% Legacy format: table/chains/sets/vmaps
%% ═══════════════════════════════════════════════════════════════

apply_legacy(Config) ->
    Table = iolist_to_binary(maps:get(table, Config, <<"fw">>)),
    Chains = maps:get(chains, Config, []),

    ok = nfnl_server:apply_msgs(erlkoenig_nft_srv, [
        fun(S) -> nft_table:add(1, Table, S) end
    ]),

    %% Counters
    Counters = maps:get(counters, Config, []),
    case Counters of
        [] -> ok;
        _ -> nfnl_server:apply_msgs(erlkoenig_nft_srv, [fun(S) ->
                nft_object:add_counter(1, Table, iolist_to_binary(N), S)
             end || N <- Counters])
    end,

    %% Sets (track types for IPv6)
    Sets = maps:get(sets, Config, []),
    SetTypes = lists:foldl(fun
        ({Name, Type}, Acc) -> Acc#{iolist_to_binary(Name) => Type};
        ({Name, Type, _}, Acc) -> Acc#{iolist_to_binary(Name) => Type};
        (_, Acc) -> Acc
    end, #{}, Sets),
    lists:foreach(fun(Spec) -> apply_set(Table, Spec) end, Sets),

    %% Phase 1: Create all chains
    Sorted = lists:sort(fun(A, _) -> not maps:is_key(hook, A) end, Chains),
    lists:foreach(fun(C) -> create_chain(Table, C) end, Sorted),

    %% Phase 2: VMaps (after chains for jump targets)
    Vmaps = maps:get(vmaps, Config, []),
    lists:foreach(fun(V) -> apply_vmap(Table, V) end, Vmaps),

    %% Phase 3: Rules
    lists:foreach(fun(C) ->
        ChainName = iolist_to_binary(maps:get(name, C)),
        Rules = maps:get(rules, C, []),
        RuleMsgs = lists:flatmap(fun(Rule) ->
            Rule2 = enrich_set_rule(Rule, SetTypes),
            compile_and_encode(1, Table, ChainName, Rule2)
        end, Rules),
        apply_rule_msgs(RuleMsgs)
    end, Sorted),

    halt(0).

%% ═══════════════════════════════════════════════════════════════
%% Shared helpers
%% ═══════════════════════════════════════════════════════════════

create_chain(Table, Chain) ->
    ChainName = iolist_to_binary(maps:get(name, Chain)),
    Msg = case maps:find(hook, Chain) of
        {ok, Hook} ->
            Prio = priority_to_int(maps:get(priority, Chain, 0)),
            [fun(S) -> nft_chain:add(1, #{
                table => Table, name => ChainName,
                hook => Hook,
                type => maps:get(type, Chain, filter),
                priority => Prio,
                policy => maps:get(policy, Chain, accept)
            }, S) end];
        error ->
            [fun(S) -> nft_chain:add_regular(1, #{
                table => Table, name => ChainName
            }, S) end]
    end,
    case nfnl_server:apply_msgs(erlkoenig_nft_srv, Msg) of
        ok -> ok;
        {error, E} -> io:format(standard_error, "Chain ~s: ~p~n", [ChainName, E])
    end.

priority_to_int(filter) -> 0;
priority_to_int(dstnat) -> -100;
priority_to_int(srcnat) -> 100;
priority_to_int(mangle) -> -150;
priority_to_int(raw) -> -300;
priority_to_int(N) when is_integer(N) -> N.

compile_and_encode(Family, Table, Chain, Rule) ->
    try
        Compiled = erlkoenig_firewall_nft:compile_rule(Rule),
        case Compiled of
            [] -> [];
            [H | _] when is_list(H) ->
                [nft_encode:rule_fun(Family, Table, Chain, R) || R <- Compiled];
            _ ->
                [nft_encode:rule_fun(Family, Table, Chain, Compiled)]
        end
    catch _:_ ->
        case whereis(erlkoenig_nft_srv) of
            undefined ->
                {ok, S} = nfnl_server:start_link(),
                register(erlkoenig_nft_srv, S);
            _ -> ok
        end,
        []
    end.

apply_rule_msgs([]) -> ok;
apply_rule_msgs(Msgs) ->
    case nfnl_server:apply_msgs(erlkoenig_nft_srv, Msgs) of
        ok -> ok;
        {error, E} -> io:format(standard_error, "Rules: ~p~n", [E])
    end.

enrich_set_rule({set_lookup_drop, Name}, ST) ->
    case maps:find(Name, ST) of
        {ok, ipv6_addr} -> {set_lookup_drop, Name, ipv6_addr};
        _ -> {set_lookup_drop, Name}
    end;
enrich_set_rule({set_lookup_drop, Name, C}, ST) when is_atom(C), C =/= ipv4_addr, C =/= ipv6_addr ->
    case maps:find(Name, ST) of
        {ok, ipv6_addr} -> {set_lookup_drop_named, Name, atom_to_binary(C), ipv6_addr};
        _ -> {set_lookup_drop, Name, C}
    end;
enrich_set_rule({set_lookup_accept, Name}, ST) ->
    case maps:find(Name, ST) of
        {ok, ipv6_addr} -> {set_lookup_accept, Name, ipv6_addr};
        _ -> {set_lookup_accept, Name}
    end;
enrich_set_rule(R, _) -> R.

apply_set(Table, {Name, Type}) -> apply_set(Table, {Name, Type, #{}});
apply_set(Table, {Name, Type, Opts}) when is_list(Opts) -> apply_set(Table, {Name, Type, maps:from_list(Opts)});
apply_set(Table, {Name, Type, Opts}) ->
    N = iolist_to_binary(Name),
    SO = #{table => Table, name => N, type => Type},
    SO2 = case maps:find(timeout, Opts) of {ok, T} -> SO#{timeout => T}; _ -> SO end,
    SO3 = case maps:find(flags, Opts) of {ok, F} -> SO2#{flags => F}; _ -> SO2 end,
    case nfnl_server:apply_msgs(erlkoenig_nft_srv, [fun(S) -> nft_set:add(1, SO3, S) end]) of
        ok ->
            case maps:find(elements, Opts) of
                {ok, Es} ->
                    Ms = [fun(S) -> nft_set_elem:add(1, Table, N, elem_value(Type, E), S) end || E <- Es],
                    case nfnl_server:apply_msgs(erlkoenig_nft_srv, Ms) of
                        ok -> ok;
                        {error, EE} -> io:format(standard_error, "Set elem ~s: ~p~n", [N, EE])
                    end;
                _ -> ok
            end;
        {error, SE} -> io:format(standard_error, "Set ~s: ~p~n", [N, SE])
    end.

apply_vmap(Table, #{name := Name, type := Type} = V) ->
    N = iolist_to_binary(Name),
    case nfnl_server:apply_msgs(erlkoenig_nft_srv, [
        fun(S) -> nft_set:add_vmap(1, #{table => Table, name => N, type => Type}, 0, S) end
    ]) of
        ok ->
            case maps:get(entries, V, []) of
                [] -> ok;
                Es ->
                    Bin = [{vmap_key(Type, K), verdict_val(Vv)} || {K, Vv} <- Es],
                    case nfnl_server:apply_msgs(erlkoenig_nft_srv, [
                        fun(S) -> nft_set_elem:add_vmap_elems(1, Table, N, Bin, S) end
                    ]) of
                        ok -> ok;
                        {error, VE} -> io:format(standard_error, "Vmap ~s: ~p~n", [N, VE])
                    end
            end;
        {error, SE} -> io:format(standard_error, "Vmap ~s: ~p~n", [N, SE])
    end.

vmap_key(inet_service, P) when is_integer(P) -> <<P:16/big>>;
vmap_key(ipv4_addr, B) when is_binary(B), byte_size(B) =:= 4 -> B;
vmap_key(ipv4_addr, B) when is_binary(B) ->
    case inet:parse_address(binary_to_list(B)) of {ok,{A,B2,C,D}} -> <<A,B2,C,D>>; _ -> B end;
vmap_key(_, V) when is_binary(V) -> V;
vmap_key(_, V) when is_integer(V) -> <<V:32/big>>.

verdict_val(accept) -> accept;
verdict_val(drop) -> drop;
verdict_val({jump, C}) -> {jump, iolist_to_binary(C)};
verdict_val(V) -> V.

elem_value(inet_service, P) when is_integer(P) -> <<P:16/big>>;
elem_value(ipv4_addr, {A,B,C,D}) -> <<A,B,C,D>>;
elem_value(ipv4_addr, B) when is_binary(B), byte_size(B) =:= 4 -> B;
elem_value(ipv4_addr, B) when is_binary(B) ->
    case inet:parse_address(binary_to_list(B)) of {ok,{A,B2,C,D}} -> <<A,B2,C,D>>; _ -> B end;
elem_value(ipv6_addr, B) when is_binary(B) ->
    case inet:parse_address(binary_to_list(B)) of
        {ok,{A,B2,C,D,E,F,G,H}} -> <<A:16,B2:16,C:16,D:16,E:16,F:16,G:16,H:16>>; _ -> B end;
elem_value(_, V) when is_binary(V) -> V;
elem_value(_, V) when is_integer(V) -> <<V:32/big>>.
