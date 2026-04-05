#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% Apply a .term config via nfnl_server + nft modules.
%% Designed to run inside an unshare -n namespace.
%%
%% Usage: escript nfnl_apply.escript <rootdir> <config.term>

main([RootDir, TermFile]) ->
    %% Add all ebin paths from the release
    Paths = filelib:wildcard(RootDir ++ "/lib/*/ebin"),
    [code:add_pathz(P) || P <- Paths],

    %% Pre-load all nft_expr_*_gen modules (used via list_to_existing_atom)
    [code:load_file(list_to_atom(filename:basename(F, ".beam")))
     || P <- Paths, F <- filelib:wildcard(P ++ "/nft_expr_*_gen.beam")],

    %% Start required apps
    {ok, _} = application:ensure_all_started(crypto),

    %% Start pg scope
    {ok, _} = pg:start_link(erlkoenig_nft),

    %% Read config
    {ok, [Config]} = file:consult(TermFile),
    Table = iolist_to_binary(maps:get(table, Config, <<"fw">>)),
    Chains = maps:get(chains, Config, []),

    %% Start nfnl_server
    {ok, Srv} = nfnl_server:start_link(),
    register(erlkoenig_nft_srv, Srv),

    %% Create table
    ok = nfnl_server:apply_msgs(erlkoenig_nft_srv, [
        fun(S) -> nft_table:add(1, Table, S) end
    ]),

    %% Create counters BEFORE chains (rules reference them)
    Counters = maps:get(counters, Config, []),
    CounterMsgs = [fun(S) ->
        nft_object:add_counter(1, Table, iolist_to_binary(N), S)
    end || N <- Counters],
    case CounterMsgs of
        [] -> ok;
        _ ->
            case nfnl_server:apply_msgs(erlkoenig_nft_srv, CounterMsgs) of
                ok -> ok;
                {error, CE} ->
                    io:format(standard_error, "Counter error: ~p~n", [CE])
            end
    end,

    %% Create sets BEFORE chains (rules reference them)
    %% Track set types for IPv6 awareness in rules
    Sets = maps:get(sets, Config, []),
    SetTypes = lists:foldl(fun
        ({Name, Type}, Acc) -> Acc#{iolist_to_binary(Name) => Type};
        ({Name, Type, _}, Acc) -> Acc#{iolist_to_binary(Name) => Type};
        (_, Acc) -> Acc
    end, #{}, Sets),
    lists:foreach(fun(SetSpec) ->
        apply_set(Table, SetSpec)
    end, Sets),

    %% Create vmaps BEFORE chains (rules reference them via vmap_dispatch)
    %% But vmaps with jump verdicts need their target chains first.
    %% Solution: create all regular chains (no rules), then vmaps, then rules.
    Vmaps = maps:get(vmaps, Config, []),

    %% Phase 1: Create ALL chains (no rules) — regular first, then base
    SortedChains = lists:sort(fun(A, _B) ->
        not maps:is_key(hook, A)
    end, Chains),
    lists:foreach(fun(Chain) ->
        ChainName = iolist_to_binary(maps:get(name, Chain)),
        ChainMsg = case maps:find(hook, Chain) of
            {ok, Hook} ->
                [fun(S) -> nft_chain:add(1, #{
                    table => Table, name => ChainName,
                    hook => Hook,
                    type => maps:get(type, Chain, filter),
                    priority => maps:get(priority, Chain, 0),
                    policy => maps:get(policy, Chain, accept)
                }, S) end];
            error ->
                [fun(S) -> nft_chain:add_regular(1, #{
                    table => Table, name => ChainName
                }, S) end]
        end,
        case nfnl_server:apply_msgs(erlkoenig_nft_srv, ChainMsg) of
            ok -> ok;
            {error, ChainErr} ->
                io:format(standard_error, "Chain create error ~s: ~p~n", [ChainName, ChainErr])
        end
    end, SortedChains),

    %% Phase 2: Create vmaps (after chains exist for jump targets)
    lists:foreach(fun(Vmap) ->
        apply_vmap(Table, Vmap)
    end, Vmaps),

    %% Phase 3: Add rules to chains
    lists:foreach(fun(Chain) ->
        ChainName = iolist_to_binary(maps:get(name, Chain)),

        %% Compile and add rules
        Rules = maps:get(rules, Chain, []),
        RuleMsgs = lists:flatmap(fun(Rule) ->
            try
                %% Enrich set-referencing rules with set type (IPv6 awareness)
                Rule2 = enrich_set_rule(Rule, SetTypes),
                Compiled = erlkoenig_firewall_nft:compile_rule(Rule2),
                %% Some rules return a list of rules (e.g. tcp_accept_limited)
                %% Detect: if first element is a list, it's multi-rule
                case Compiled of
                    [] -> [];
                    [First | _] when is_list(First) ->
                        [nft_encode:rule_fun(1, Table, ChainName, R) || R <- Compiled];
                    _ ->
                        [nft_encode:rule_fun(1, Table, ChainName, Compiled)]
                end
            catch C:E ->
                io:format(standard_error, "Rule compile error: ~p:~p for ~p~n", [C, E, Rule]),
                %% nfnl_server may have crashed — restart it
                case whereis(erlkoenig_nft_srv) of
                    undefined ->
                        {ok, NewSrv} = nfnl_server:start_link(),
                        register(erlkoenig_nft_srv, NewSrv);
                    _ -> ok
                end,
                []
            end
        end, Rules),
        case RuleMsgs of
            [] -> ok;
            _ ->
                case nfnl_server:apply_msgs(erlkoenig_nft_srv, RuleMsgs) of
                    ok -> ok;
                    {error, RE} ->
                        io:format(standard_error, "Rules apply error: ~p~n", [RE])
                end
        end
    end, SortedChains),

    halt(0);

main(_) ->
    io:format(standard_error, "Usage: nfnl_apply.escript <rootdir> <config.term>~n", []),
    halt(1).

%% Add set type info to set-referencing rules so compile_rule uses the right IP version
enrich_set_rule({set_lookup_drop, SetName}, SetTypes) ->
    case maps:find(SetName, SetTypes) of
        {ok, ipv6_addr} -> {set_lookup_drop, SetName, ipv6_addr};
        _ -> {set_lookup_drop, SetName}
    end;
enrich_set_rule({set_lookup_drop, SetName, Counter}, SetTypes) when is_atom(Counter), Counter =/= ipv4_addr, Counter =/= ipv6_addr ->
    case maps:find(SetName, SetTypes) of
        {ok, ipv6_addr} -> {set_lookup_drop_named, SetName, atom_to_binary(Counter), ipv6_addr};
        _ -> {set_lookup_drop, SetName, Counter}
    end;
enrich_set_rule({set_lookup_accept, SetName}, SetTypes) ->
    case maps:find(SetName, SetTypes) of
        {ok, ipv6_addr} -> {set_lookup_accept, SetName, ipv6_addr};
        _ -> {set_lookup_accept, SetName}
    end;
enrich_set_rule(Rule, _) -> Rule.

apply_set(Table, {Name, Type}) ->
    apply_set(Table, {Name, Type, #{}});
apply_set(Table, {Name, Type, Opts}) when is_list(Opts) ->
    apply_set(Table, {Name, Type, maps:from_list(Opts)});
apply_set(Table, {Name, Type, Opts}) when is_map(Opts) ->
    NameBin = iolist_to_binary(Name),
    SetOpts = #{
        table => Table,
        name => NameBin,
        type => Type
    },
    SetOpts2 = case maps:find(timeout, Opts) of
        {ok, Tval} -> SetOpts#{timeout => Tval};
        error -> SetOpts
    end,
    SetOpts3 = case maps:find(flags, Opts) of
        {ok, F} -> SetOpts2#{flags => F};
        error -> SetOpts2
    end,
    Msg = fun(S) -> nft_set:add(1, SetOpts3, S) end,
    case nfnl_server:apply_msgs(erlkoenig_nft_srv, [Msg]) of
        ok ->
            %% Add elements if present
            case maps:find(elements, Opts) of
                {ok, Elems} ->
                    ElemMsgs = [fun(S) ->
                        nft_set_elem:add(1, Table, NameBin, elem_value(Type, E), S)
                    end || E <- Elems],
                    case nfnl_server:apply_msgs(erlkoenig_nft_srv, ElemMsgs) of
                        ok -> ok;
                        {error, EE} ->
                            io:format(standard_error, "Set elem error ~s: ~p~n", [NameBin, EE])
                    end;
                error -> ok
            end;
        {error, SE} ->
            io:format(standard_error, "Set error ~s: ~p~n", [NameBin, SE])
    end.

apply_vmap(Table, #{name := Name, type := Type} = Vmap) ->
    NameBin = iolist_to_binary(Name),
    %% nft_set:add_vmap(Family, Opts, Id, Seq) — Id=0 auto
    VmapMsg = fun(S) -> nft_set:add_vmap(1, #{
        table => Table,
        name => NameBin,
        type => Type
    }, 0, S) end,
    case nfnl_server:apply_msgs(erlkoenig_nft_srv, [VmapMsg]) of
        ok ->
            Entries = maps:get(entries, Vmap, []),
            case Entries of
                [] -> ok;
                _ ->
                    %% Convert entries to {Key, Verdict} with binary keys
                    BinEntries = [{vmap_key(Type, K), verdict_val(V)} || {K, V} <- Entries],
                    ElemMsg = fun(S) ->
                        nft_set_elem:add_vmap_elems(1, Table, NameBin, BinEntries, S)
                    end,
                    case nfnl_server:apply_msgs(erlkoenig_nft_srv, [ElemMsg]) of
                        ok -> ok;
                        {error, VE} ->
                            io:format(standard_error, "Vmap elem error ~s: ~p~n", [NameBin, VE])
                    end
            end;
        {error, SE} ->
            io:format(standard_error, "Vmap error ~s: ~p~n", [NameBin, SE])
    end.

vmap_key(inet_service, Port) when is_integer(Port) -> <<Port:16/big>>;
vmap_key(ipv4_addr, IP) when is_binary(IP), byte_size(IP) =:= 4 -> IP;
vmap_key(ipv4_addr, IP) when is_binary(IP) ->
    case inet:parse_address(binary_to_list(IP)) of
        {ok, {A,B,C,D}} -> <<A,B,C,D>>;
        _ -> IP
    end;
vmap_key(_, V) when is_binary(V) -> V;
vmap_key(_, V) when is_integer(V) -> <<V:32/big>>.

verdict_val(accept) -> accept;
verdict_val(drop) -> drop;
verdict_val({jump, Chain}) -> {jump, iolist_to_binary(Chain)};
verdict_val(V) -> V.

elem_value(inet_service, Port) when is_integer(Port) -> <<Port:16/big>>;
elem_value(ipv4_addr, {A,B,C,D}) -> <<A,B,C,D>>;
elem_value(ipv4_addr, Bin) when is_binary(Bin), byte_size(Bin) =:= 4 -> Bin;
elem_value(ipv4_addr, Bin) when is_binary(Bin) ->
    %% IP string like <<"198.51.100.1">>
    case inet:parse_address(binary_to_list(Bin)) of
        {ok, {A,B,C,D}} -> <<A,B,C,D>>;
        _ -> Bin
    end;
elem_value(ipv6_addr, Bin) when is_binary(Bin) ->
    case inet:parse_address(binary_to_list(Bin)) of
        {ok, {A,B,C,D,E,F,G,H}} -> <<A:16,B:16,C:16,D:16,E:16,F:16,G:16,H:16>>;
        _ -> Bin
    end;
elem_value(_, V) when is_binary(V) -> V;
elem_value(_, V) when is_integer(V) -> <<V:32/big>>.
