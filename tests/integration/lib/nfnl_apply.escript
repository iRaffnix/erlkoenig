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
    Sets = maps:get(sets, Config, []),
    lists:foreach(fun(SetSpec) ->
        apply_set(Table, SetSpec)
    end, Sets),

    %% Process each chain
    lists:foreach(fun(Chain) ->
        ChainName = iolist_to_binary(maps:get(name, Chain)),

        %% Create chain
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
        ok = nfnl_server:apply_msgs(erlkoenig_nft_srv, ChainMsg),

        %% Compile and add rules
        Rules = maps:get(rules, Chain, []),
        RuleMsgs = lists:filtermap(fun(Rule) ->
            try
                Compiled = erlkoenig_firewall_nft:compile_rule(Rule),
                {true, nft_encode:rule_fun(1, Table, ChainName, Compiled)}
            catch C:E ->
                io:format(standard_error, "Rule compile error: ~p:~p for ~p~n", [C, E, Rule]),
                false
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
    end, Chains),

    halt(0);

main(_) ->
    io:format(standard_error, "Usage: nfnl_apply.escript <rootdir> <config.term>~n", []),
    halt(1).

apply_set(Table, {Name, Type}) ->
    apply_set(Table, {Name, Type, []});
apply_set(Table, {Name, Type, Opts}) ->
    NameBin = iolist_to_binary(Name),
    TypeAtom = case Type of
        ipv4_addr -> ipv4_addr;
        inet_service -> inet_service;
        T when is_atom(T) -> T;
        _ -> ipv4_addr
    end,
    SetFlags = proplists:get_value(flags, Opts, []),
    Timeout = proplists:get_value(timeout, Opts, undefined),
    SetOpts = #{
        table => Table,
        name => NameBin,
        key_type => TypeAtom
    },
    SetOpts2 = case Timeout of
        undefined -> SetOpts;
        Tval -> SetOpts#{timeout => Tval}
    end,
    SetOpts3 = case SetFlags of
        [] -> SetOpts2;
        F -> SetOpts2#{flags => F}
    end,
    Msg = fun(S) -> nft_set:add(1, SetOpts3, S) end,
    case nfnl_server:apply_msgs(erlkoenig_nft_srv, [Msg]) of
        ok -> ok;
        {error, SE} ->
            io:format(standard_error, "Set error ~s: ~p~n", [NameBin, SE])
    end.
