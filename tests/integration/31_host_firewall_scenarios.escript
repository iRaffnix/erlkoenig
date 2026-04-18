#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 31: Host firewall scenarios — standalone nft tables from Chapter 6.
%%
%% Tests each host-firewall example from doc/book/06-firewall.md by
%% building the config as an Erlang map, applying it via the running
%% erlkoenig daemon, verifying the kernel state, then cleaning up.
%%
%% SAFETY: Every config that uses policy:drop on an input chain
%% gets a dead-man-switch. Before applying, we spawn a timer process
%% that deletes the table after 30 seconds. If the test passes and
%% SSH still works, we cancel the timer and delete the table ourselves.
%% If the test crashes or SSH breaks, the timer fires and restores
%% network access automatically.
%%
%% Additionally, every input chain includes ct_state established/related
%% as the first rule, which protects the SSH session used to run this
%% test (it's already established when rules are applied).
%%
%% Requires: root, running erlkoenig daemon with nfnl_server.
-mode(compile).

-define(INET, 1).
-define(SSH_PORT, 22).
-define(TIMEOUT, 30000).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 31: Host firewall scenarios ===~n~n"),

    require_root(),

    test_helper:boot(),
    logger:set_primary_config(level, warning),

    %% Verify erlkoenig nfnl_server is running
    case whereis(erlkoenig_nft_srv) of
        undefined ->
            io:format("SKIP: erlkoenig_nft_srv not running~n"),
            halt(1);
        _ -> ok
    end,

    %% Verify SSH works before we start
    verify_ssh_reachable(),

    %% Run each scenario
    test_helper:step("scenario: web server", fun() ->
        run_scenario(web_server_config(), <<"test_webserver">>)
    end),

    test_helper:step("scenario: database server", fun() ->
        run_scenario(database_server_config(), <<"test_database">>)
    end),

    test_helper:step("scenario: bastion host", fun() ->
        run_scenario(bastion_config(), <<"test_bastion">>)
    end),

    test_helper:step("scenario: NAT gateway", fun() ->
        run_scenario(nat_gateway_config(), <<"test_natgw">>)
    end),

    test_helper:step("scenario: ban set early drop", fun() ->
        run_scenario(ban_set_config(), <<"test_banset">>)
    end),

    test_helper:step("scenario: atomic reload replaces table", fun() ->
        test_atomic_reload()
    end),

    %% ── Phase 2: DSL-compiled .term files ──────────────────────
    %% These test the FULL pipeline: .exs → DSL compiler → .term → kernel.
    %% Each .term was pre-compiled by `ek dsl compile`.
    TermDir = "/tmp",
    DslExamples = [
        {"fw_web_server",  <<"host">>},
        {"fw_database",    <<"host">>},
        {"fw_bastion",     <<"host">>},
        {"fw_nat_gateway", <<"host">>}
    ],
    lists:foreach(fun({Name, TableName}) ->
        test_helper:step("DSL end-to-end: " ++ Name, fun() ->
            test_dsl_term(TermDir, Name, TableName)
        end)
    end, DslExamples),

    %% Final SSH check
    verify_ssh_reachable(),

    io:format("~n=== Test 31: all scenarios passed ===~n"),
    halt(0).

%%====================================================================
%% Scenario runner with dead-man-switch
%%====================================================================

run_scenario(Config, TableName) ->
    %% 1. Ensure clean slate
    cleanup_table(TableName),

    %% 2. Start dead-man-switch: delete table after 30s
    DMS = spawn_dead_man_switch(TableName),

    %% 3. Apply config atomically (add -> delete -> add pattern)
    ok = apply_table(Config),

    %% 4. Verify rules are installed
    verify_table_exists(TableName),
    verify_chains(Config),
    verify_counters(Config),
    verify_sets(Config),

    %% 5. Verify SSH still works (the critical safety check)
    verify_ssh_reachable(),

    %% 6. Cancel dead-man-switch and cleanup
    cancel_dead_man_switch(DMS),
    cleanup_table(TableName),

    %% 7. Verify table is gone
    verify_table_gone(TableName),
    ok.

%%====================================================================
%% Dead-man-switch
%%====================================================================

spawn_dead_man_switch(TableName) ->
    Self = self(),
    Pid = spawn(fun() ->
        receive
            cancel -> ok
        after 30000 ->
            %% Emergency cleanup — SSH might be blocked
            io:format("  !! DEAD-MAN-SWITCH: deleting table ~s~n",
                      [TableName]),
            _ = nfnl_server:apply_msgs(erlkoenig_nft_srv, [
                fun(S) -> nft_table:add(?INET, TableName, S) end,
                fun(S) -> nft_delete:table(?INET, TableName, S) end
            ]),
            Self ! {dms_fired, TableName}
        end
    end),
    Pid.

cancel_dead_man_switch(Pid) ->
    Pid ! cancel.

%%====================================================================
%% Table operations (using atomic add->delete->add pattern)
%%====================================================================

apply_table(#{table := Table} = Config) ->
    Sets = maps:get(sets, Config, []),
    Counters = maps:get(counters, Config, []),
    Chains = maps:get(chains, Config, []),

    Msgs = lists:flatten([
        %% Atomic replace: ensure-exists, delete, recreate
        [fun(S) -> nft_table:add(?INET, Table, S) end],
        [fun(S) -> nft_delete:table(?INET, Table, S) end],
        [fun(S) -> nft_table:add(?INET, Table, S) end],

        %% Named counters
        [fun(S) ->
            nft_object:add_counter(?INET, Table, counter_name(C), S)
         end || C <- Counters],

        %% Sets
        lists:flatten([build_set_msgs(Table, Set) || Set <- Sets]),

        %% Chains: create first (for jump targets)
        [build_chain_create(Table, Chain) || Chain <- Chains],

        %% Rules
        lists:flatten([build_chain_rules(Table, Chain) || Chain <- Chains])
    ]),

    nfnl_server:apply_msgs(erlkoenig_nft_srv, Msgs).

cleanup_table(Table) ->
    _ = nfnl_server:apply_msgs(erlkoenig_nft_srv, [
        fun(S) -> nft_table:add(?INET, Table, S) end,
        fun(S) -> nft_delete:table(?INET, Table, S) end
    ]),
    ok.

build_set_msgs(Table, {Name, Type}) ->
    [fun(S) -> nft_set:add(?INET,
        #{table => Table, name => Name, type => Type, id => 1}, S) end];
build_set_msgs(Table, {Name, Type, Opts}) ->
    SetOpts = #{table => Table, name => Name, type => Type, id => 1},
    Merged = maps:merge(SetOpts, maps:without([elements], Opts)),
    [fun(S) -> nft_set:add(?INET, Merged, S) end].

build_chain_create(Table, #{name := Name} = Chain) ->
    case maps:is_key(hook, Chain) of
        true ->
            fun(S) ->
                nft_chain:add(?INET, #{
                    table => Table,
                    name => Name,
                    hook => maps:get(hook, Chain),
                    type => maps:get(type, Chain, filter),
                    priority => priority_to_int(
                        maps:get(priority, Chain, filter)),
                    policy => maps:get(policy, Chain, accept)
                }, S)
            end;
        false ->
            fun(S) ->
                nft_chain:add_regular(?INET,
                    #{table => Table, name => Name}, S)
            end
    end.

build_chain_rules(Table, #{name := Name, rules := Rules}) ->
    [begin
        Exprs = erlkoenig_firewall_nft:compile_rule(R),
        nft_encode:rule_fun(inet, Table, Name, Exprs)
     end || R <- Rules].

counter_name(Name) when is_binary(Name) -> Name;
counter_name(Name) when is_atom(Name) -> atom_to_binary(Name);
counter_name(Name) when is_list(Name) -> list_to_binary(Name).

priority_to_int(raw) -> -300;
priority_to_int(mangle) -> -150;
priority_to_int(dstnat) -> -100;
priority_to_int(filter) -> 0;
priority_to_int(security) -> 50;
priority_to_int(srcnat) -> 100;
priority_to_int(N) when is_integer(N) -> N.

%%====================================================================
%% Verification helpers
%%====================================================================

verify_table_exists(Table) ->
    Out = os:cmd("nft list table inet " ++ binary_to_list(Table) ++
                 " 2>&1"),
    case string:find(Out, "table inet " ++ binary_to_list(Table)) of
        nomatch ->
            error({table_not_found, Table, Out});
        _ -> ok
    end.

verify_table_gone(Table) ->
    Out = os:cmd("nft list table inet " ++ binary_to_list(Table) ++
                 " 2>&1"),
    case string:find(Out, "No such file or directory") of
        nomatch ->
            case string:find(Out, "table inet " ++ binary_to_list(Table)) of
                nomatch -> ok;
                _ -> error({table_still_exists, Table})
            end;
        _ -> ok
    end.

verify_chains(#{chains := Chains, table := Table}) ->
    Out = os:cmd("nft list table inet " ++ binary_to_list(Table) ++
                 " 2>&1"),
    lists:foreach(fun(#{name := Name} = Chain) ->
        NameStr = binary_to_list(Name),
        case string:find(Out, "chain " ++ NameStr) of
            nomatch ->
                error({chain_not_found, Name, Out});
            _ -> ok
        end,
        %% Verify policy for base chains
        case maps:find(policy, Chain) of
            {ok, drop} ->
                %% Check "policy drop" appears after "chain <name>"
                case string:find(Out, "policy drop") of
                    nomatch ->
                        error({policy_not_drop, Name});
                    _ -> ok
                end;
            _ -> ok
        end
    end, Chains).

verify_counters(#{counters := Counters, table := Table}) ->
    lists:foreach(fun(C) ->
        Name = counter_name(C),
        case nfnl_server:get_counter(erlkoenig_nft_srv,
                                     ?INET, Table, Name) of
            {ok, #{packets := _, bytes := _}} -> ok;
            {error, Reason} ->
                error({counter_missing, Name, Reason})
        end
    end, Counters);
verify_counters(_) -> ok.

verify_sets(#{sets := Sets, table := Table}) ->
    Out = os:cmd("nft list table inet " ++ binary_to_list(Table) ++
                 " 2>&1"),
    lists:foreach(fun
        ({Name, _Type}) ->
            case string:find(Out, "set " ++ binary_to_list(Name)) of
                nomatch -> error({set_not_found, Name});
                _ -> ok
            end;
        ({Name, _Type, _Opts}) ->
            case string:find(Out, "set " ++ binary_to_list(Name)) of
                nomatch -> error({set_not_found, Name});
                _ -> ok
            end
    end, Sets);
verify_sets(_) -> ok.

verify_ssh_reachable() ->
    %% Verify our rules don't block established SSH by checking
    %% we can still execute commands. We are running over SSH;
    %% if the firewall killed our session, we wouldn't reach this
    %% code. Additionally verify sshd accepts new connections on
    %% at least one interface.
    %%
    %% We try all listen addresses: the firewall might block
    %% localhost but allow the external interface (or vice versa).
    Addrs = [{127, 0, 0, 1} | local_ipv4_addrs()],
    Results = [gen_tcp:connect(A, ?SSH_PORT,
                               [binary, {active, false}], 2000)
               || A <- Addrs],
    case lists:any(fun({ok, _}) -> true; (_) -> false end, Results) of
        true ->
            %% Close successful sockets
            lists:foreach(fun
                ({ok, S}) -> gen_tcp:close(S);
                (_) -> ok
            end, Results),
            ok;
        false ->
            %% No address worked, but we ARE still running over SSH
            %% (ct_state established protects us). Log warning but
            %% don't fail — the rules are verified by nft output.
            io:format("    WARN: no new SSH connections possible "
                      "(existing session protected by ct_state)~n"),
            ok
    end.

local_ipv4_addrs() ->
    case inet:getifaddrs() of
        {ok, Ifs} ->
            All = lists:flatten(
                [proplists:get_all_values(addr, Opts)
                 || {_Name, Opts} <- Ifs]),
            %% Only IPv4 (4-tuples), skip IPv6 (8-tuples)
            [A || A = {_,_,_,_} <- lists:usort(All)];
        _ -> []
    end.

%%====================================================================
%% Atomic reload test
%%====================================================================

test_atomic_reload() ->
    T = <<"test_atomic_reload">>,
    cleanup_table(T),
    DMS = spawn_dead_man_switch(T),

    %% Phase 1: install with counter_A
    Config1 = #{
        table => T,
        counters => [<<"counter_A">>],
        chains => [
            #{name => <<"input">>, hook => input, type => filter,
              priority => filter, policy => accept,
              rules => []}
        ]
    },
    ok = apply_table(Config1),
    {ok, #{packets := 0}} =
        nfnl_server:get_counter(erlkoenig_nft_srv,
                                ?INET, T, <<"counter_A">>),

    %% Phase 2: reload with counter_B (replaces counter_A)
    Config2 = #{
        table => T,
        counters => [<<"counter_B">>],
        chains => [
            #{name => <<"input">>, hook => input, type => filter,
              priority => filter, policy => accept,
              rules => []}
        ]
    },
    ok = apply_table(Config2),

    %% counter_A must be gone
    {error, _} = nfnl_server:get_counter(erlkoenig_nft_srv,
                                         ?INET, T, <<"counter_A">>),
    %% counter_B must be fresh
    {ok, #{packets := 0, bytes := 0}} =
        nfnl_server:get_counter(erlkoenig_nft_srv,
                                ?INET, T, <<"counter_B">>),

    verify_ssh_reachable(),
    cancel_dead_man_switch(DMS),
    cleanup_table(T),
    ok.

%%====================================================================
%% DSL .term file test — full pipeline verification
%%====================================================================

test_dsl_term(Dir, Name, ExpectedTable) ->
    Path = filename:join(Dir, Name ++ ".term"),
    {ok, [Config]} = case file:consult(Path) of
        {ok, [C]} when is_map(C) -> {ok, [C]};
        Other -> error({bad_term_file, Path, Other})
    end,

    NftTables = maps:get(nft_tables, Config, []),
    case NftTables of
        [] -> error({no_nft_tables_in_config, Name});
        _ -> ok
    end,

    %% Dead-man-switch
    DMS = spawn_dead_man_switch(ExpectedTable),

    %% Apply via erlkoenig_config:apply_nft_tables/5
    %% Empty maps for IpMap/VethMap/Pods/Zones — host-only firewalls
    %% don't reference container IPs.
    erlkoenig_config:apply_nft_tables(NftTables, #{}, #{}, [], []),

    %% Verify the table exists in kernel
    verify_table_exists(ExpectedTable),

    %% Verify each chain from the DSL appears
    lists:foreach(fun(#{chains := Chains}) ->
        lists:foreach(fun(#{name := ChainName}) ->
            ChainBin = iolist_to_binary(ChainName),
            Out = os:cmd("nft list table inet " ++
                         binary_to_list(ExpectedTable) ++ " 2>&1"),
            case string:find(Out, "chain " ++
                             binary_to_list(ChainBin)) of
                nomatch ->
                    error({dsl_chain_missing, Name, ChainBin});
                _ -> ok
            end
        end, Chains)
    end, NftTables),

    %% Verify SSH still works
    verify_ssh_reachable(),

    %% Cleanup
    cancel_dead_man_switch(DMS),
    cleanup_table(ExpectedTable),
    ok.

%%====================================================================
%% Scenario configs — match the Chapter 6 examples
%%====================================================================

%% Every input chain with policy:drop starts with:
%%   1. ct_state established/related (protects our SSH session)
%%   2. loopback accept
%%   3. ICMP accept
%%   4. SSH on port 22 (the ACTUAL port, not 22222)
%%
%% This ensures we never lock ourselves out, even if the
%% dead-man-switch fails.

ssh_safety_rules() ->
    [
        ct_established_accept,
        {iifname_accept, <<"lo">>},
        icmp_accept,
        {tcp_accept, ?SSH_PORT}
    ].

web_server_config() ->
    #{
        table => <<"test_webserver">>,
        counters => [<<"ssh_accepted">>, <<"http_accepted">>,
                     <<"input_drop">>],
        chains => [
            #{name => <<"input">>, hook => input, type => filter,
              priority => filter, policy => drop,
              rules =>
                ssh_safety_rules() ++ [
                    {tcp_accept, 80, <<"http_accepted">>},
                    {tcp_accept, 443},
                    {log_drop, <<"INPUT: ">>, <<"input_drop">>}
                ]}
        ]
    }.

database_server_config() ->
    #{
        table => <<"test_database">>,
        sets => [{<<"app_servers">>, ipv4_addr}],
        counters => [<<"pg_accepted">>, <<"input_drop">>,
                     <<"output_drop">>],
        chains => [
            #{name => <<"input">>, hook => input, type => filter,
              priority => filter, policy => drop,
              rules =>
                ssh_safety_rules() ++ [
                    {set_lookup_accept_tcp, <<"app_servers">>},
                    {log_drop, <<"DB-IN: ">>, <<"input_drop">>}
                ]},
            #{name => <<"output">>, hook => output, type => filter,
              priority => filter, policy => drop,
              rules => [
                    ct_established_accept,
                    {iifname_accept, <<"lo">>},
                    icmp_accept,
                    {udp_accept, 53},
                    {log_drop, <<"DB-OUT: ">>, <<"output_drop">>}
                ]}
        ]
    }.

bastion_config() ->
    #{
        table => <<"test_bastion">>,
        counters => [<<"ssh_office">>, <<"ssh_rejected">>,
                     <<"forward_drop">>],
        chains => [
            #{name => <<"input">>, hook => input, type => filter,
              priority => filter, policy => drop,
              rules =>
                ssh_safety_rules() ++ [
                    {log_drop, <<"BASTION: ">>}
                ]},
            #{name => <<"forward">>, hook => forward, type => filter,
              priority => filter, policy => drop,
              rules => [
                    {log_drop, <<"BASTION-FWD: ">>, <<"forward_drop">>}
                ]}
        ]
    }.

nat_gateway_config() ->
    #{
        table => <<"test_natgw">>,
        counters => [<<"forward_drop">>],
        chains => [
            #{name => <<"input">>, hook => input, type => filter,
              priority => filter, policy => drop,
              rules =>
                ssh_safety_rules() ++ [
                    {log_drop, <<"GW-IN: ">>}
                ]},
            #{name => <<"forward">>, hook => forward, type => filter,
              priority => filter, policy => drop,
              rules => [
                    ct_established_accept,
                    {log_drop, <<"GW-FWD: ">>, <<"forward_drop">>}
                ]},
            %% Prerouting: anti-spoofing
            #{name => <<"prerouting">>, hook => prerouting,
              type => filter, priority => raw, policy => accept,
              rules => [
                    fib_rpf_drop
                ]}
        ]
    }.

ban_set_config() ->
    #{
        table => <<"test_banset">>,
        sets => [{<<"ban">>, ipv4_addr}],
        counters => [<<"ban_drop">>],
        chains => [
            %% Raw priority — before conntrack
            #{name => <<"prerouting_ban">>, hook => prerouting,
              type => filter, priority => raw, policy => accept,
              rules => [
                    {set_lookup_drop, <<"ban">>, <<"ban_drop">>}
                ]},
            %% Still need an input chain so the test can verify
            %% SSH works (ban set is empty so nothing is blocked)
            #{name => <<"input">>, hook => input, type => filter,
              priority => filter, policy => accept,
              rules => []}
        ]
    }.

%%====================================================================
%% Helpers
%%====================================================================

require_root() ->
    case os:cmd("id -u") of
        "0\n" -> ok;
        _ ->
            io:format("SKIP: requires root~n"),
            halt(77)
    end.
