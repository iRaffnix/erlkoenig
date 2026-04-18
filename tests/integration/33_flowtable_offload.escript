#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 33: Flowtable offload -- fast-path for established connections.
%%
%% Demonstrates nftables flowtable support:
%%   1. Create a table with a flowtable "ft0" on a dummy device
%%   2. Add a forward chain with ct state established -> flow offload @ft0
%%   3. Verify the flowtable and offload rule appear in nft list ruleset
%%   4. Verify the kernel accepted the configuration
%%   5. Cleanup
%%
%% This is a kernel-level smoke test: it proves the Netlink encoding
%% for NEWFLOWTABLE + flow_offload expression is accepted by the
%% kernel. Actual throughput offloading requires real traffic on
%% a physical or veth device (not tested here).
%%
%% Requires: root, kernel >= 4.16 (flowtable support)
-mode(compile).

-define(INET, 1).
-define(TABLE, <<"test_flowtable">>).
-define(FT_NAME, <<"ft0">>).
-define(DEVICE, <<"lo">>).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 33: Flowtable offload ===~n~n"),

    require_root(),
    test_helper:boot(),
    logger:set_primary_config(level, warning),

    case whereis(erlkoenig_nft_srv) of
        undefined ->
            io:format("SKIP: erlkoenig_nft_srv not running~n"),
            halt(1);
        _ -> ok
    end,

    %% 1. Create table + flowtable + forward chain with offload rule
    test_helper:step("create table with flowtable and offload rule", fun() ->
        %% Clean slate
        _ = nfnl_server:apply_msgs(erlkoenig_nft_srv, [
            fun(S) -> nft_table:add(?INET, ?TABLE, S) end,
            fun(S) -> nft_delete:table(?INET, ?TABLE, S) end
        ]),

        %% Build the full config in one atomic batch:
        %%   table -> flowtable -> chain -> rules
        Msgs = lists:flatten([
            %% Table
            [fun(S) -> nft_table:add(?INET, ?TABLE, S) end],

            %% Flowtable: ingress hook on loopback
            [fun(S) -> nft_flowtable:add(?INET, #{
                table => ?TABLE,
                name => ?FT_NAME,
                hook => ingress,
                priority => 0,
                devices => [?DEVICE],
                flags => 0
            }, S) end],

            %% Forward chain
            [fun(S) -> nft_chain:add(?INET, #{
                table => ?TABLE,
                name => <<"forward">>,
                hook => forward,
                type => filter,
                priority => 0,
                policy => accept
            }, S) end],

            %% Rule 1: ct state established -> flow offload @ft0
            [begin
                Exprs = nft_rules:flow_offload(?FT_NAME),
                nft_encode:rule_fun(inet, ?TABLE, <<"forward">>, Exprs)
             end],

            %% Rule 2: ct state established,related accept (fallback)
            [begin
                Exprs2 = nft_rules:ct_established_accept(),
                nft_encode:rule_fun(inet, ?TABLE, <<"forward">>, Exprs2)
             end]
        ]),

        nfnl_server:apply_msgs(erlkoenig_nft_srv, Msgs)
    end),

    %% 2. Verify flowtable exists in kernel
    test_helper:step("verify flowtable in nft list ruleset", fun() ->
        Out = os:cmd("nft list table inet " ++
                     binary_to_list(?TABLE) ++ " 2>&1"),
        io:format("~n    ~s~n", [Out]),

        %% Check flowtable declaration
        case string:find(Out, "flowtable " ++ binary_to_list(?FT_NAME)) of
            nomatch -> error({flowtable_not_found, Out});
            _ -> ok
        end,

        %% Check device binding
        case string:find(Out, binary_to_list(?DEVICE)) of
            nomatch -> error({device_not_in_flowtable, Out});
            _ -> ok
        end,

        %% Check offload rule
        case string:find(Out, "flow offload") of
            nomatch ->
                case string:find(Out, "flow add") of
                    nomatch -> error({offload_rule_not_found, Out});
                    _ -> ok
                end;
            _ -> ok
        end,

        ok
    end),

    %% 3. Cleanup
    test_helper:step("cleanup", fun() ->
        _ = nfnl_server:apply_msgs(erlkoenig_nft_srv, [
            fun(S) -> nft_delete:table(?INET, ?TABLE, S) end
        ]),
        ok
    end),

    io:format("~n=== Test 33: flowtable offload passed ===~n"),
    halt(0).

require_root() ->
    case os:cmd("id -u") of
        "0\n" -> ok;
        _ -> io:format("SKIP: requires root~n"), halt(77)
    end.
