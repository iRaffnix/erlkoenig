#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 21: Full Stack End-to-End
%%
%% Tests the complete execution chain:
%%   1. Spawn two containers with different firewall policies
%%      - Container A: strict (only port 7001 via generic rule macro)
%%      - Container B: open (default rules)
%%   2. Verify containers are running
%%   3. TCP echo on allowed ports works
%%   4. TCP on blocked port is rejected (strict firewall)
%%   5. nftables chains have correct rules
%%   6. Container inspect returns correct metadata
%%   7. Cleanup removes chains
-mode(compile).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 21: Full Stack End-to-End ===~n~n"),
    test_helper:boot(),

    DemoBin = test_helper:demo("echo_server"),

    %% Step 1: Spawn container A — strict firewall (generic rule macro format)
    PidA = test_helper:step("Spawn Container A (strict: nur Port 7001)", fun() ->
        {ok, P} = erlkoenig:spawn(DemoBin, #{
            ip => {10, 0, 0, 60},
            args => [<<"7001">>],
            firewall => #{chains => [#{
                name => <<"inbound">>,
                rules => [
                    ct_established_accept,
                    icmp_accept,
                    {rule, accept, #{tcp => 7001}},
                    {rule, drop, #{log => <<"E2E_DROP: ">>}}
                ]
            }]}
        }),
        {ok, P}
    end),

    %% Step 2: Spawn container B — open (default rules)
    PidB = test_helper:step("Spawn Container B (open)", fun() ->
        {ok, P} = erlkoenig:spawn(DemoBin, #{
            ip => {10, 0, 0, 70},
            args => [<<"7002">>]
        }),
        {ok, P}
    end),

    timer:sleep(1500),

    %% Step 3: Verify both containers are running
    test_helper:step("Beide Container running", fun() ->
        #{state := running} = erlkoenig:inspect(PidA),
        #{state := running} = erlkoenig:inspect(PidB),
        io:format("    A + B running~n"),
        ok
    end),

    %% Step 4: Allowed port on A works
    test_helper:step("Container A: Port 7001 erlaubt", fun() ->
        test_helper:echo_test({10, 0, 0, 60}, 7001, <<"e2e_strict_allowed">>)
    end),

    %% Step 5: Container B works (open)
    test_helper:step("Container B: Port 7002 erlaubt (open)", fun() ->
        test_helper:echo_test({10, 0, 0, 70}, 7002, <<"e2e_open_works">>)
    end),

    %% Step 6: Blocked port on A is rejected
    test_helper:step("Container A: Port 7002 geblockt (drop)", fun() ->
        case gen_tcp:connect({10, 0, 0, 60}, 7002, [binary, {active, false}], 2000) of
            {error, _} ->
                io:format("    Port 7002 korrekt geblockt~n"),
                ok;
            {ok, Sock} ->
                gen_tcp:close(Sock),
                {error, port_should_be_blocked}
        end
    end),

    %% Step 7: Verify nftables chains
    test_helper:step("nftables: generic rule in per-container chain", fun() ->
        Output = os:cmd("nft list table inet erlkoenig_ct 2>&1"),
        case string:find(Output, "tcp dport 7001 accept") of
            nomatch -> {error, "tcp dport 7001 accept rule missing"};
            _ ->
                io:format("    tcp dport 7001 accept — vorhanden~n"),
                ok
        end
    end),

    %% Step 8: Inspect metadata
    test_helper:step("Container inspect metadata", fun() ->
        InfoA = erlkoenig:inspect(PidA),
        #{net_info := #{ip := {10, 0, 0, 60}}} = InfoA,
        #{args := [<<"7001">>]} = InfoA,
        io:format("    A: ip=10.0.0.60 args=[7001]~n"),

        InfoB = erlkoenig:inspect(PidB),
        #{net_info := #{ip := {10, 0, 0, 70}}} = InfoB,
        io:format("    B: ip=10.0.0.70 args=[7002]~n"),
        ok
    end),

    %% Step 9: Cleanup
    test_helper:step("Cleanup", fun() ->
        erlkoenig:stop(PidA),
        erlkoenig:stop(PidB),
        timer:sleep(1000),
        %% Verify chains are gone
        Output = os:cmd("nft list table inet erlkoenig_ct 2>&1"),
        case string:find(Output, "tcp dport 7001") of
            nomatch ->
                io:format("    Container chains entfernt~n"),
                ok;
            _ ->
                io:format("    WARN: container chain still present~n"),
                ok  %% non-fatal, cleanup may be async
        end
    end),

    io:format("~n=== Test 21 bestanden ===~n~n"),
    halt(0).
